from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from medflow_compare.shared_tools import call_redteam_llm
from medflow_ti.config import load_settings
from medflow_ti.llm import LLMError, is_llm_api_error


ALLOWED_NMAP_FLAGS = {
    "-sV",
    "-Pn",
    "--version-light",
    "--reason",
    "--open",
    "-T2",
    "-T3",
    "-T4",
}
ALLOWED_SET_KEYS = {
    "CMD",
    "FETCH_SRVHOST",
    "FETCH_SRVPORT",
    "JAVA_GADGET_CHAIN",
    "LHOST",
    "LPORT",
    "PAYLOAD",
    "RHOST",
    "RHOSTS",
    "RPORT",
    "SRVHOST",
    "SRVPORT",
    "SSL",
    "TARGET",
    "TARGETURI",
    "URI",
    "VHOST",
}
ALLOWED_PROOF_COMMANDS = {
    "id": "Show the effective Unix user and groups.",
    "whoami": "Show the effective username.",
    "pwd": "Show the current working directory.",
    "hostname": "Show the target hostname.",
    "uname -a": "Show kernel/platform information.",
}


def plan_nmap_command(
    target: str,
    ports: list[int],
    *,
    provider: str = "llama",
    use_llm: bool = False,
) -> dict[str, Any]:
    fallback = fallback_nmap_plan(target, ports)
    if not use_llm:
        return fallback
    prompt = f"""
You generate one safe Nmap service discovery command for an authorized local lab.

Target: {target}
Ports: {','.join(str(port) for port in ports)}

Return strict JSON only:
{{
  "argv": ["nmap", "..."],
  "reason": "short reason"
}}

Rules:
- Use only the executable nmap.
- Include -Pn.
- Use service/version discovery.
- Do not use NSE scripts, brute force, vulnerability scripts, UDP, spoofing, decoys, packet flooding, or output redirection.
- Scan only the exact target and exact port list provided.
"""
    try:
        raw = call_redteam_llm(prompt, settings=load_settings(), provider=provider)
        parsed = parse_json(raw)
        argv = [str(item) for item in parsed.get("argv", [])]
        validated = validate_nmap_argv(argv, target, ports)
        return {
            "argv": validated,
            "reason": str(parsed.get("reason") or "LLM generated a validated Nmap service discovery command."),
            "generated_by": "llm",
            "llm_raw": raw[:2000],
        }
    except Exception as exc:
        if not is_llm_api_error(exc) and not isinstance(exc, (LLMError, RuntimeError, ValueError, json.JSONDecodeError)):
            raise
        return {**fallback, "planner_error": f"{type(exc).__name__}: {exc}"}


def fallback_nmap_plan(target: str, ports: list[int]) -> dict[str, Any]:
    return {
        "argv": ["nmap", "-sV", "-Pn", "--version-light", "--reason", "-p", ",".join(str(port) for port in ports), target],
        "reason": "Deterministic fallback Nmap service discovery command.",
        "generated_by": "fallback",
    }


def validate_nmap_argv(argv: list[str], target: str, ports: list[int]) -> list[str]:
    if not argv or argv[0] != "nmap":
        raise ValueError("Nmap plan must start with nmap.")
    if target not in argv:
        raise ValueError("Nmap plan must include the exact target.")
    if argv[-1] != target:
        raise ValueError("Nmap target must be the final argument.")
    if "-p" not in argv:
        raise ValueError("Nmap plan must include -p.")
    port_index = argv.index("-p") + 1
    if port_index >= len(argv):
        raise ValueError("Nmap plan has no -p value.")
    expected_ports = ",".join(str(port) for port in ports)
    if argv[port_index] != expected_ports:
        raise ValueError("Nmap plan must use the exact provided port list.")
    for item in argv[1:-1]:
        if item == expected_ports or item == "-p":
            continue
        if item.startswith("-") and item not in ALLOWED_NMAP_FLAGS:
            raise ValueError(f"Nmap flag not allowed: {item}")
        if not item.startswith("-") and item != expected_ports:
            raise ValueError(f"Nmap positional argument not allowed: {item}")
    if "-Pn" not in argv:
        raise ValueError("Nmap plan must include -Pn.")
    if not any(flag in argv for flag in ["-sV", "-A"]):
        raise ValueError("Nmap plan must perform service discovery.")
    return argv


def plan_metasploit_resource(
    target: str,
    module_path: str,
    options: dict[str, Any],
    selected_payload: str,
    action: str,
    *,
    provider: str = "llama",
    use_llm: bool = False,
) -> dict[str, Any]:
    fallback = fallback_metasploit_resource(target, module_path, options, selected_payload, action)
    if not use_llm:
        return fallback
    prompt = f"""
You generate a Metasploit resource command plan for an authorized isolated lab.

Module: {module_path}
Target host: {target}
Action: {action}
Selected payload: {selected_payload or "(none)"}
Options JSON:
{json.dumps(options, indent=2, default=str)}

Return strict JSON only:
{{
  "resource_lines": ["use ...", "set ...", "check"],
  "reason": "short reason"
}}

Rules:
- Use exactly module {module_path}.
- Set RHOSTS to exactly {target}.
- Use only resource lines beginning with: use, set, check, run -j, sleep, sessions -l, sessions -K, exit -y.
- Do not include shell commands, backticks, semicolons inside values, file writes, persistence, credential dumping, or evasion.
- If action is check, end with check and exit -y.
- If action is exploit, use run -j, sleep, sessions -l, sessions -K, exit -y.
- For cmd/unix/generic exploit payloads, set CMD to the exact value already present in Options JSON.
"""
    try:
        raw = call_redteam_llm(prompt, settings=load_settings(), provider=provider)
        parsed = parse_json(raw)
        lines = [str(item) for item in parsed.get("resource_lines", [])]
        validated = validate_metasploit_resource(lines, target, module_path, action)
        return {
            "resource_lines": validated,
            "reason": str(parsed.get("reason") or "LLM generated a validated Metasploit resource plan."),
            "generated_by": "llm",
            "llm_raw": raw[:2500],
        }
    except Exception as exc:
        if not is_llm_api_error(exc) and not isinstance(exc, (LLMError, RuntimeError, ValueError, json.JSONDecodeError)):
            raise
        return {**fallback, "planner_error": f"{type(exc).__name__}: {exc}"}


def fallback_metasploit_resource(
    target: str,
    module_path: str,
    options: dict[str, Any],
    selected_payload: str,
    action: str,
) -> dict[str, Any]:
    resource_lines = [f"use {module_path}"]
    merged_options = {**options, "RHOSTS": target}
    for key, value in merged_options.items():
        if key in {"LHOST", "LPORT"} and not selected_payload:
            continue
        if value not in {"", None, "auto"}:
            resource_lines.append(f"set {key} {value}")
    if selected_payload:
        resource_lines.append(f"set PAYLOAD {selected_payload}")
    if action == "exploit" and selected_payload == "cmd/unix/generic" and not any(line.startswith("set CMD ") for line in resource_lines):
        resource_lines.append("set CMD id")
    if action == "exploit":
        resource_lines.extend(["run -j", "sleep 12", "sessions -l", "sessions -K", "exit -y"])
    else:
        resource_lines.extend(["check", "exit -y"])
    return {
        "resource_lines": validate_metasploit_resource(resource_lines, target, module_path, action),
        "reason": "Deterministic fallback Metasploit resource plan.",
        "generated_by": "fallback",
    }


def validate_metasploit_resource(lines: list[str], target: str, module_path: str, action: str) -> list[str]:
    if not lines or lines[0] != f"use {module_path}":
        raise ValueError("Metasploit plan must begin with the selected module.")
    if any(";" in line or "`" in line or "$(" in line for line in lines):
        raise ValueError("Metasploit resource lines cannot contain shell chaining or substitution.")
    has_target = False
    for line in lines:
        parts = shlex.split(line)
        if not parts:
            raise ValueError("Empty Metasploit resource line.")
        if parts[0] == "use":
            if len(parts) != 2 or parts[1] != module_path:
                raise ValueError("Metasploit use line must match selected module.")
        elif parts[0] == "set":
            if len(parts) < 3:
                raise ValueError("Metasploit set line requires key and value.")
            key = parts[1].upper()
            value = " ".join(parts[2:])
            if key not in ALLOWED_SET_KEYS:
                raise ValueError(f"Metasploit option not allowed: {key}")
            if key == "CMD":
                validate_proof_command(value)
            if key in {"RHOST", "RHOSTS"}:
                if value != target:
                    raise ValueError("Metasploit target option must match exact target.")
                has_target = True
        elif line == "check":
            continue
        elif re.fullmatch(r"run\s+-j", line):
            continue
        elif re.fullmatch(r"sleep\s+\d{1,2}", line):
            continue
        elif line in {"sessions -l", "sessions -K", "exit -y"}:
            continue
        else:
            raise ValueError(f"Metasploit resource line not allowed: {line}")
    if not has_target:
        raise ValueError("Metasploit plan must set RHOSTS/RHOST to the exact target.")
    if action == "exploit":
        required = {"run -j", "sessions -l", "sessions -K", "exit -y"}
        if not required.issubset(set(lines)):
            raise ValueError("Exploit plan must run, list sessions, kill sessions, and exit.")
    else:
        if "check" not in lines or "exit -y" not in lines:
            raise ValueError("Check plan must include check and exit -y.")
    return lines


def plan_proof_command(
    context: dict[str, Any],
    *,
    provider: str = "llama",
    use_llm: bool = False,
) -> dict[str, Any]:
    fallback = fallback_proof_command()
    if not use_llm:
        return fallback
    prompt = f"""
You choose one harmless command-execution proof command for an authorized isolated lab.

Context:
{json.dumps(context, indent=2, default=str)[:4000]}

Allowed commands:
{json.dumps(ALLOWED_PROOF_COMMANDS, indent=2)}

Return strict JSON only:
{{
  "command": "id",
  "reason": "short reason"
}}

Rules:
- Choose exactly one command from the allowed command keys.
- Do not invent commands, arguments, shell metacharacters, file writes, downloads, persistence, or cleanup commands.
- Prefer a command that gives observable identity/platform proof.
"""
    try:
        raw = call_redteam_llm(prompt, settings=load_settings(), provider=provider)
        parsed = parse_json(raw)
        command = validate_proof_command(str(parsed.get("command") or ""))
        return {
            "command": command,
            "reason": str(parsed.get("reason") or "LLM selected a validated proof command."),
            "generated_by": "llm",
            "llm_raw": raw[:1500],
        }
    except Exception as exc:
        if not is_llm_api_error(exc) and not isinstance(exc, (LLMError, RuntimeError, ValueError, json.JSONDecodeError)):
            raise
        return {**fallback, "planner_error": f"{type(exc).__name__}: {exc}"}


def fallback_proof_command() -> dict[str, Any]:
    return {
        "command": "id",
        "reason": "Deterministic fallback command-execution proof.",
        "generated_by": "fallback",
    }


def validate_proof_command(command: str) -> str:
    normalized = re.sub(r"\s+", " ", command.strip())
    if normalized not in ALLOWED_PROOF_COMMANDS:
        raise ValueError(f"Proof command not allowed: {command}")
    return normalized


def execute_command(argv: list[str], *, timeout: int) -> tuple[subprocess.CompletedProcess[str], float]:
    started = time.monotonic()
    proc = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    return proc, time.monotonic() - started


def parse_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        stripped = stripped.removeprefix("json").strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise json.JSONDecodeError("No JSON object found", stripped, 0)
    return json.loads(stripped[start : end + 1])


def plan_recon_strategy(
    goal: str,
    target: str,
    tcp: dict[str, Any],
    requested_ports: list[int],
    *,
    provider: str = "llama",
    use_llm: bool = False,
) -> dict[str, Any]:
    open_ports = [int(port) for port, result in tcp.items() if isinstance(result, dict) and result.get("open") and str(port).isdigit()]
    fallback = fallback_recon_strategy(open_ports or requested_ports)
    if not use_llm:
        return fallback
    prompt = f"""
You are the reconnaissance planner for an authorized isolated lab assessment.

Goal: {goal}
Target: {target}
Requested ports: {requested_ports}
TCP observations:
{json.dumps(tcp, indent=2, default=str)[:6000]}

Choose what to inspect next. Return strict JSON only:
{{
  "service_scan_ports": [22, 80],
  "http_probe_ports": [80],
  "validation_focus": ["short rationale item"],
  "reason": "short reason"
}}

Rules:
- Choose only ports from the observed open TCP ports. If no ports are open, return empty arrays.
- Prefer ports that are likely to reveal attack surface or service identity.
- Include HTTP-like ports in http_probe_ports only when the port or evidence suggests HTTP/HTTPS/web/API.
- Do not include commands or exploit steps.
"""
    try:
        raw = call_redteam_llm(prompt, settings=load_settings(), provider=provider)
        parsed = parse_json(raw)
        return validate_recon_strategy(parsed, open_ports, fallback, raw)
    except Exception as exc:
        if not is_llm_api_error(exc) and not isinstance(exc, (LLMError, RuntimeError, ValueError, json.JSONDecodeError)):
            raise
        return {**fallback, "planner_error": f"{type(exc).__name__}: {exc}"}


def fallback_recon_strategy(open_ports: list[int]) -> dict[str, Any]:
    httpish = [port for port in open_ports if port in {80, 443, 5000, 8000, 8080, 8443}]
    return {
        "service_scan_ports": sorted(open_ports),
        "http_probe_ports": sorted(httpish),
        "validation_focus": ["Inspect observed open services and prioritize web/API-like ports."],
        "reason": "Deterministic fallback recon strategy.",
        "generated_by": "fallback",
    }


def validate_recon_strategy(parsed: dict[str, Any], open_ports: list[int], fallback: dict[str, Any], raw: str = "") -> dict[str, Any]:
    allowed = set(open_ports)
    service_ports = [port for port in coerce_ports(parsed.get("service_scan_ports", [])) if port in allowed]
    http_ports = [port for port in coerce_ports(parsed.get("http_probe_ports", [])) if port in allowed]
    if not service_ports and open_ports:
        service_ports = fallback["service_scan_ports"]
    focus = [str(item)[:180] for item in parsed.get("validation_focus", [])[:8]]
    return {
        "service_scan_ports": sorted(set(service_ports)),
        "http_probe_ports": sorted(set(http_ports)),
        "validation_focus": focus or fallback["validation_focus"],
        "reason": str(parsed.get("reason") or "LLM generated a validated recon strategy."),
        "generated_by": "llm",
        "llm_raw": raw[:2500],
    }


def coerce_ports(values: Any) -> list[int]:
    ports: list[int] = []
    if not isinstance(values, list):
        return ports
    for value in values:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535:
            ports.append(port)
    return ports


def plan_validation_strategy(
    goal: str,
    target: str,
    services: list[dict[str, Any]],
    selection: dict[str, Any],
    *,
    max_capabilities: int,
    provider: str = "llama",
    use_llm: bool = False,
) -> dict[str, Any]:
    candidates = selection.get("candidates") or selection.get("selected_candidates") or []
    fallback = fallback_validation_strategy(candidates, max_capabilities)
    if not use_llm or not candidates:
        return fallback
    compact_candidates = [
        {
            "id": item.get("id"),
            "runner": item.get("runner"),
            "provider": item.get("provider"),
            "score": item.get("score"),
            "matched_service": item.get("matched_service"),
            "reasons": item.get("reasons", [])[:8],
        }
        for item in candidates[:30]
    ]
    prompt = f"""
You are the validation planner for an authorized isolated lab assessment.

Goal: {goal}
Target: {target}
Observed services:
{json.dumps(services, indent=2, default=str)[:4000]}

Ranked capability candidates:
{json.dumps(compact_candidates, indent=2, default=str)[:9000]}

Choose which capability IDs to attempt and in what order. Return strict JSON only:
{{
  "selected_ids": ["candidate id"],
  "reason": "short reason"
}}

Rules:
- Select at most {max_capabilities} IDs.
- Select only IDs present in the candidate list.
- Prefer likely, evidence-backed checks over broad generic checks.
- Do not include commands, payloads, shell, or exploit instructions.
"""
    try:
        raw = call_redteam_llm(prompt, settings=load_settings(), provider=provider)
        parsed = parse_json(raw)
        return validate_validation_strategy(parsed, candidates, max_capabilities, fallback, raw)
    except Exception as exc:
        if not is_llm_api_error(exc) and not isinstance(exc, (LLMError, RuntimeError, ValueError, json.JSONDecodeError)):
            raise
        return {**fallback, "planner_error": f"{type(exc).__name__}: {exc}"}


def fallback_validation_strategy(candidates: list[dict[str, Any]], max_capabilities: int) -> dict[str, Any]:
    return {
        "selected_ids": [str(item.get("id")) for item in candidates[:max_capabilities] if item.get("id")],
        "reason": "Deterministic fallback selected the highest-ranked candidates.",
        "generated_by": "fallback",
    }


def validate_validation_strategy(
    parsed: dict[str, Any],
    candidates: list[dict[str, Any]],
    max_capabilities: int,
    fallback: dict[str, Any],
    raw: str = "",
) -> dict[str, Any]:
    allowed = {str(item.get("id")) for item in candidates if item.get("id")}
    selected: list[str] = []
    for raw_id in parsed.get("selected_ids", []):
        cap_id = str(raw_id)
        if cap_id in allowed and cap_id not in selected:
            selected.append(cap_id)
        if len(selected) >= max_capabilities:
            break
    if not selected:
        selected = fallback["selected_ids"]
    return {
        "selected_ids": selected,
        "reason": str(parsed.get("reason") or "LLM generated a validated capability selection strategy."),
        "generated_by": "llm",
        "llm_raw": raw[:2500],
    }


def metasploit_backend() -> str:
    return os.getenv("MEDFLOW_METASPLOIT_BACKEND", "auto").strip().lower() or "auto"


def rpc_settings() -> dict[str, Any]:
    return {
        "password": os.getenv("MSFRPC_PASSWORD", "medflow"),
        "server": os.getenv("MSFRPC_HOST", "127.0.0.1"),
        "port": int(os.getenv("MSFRPC_PORT", "55552")),
        "ssl": os.getenv("MSFRPC_SSL", "true").lower() not in {"0", "false", "no"},
    }


def start_msfrpcd_if_requested() -> dict[str, Any]:
    if os.getenv("MEDFLOW_START_MSFRPCD", "").lower() not in {"1", "true", "yes"}:
        return {"started": False, "reason": "MEDFLOW_START_MSFRPCD is not enabled."}
    settings = rpc_settings()
    msfrpcd = Path("/usr/bin/msfrpcd")
    if not msfrpcd.exists():
        return {"started": False, "reason": "msfrpcd not found."}
    argv = [
        str(msfrpcd),
        "-P",
        str(settings["password"]),
        "-a",
        str(settings["server"]),
        "-p",
        str(settings["port"]),
        "-S",
        "-f",
    ]
    subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)
    return {"started": True, "argv": [argv[0], "-P", "<redacted>", *argv[3:]]}
