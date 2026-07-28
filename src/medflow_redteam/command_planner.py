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
PROOF_MARKER = "MEDFLOW_RCE_PROOF_7F3A"
ALLOWED_PROOF_COMMANDS = {
    f"echo {PROOF_MARKER}": "Emit a deterministic marker using a common shell built-in.",
    "id": "Show the effective Unix user and groups.",
    "whoami": "Show the effective username on Unix or Windows.",
    "pwd": "Show the current Unix working directory.",
    "hostname": "Show the target hostname on Unix or Windows.",
    "uname -a": "Show Unix kernel/platform information.",
    "cd": "Show the current Windows command-shell directory.",
    "ver": "Show the Windows command-shell version.",
    "sw_vers": "Show the macOS product and version.",
}
PROOF_COMMAND_PLATFORMS = {
    f"echo {PROOF_MARKER}": {"unknown", "unix", "windows", "macos"},
    "id": {"unix", "macos"},
    "whoami": {"unknown", "unix", "windows", "macos"},
    "pwd": {"unix", "macos"},
    "hostname": {"unknown", "unix", "windows", "macos"},
    "uname -a": {"unix", "macos"},
    "cd": {"windows"},
    "ver": {"windows"},
    "sw_vers": {"macos"},
}
PROOF_COMMAND_PREFERENCES = {
    "unix": ["id", "whoami", "pwd", "hostname", "uname -a", f"echo {PROOF_MARKER}"],
    "windows": [f"echo {PROOF_MARKER}", "whoami", "hostname", "cd", "ver"],
    "macos": ["id", "whoami", "pwd", "hostname", "sw_vers", "uname -a", f"echo {PROOF_MARKER}"],
    "unknown": [f"echo {PROOF_MARKER}", "whoami", "hostname"],
}


def plan_nmap_command(
    target: str,
    ports: list[int],
    *,
    provider: str = "gpt_oss",
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
    session_proof_command: str = "",
    provider: str = "gpt_oss",
    use_llm: bool = False,
) -> dict[str, Any]:
    fallback = fallback_metasploit_resource(
        target,
        module_path,
        options,
        selected_payload,
        action,
        session_proof_command=session_proof_command,
    )
    if not use_llm:
        return fallback
    expected_cmd = str(options.get("CMD") or "")
    proof_instruction = (
        f'- After sessions -l, run exactly: {format_session_proof_line(session_proof_command)}'
        if session_proof_command
        else "- Do not add a sessions -c command for this direct-output payload."
    )
    prompt = f"""
You generate a Metasploit resource command plan for an authorized isolated lab.

Module: {module_path}
Target host: {target}
Action: {action}
Selected payload: {selected_payload or "(none)"}
Session proof command: {session_proof_command or "(not applicable)"}
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
- Use only resource lines beginning with: use, set, check, run -j, sleep, sessions -l, sessions -c, sessions -K, exit -y.
- Do not include shell commands, backticks, semicolons inside values, file writes, persistence, credential dumping, or evasion.
- If action is check, end with check and exit -y.
- If action is exploit, use run -j, sleep, sessions -l, sessions -K, exit -y.
- For cmd/unix/generic or cmd/windows/generic, set CMD to the exact value already present in Options JSON.
{proof_instruction}
"""
    try:
        raw = call_redteam_llm(prompt, settings=load_settings(), provider=provider)
        parsed = parse_json(raw)
        lines = [str(item) for item in parsed.get("resource_lines", [])]
        validated = validate_metasploit_resource(
            lines,
            target,
            module_path,
            action,
            expected_cmd=expected_cmd,
            expected_session_proof_command=session_proof_command,
        )
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
    *,
    session_proof_command: str = "",
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
    if (
        action == "exploit"
        and selected_payload in {"cmd/unix/generic", "cmd/windows/generic"}
        and not any(line.startswith("set CMD ") for line in resource_lines)
    ):
        proof_plan = fallback_proof_command(
            {
                "selected_payload": selected_payload,
                "module": module_path,
            }
        )
        resource_lines.append(f"set CMD {proof_plan['command']}")
    if action == "exploit":
        resource_lines.extend(["run -j", "sleep 12", "sessions -l"])
        if session_proof_command:
            resource_lines.append(format_session_proof_line(session_proof_command))
        resource_lines.extend(["sessions -K", "exit -y"])
    else:
        resource_lines.extend(["check", "exit -y"])
    return {
        "resource_lines": validate_metasploit_resource(
            resource_lines,
            target,
            module_path,
            action,
            expected_cmd=str(options.get("CMD") or ""),
            expected_session_proof_command=session_proof_command,
        ),
        "reason": "Deterministic fallback Metasploit resource plan.",
        "generated_by": "fallback",
    }


def format_session_proof_line(command: str) -> str:
    validated = validate_proof_command(command)
    return f"sessions -c {shlex.quote(validated)}"


def validate_metasploit_resource(
    lines: list[str],
    target: str,
    module_path: str,
    action: str,
    *,
    expected_cmd: str = "",
    expected_session_proof_command: str = "",
) -> list[str]:
    if not lines or lines[0] != f"use {module_path}":
        raise ValueError("Metasploit plan must begin with the selected module.")
    if any(";" in line or "`" in line or "$(" in line for line in lines):
        raise ValueError("Metasploit resource lines cannot contain shell chaining or substitution.")
    has_target = False
    command_option_seen = False
    session_proof_seen = False
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
                value = validate_proof_command(value)
                if expected_cmd and value != validate_proof_command(expected_cmd):
                    raise ValueError("Metasploit CMD must match the selected proof command.")
                command_option_seen = True
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
        elif parts[:2] == ["sessions", "-c"]:
            if len(parts) != 3:
                raise ValueError("Metasploit sessions -c requires one quoted proof command.")
            session_command = validate_proof_command(parts[2])
            if (
                expected_session_proof_command
                and session_command
                != validate_proof_command(expected_session_proof_command)
            ):
                raise ValueError(
                    "Metasploit session command must match the selected proof command."
                )
            session_proof_seen = True
        elif line in {"sessions -l", "sessions -K", "exit -y"}:
            continue
        else:
            raise ValueError(f"Metasploit resource line not allowed: {line}")
    if not has_target:
        raise ValueError("Metasploit plan must set RHOSTS/RHOST to the exact target.")
    if expected_cmd and not command_option_seen:
        raise ValueError("Metasploit plan must set the selected direct proof command.")
    if action == "exploit":
        required = {"run -j", "sessions -l", "sessions -K", "exit -y"}
        if not required.issubset(set(lines)):
            raise ValueError("Exploit plan must run, list sessions, kill sessions, and exit.")
        if expected_session_proof_command and not session_proof_seen:
            raise ValueError("Exploit plan must run the selected session proof command.")
    else:
        if "check" not in lines or "exit -y" not in lines:
            raise ValueError("Check plan must include check and exit -y.")
    return lines


def plan_proof_command(
    context: dict[str, Any],
    *,
    provider: str = "gpt_oss",
    use_llm: bool = False,
) -> dict[str, Any]:
    fallback = fallback_proof_command(context)
    if not use_llm:
        return fallback
    platform = fallback["platform"]
    candidates = proof_commands_for_platform(platform)
    prompt = f"""
You choose one harmless command-execution proof command for an authorized isolated lab.

Inferred target command platform: {platform}

Context:
{json.dumps(context, indent=2, default=str)[:4000]}

Allowed commands:
{json.dumps(candidates, indent=2)}

Return strict JSON only:
{{
  "command": "{fallback['command']}",
  "reason": "short reason"
}}

Rules:
- Choose exactly one command from the allowed command keys.
- Do not invent commands, arguments, shell metacharacters, file writes, downloads, persistence, or cleanup commands.
- Use only commands compatible with the inferred target platform.
- Prefer deterministic marker proof when the target platform is unknown.
- Otherwise prefer observable identity or platform proof.
"""
    try:
        raw = call_redteam_llm(prompt, settings=load_settings(), provider=provider)
        parsed = parse_json(raw)
        command = validate_proof_command(
            str(parsed.get("command") or ""),
            platform=platform,
        )
        return {
            "command": command,
            "reason": str(parsed.get("reason") or "LLM selected a validated proof command."),
            "generated_by": "llm",
            "platform": platform,
            "candidates": list(candidates),
            "llm_raw": raw[:1500],
        }
    except Exception as exc:
        if not is_llm_api_error(exc) and not isinstance(exc, (LLMError, RuntimeError, ValueError, json.JSONDecodeError)):
            raise
        return {**fallback, "planner_error": f"{type(exc).__name__}: {exc}"}


def fallback_proof_command(context: dict[str, Any] | None = None) -> dict[str, Any]:
    platform = infer_proof_platform(context or {})
    command = {
        "unix": "id",
        "macos": "id",
        "windows": f"echo {PROOF_MARKER}",
        "unknown": f"echo {PROOF_MARKER}",
    }[platform]
    return {
        "command": command,
        "reason": f"Deterministic {platform} command-execution proof.",
        "generated_by": "fallback",
        "platform": platform,
        "candidates": list(proof_commands_for_platform(platform)),
    }


def validate_proof_command(command: str, *, platform: str | None = None) -> str:
    normalized = re.sub(r"\s+", " ", command.strip())
    if normalized not in ALLOWED_PROOF_COMMANDS:
        raise ValueError(f"Proof command not allowed: {command}")
    if platform and normalized not in proof_commands_for_platform(platform):
        raise ValueError(
            f"Proof command {normalized!r} is not allowed for platform {platform!r}."
        )
    return normalized


def proof_commands_for_platform(platform: str) -> dict[str, str]:
    normalized = platform if platform in PROOF_COMMAND_PREFERENCES else "unknown"
    return {
        command: ALLOWED_PROOF_COMMANDS[command]
        for command in PROOF_COMMAND_PREFERENCES[normalized]
    }


def infer_proof_platform(context: dict[str, Any]) -> str:
    selected_payload = str(context.get("selected_payload") or "").lower()
    if "windows" in selected_payload:
        return "windows"
    if any(term in selected_payload for term in ("cmd/unix/", "cmd/linux/", "linux/")):
        return "unix"
    if any(term in selected_payload for term in ("osx/", "macos/", "darwin/")):
        return "macos"

    evidence = " ".join(
        [
            scalar_context(context.get("platform")),
            scalar_context(context.get("module")),
            scalar_context(context.get("service")),
            scalar_context(context.get("description")),
            scalar_context(context.get("targets")),
        ]
    ).lower()
    if re.search(r"\b(windows|win32|win64|microsoft|iis)\b", evidence):
        return "windows"
    if re.search(r"\b(macos|mac os|osx|darwin)\b", evidence):
        return "macos"
    if re.search(r"\b(linux|unix|freebsd|openbsd|netbsd|solaris|sunos|aix)\b", evidence):
        return "unix"
    return "unknown"


def scalar_context(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        return " ".join(
            f"{key} {scalar_context(item)}"
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set)):
        return " ".join(scalar_context(item) for item in value)
    return str(value)


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
    provider: str = "gpt_oss",
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
    provider: str = "gpt_oss",
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
