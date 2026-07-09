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
    "TARGET",
    "TARGETURI",
    "URI",
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
- For cmd/unix/generic exploit payloads, set CMD id.
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
    if action == "exploit" and selected_payload == "cmd/unix/generic":
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
