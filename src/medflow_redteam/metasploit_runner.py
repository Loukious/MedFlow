from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from typing import Any

from .command_planner import (
    PROOF_MARKER,
    metasploit_backend,
    plan_metasploit_resource,
    plan_proof_command,
    rpc_settings,
    start_msfrpcd_if_requested,
)
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

DIRECT_PROOF_PAYLOADS = {
    "cmd/unix/generic",
    "cmd/windows/generic",
}


def run_metasploit_module(
    target: str,
    capability: dict[str, Any],
    *,
    execution_mode: str,
    action: str = "check",
    timeout: int = 180,
    provider: str = "gpt_oss",
    use_llm: bool = False,
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

    attempts = []
    proof_command_plans: list[dict[str, Any]] = []
    payloads = payload_attempts(plan) if action == "exploit" else [plan.get("selected_payload", "")]
    final: dict[str, Any] | None = None
    for selected_payload in payloads:
        proof_command_plan: dict[str, Any] | None = None
        if action == "exploit":
            proof_command_plan = plan_proof_command(
                {
                    "target": target,
                    "module": plan.get("module_path"),
                    "service": capability.get("matched_service") or {},
                    "platform": capability.get("platform") or [],
                    "arch": capability.get("arch") or [],
                    "targets": capability.get("targets") or [],
                    "description": capability.get("description") or "",
                    "selected_payload": selected_payload,
                    "payload_candidates": plan.get("payload_candidates", []),
                },
                provider=provider,
                use_llm=use_llm,
            )
            proof_command_plans.append(
                {
                    "payload": selected_payload,
                    **proof_command_plan,
                }
            )
        for variant_options in option_variants(plan, options, selected_payload):
            attempt_options = dict(variant_options)
            if action == "exploit":
                attempt_options = {**attempt_options, **exploit_payload_options(target, selected_payload)}
                if (
                    proof_command_plan is not None
                    and supports_direct_proof_command(selected_payload)
                ):
                    attempt_options["CMD"] = proof_command_plan["command"]
            proc, stdout, stderr, elapsed, command = run_msfconsole_action(
                msfconsole,
                plan.get("module_path"),
                attempt_options,
                selected_payload,
                action,
                timeout=timeout,
                target=target,
                session_proof_command=(
                    str(proof_command_plan.get("command") or "")
                    if proof_command_plan
                    and not supports_direct_proof_command(selected_payload)
                    else ""
                ),
                provider=provider,
                use_llm=use_llm,
            )
            combined = stdout + "\n" + stderr
            verdict = parse_check_verdict(combined)
            session_created = bool(re.search(r"(command shell|meterpreter) session \d+ opened", combined, re.I))
            proof_command = (
                str(proof_command_plan.get("command") or "")
                if proof_command_plan
                else ""
            )
            command_proof = bool(
                proof_command
                and has_command_output_proof(combined, proof_command)
            )
            command_executed = bool(re.search(r"\[\+\]\s+command executed\b", combined, re.I))
            exploited = action == "exploit" and (session_created or command_proof)
            final = {
                "payload": selected_payload,
                "proof_command": proof_command,
                "proof_command_plan": proof_command_plan,
                "options": attempt_options,
                "command": command,
                "returncode": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "elapsed_seconds": round(elapsed, 3),
                "verdict": verdict,
                "session_created": session_created,
                "command_proof": command_proof,
                "command_executed": command_executed,
                "exploited": exploited,
            }
            attempts.append(summarize_attempt(final))
            if exploited or action != "exploit":
                break
            if not should_retry_payload(combined):
                break
        if final and (final.get("exploited") or action != "exploit"):
            break

    if final is None:
        final = {
            "payload": "",
            "options": options,
            "command": [],
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "elapsed_seconds": 0,
            "verdict": "no_check_signal",
            "session_created": False,
            "command_proof": False,
            "command_executed": False,
            "exploited": False,
            "proof_command": "",
            "proof_command_plan": None,
        }
    stdout = final["stdout"]
    stderr = final["stderr"]
    verdict = final["verdict"]
    session_created = final["session_created"]
    command_proof = final["command_proof"]
    command_executed = final["command_executed"]
    exploited = final["exploited"]
    verified = exploited or verdict == "appears_vulnerable"
    return {
        "allowed": True,
        "verified": verified,
        "exploited": exploited,
        "cleanup_verified": "killing all sessions" in f"{stdout}\n{stderr}".lower() or not session_created,
        "reason": exploit_reason(verdict, exploited, session_created, command_executed) if action == "exploit" else check_reason(verdict),
        "proof_output": first_interesting_line(stdout, final.get("proof_command", "")) if verified else "",
        "proof_goal": (
            "Run Metasploit exploit against an allowlisted isolated lab target and collect session or platform-compatible harmless command proof."
            if action == "exploit"
            else "Run Metasploit check against an allowlisted lab target; do not execute exploit."
        ),
        "metasploit_plan": {**plan, "options": final["options"], "attempted_payloads": payloads},
        "proof_command_plan": final.get("proof_command_plan"),
        "proof_command_plans": proof_command_plans,
        "metasploit_check": {
            "command": redact_command(final["command"]),
            "returncode": final["returncode"],
            "stdout": stdout[-6000:],
            "stderr": stderr[-3000:],
            "elapsed_seconds": final["elapsed_seconds"],
            "verdict": verdict,
            "action": action,
            "session_created": session_created,
            "command_proof": command_proof,
            "command_executed": command_executed,
            "payload": final["payload"],
            "proof_command": final.get("proof_command", ""),
            "proof_platform": (
                (final.get("proof_command_plan") or {}).get("platform", "")
            ),
            "attempts": attempts,
        },
    }


def run_msfconsole_action(
    msfconsole: str,
    module_path: str,
    options: dict[str, str],
    selected_payload: str,
    action: str,
    *,
    timeout: int,
    target: str,
    session_proof_command: str = "",
    provider: str = "gpt_oss",
    use_llm: bool = False,
) -> tuple[subprocess.CompletedProcess[str], str, str, float, list[str]]:
    resource_plan = plan_metasploit_resource(
        target,
        module_path,
        options,
        selected_payload,
        action,
        session_proof_command=session_proof_command,
        provider=provider,
        use_llm=use_llm,
    )
    resource_lines = resource_plan["resource_lines"]
    backend = metasploit_backend()
    if backend in {"rpc", "auto"}:
        rpc_result = run_metasploit_rpc_action(resource_lines, timeout=timeout)
        if rpc_result is not None:
            proc, stdout, stderr, elapsed = rpc_result
            command = ["msfrpc", *resource_lines]
            stdout = f"[medflow_command_plan] {json.dumps(resource_plan, default=str)}\n{stdout}"
            return proc, strip_ansi(stdout), strip_ansi(stderr), elapsed, command
        if backend == "rpc":
            proc = subprocess.CompletedProcess(["msfrpc"], 1, "", "Metasploit RPC backend unavailable.")
            return proc, "", "Metasploit RPC backend unavailable.", 0.0, ["msfrpc", *resource_lines]
    command = [msfconsole, "-q", "-x", "; ".join(resource_lines)]
    started = time.monotonic()
    proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    elapsed = time.monotonic() - started
    stdout = f"[medflow_command_plan] {json.dumps(resource_plan, default=str)}\n{proc.stdout}"
    return proc, strip_ansi(stdout), strip_ansi(proc.stderr), elapsed, command


def run_metasploit_rpc_action(
    resource_lines: list[str],
    *,
    timeout: int,
) -> tuple[subprocess.CompletedProcess[str], str, str, float] | None:
    try:
        from pymetasploit3.msfrpc import MsfRpcClient
    except Exception:
        return None
    start_msfrpcd_if_requested()
    settings = rpc_settings()
    started = time.monotonic()
    try:
        client = MsfRpcClient(
            settings["password"],
            server=settings["server"],
            port=settings["port"],
            ssl=settings["ssl"],
        )
        console = client.consoles.console()
        console.write("\n".join(resource_lines) + "\n")
        output = ""
        while time.monotonic() - started < timeout:
            chunk = console.read()
            output += str(chunk.get("data") or "")
            if not chunk.get("busy") and re.search(r"exit|completed|sessions|Job \d+", output, re.I):
                break
            time.sleep(1)
        try:
            console.destroy()
        except Exception:
            pass
        elapsed = time.monotonic() - started
        proc = subprocess.CompletedProcess(["msfrpc", *resource_lines], 0, output, "")
        return proc, output, "", elapsed
    except Exception as exc:
        return None


def payload_attempts(plan: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    payloads: list[str] = []

    def add(payload: str) -> None:
        if payload and payload not in seen:
            seen.add(payload)
            payloads.append(payload)

    add(str(plan.get("selected_payload") or ""))
    for item in plan.get("payload_candidates", []):
        if isinstance(item, dict):
            add(str(item.get("payload") or ""))
        else:
            add(str(item))
    selected = str(plan.get("selected_payload") or "")
    preferred_direct = ""
    if "windows" in selected:
        preferred_direct = "cmd/windows/generic"
    elif any(term in selected for term in ("cmd/unix/", "cmd/linux/", "linux/")):
        preferred_direct = "cmd/unix/generic"
    if not preferred_direct:
        preferred_direct = next(
            (payload for payload in payloads if supports_direct_proof_command(payload)),
            "",
        )
    if preferred_direct in payloads:
        payloads = [
            preferred_direct,
            *[payload for payload in payloads if payload != preferred_direct],
        ]
    return payloads[:4] or [""]


def supports_direct_proof_command(payload: str) -> bool:
    return payload in DIRECT_PROOF_PAYLOADS


def option_variants(plan: dict[str, Any], options: dict[str, str], selected_payload: str = "") -> list[dict[str, str]]:
    variants = [dict(options)]
    text = " ".join(str(plan.get(key, "")) for key in ["module_path", "module_id"]).lower()
    if any(term in text for term in ["deserialize", "deserial", "shiro"]):
        for chain in ["CommonsBeanutils1", "CommonsCollections2", "CommonsCollections1"]:
            variant = {**options, "JAVA_GADGET_CHAIN": chain}
            if variant not in variants:
                variants.append(variant)
    if selected_payload.startswith("cmd/linux/") or "/linux/" in selected_payload or "linux" in text:
        for target_id in ["1", "2"]:
            variant = {**options, "TARGET": target_id}
            if variant not in variants:
                variants.append(variant)
    if selected_payload.startswith("cmd/windows/") or "/windows/" in selected_payload:
        variant = {**options, "TARGET": "0"}
        if variant not in variants:
            variants.append(variant)
    return variants[:4]


def should_retry_payload(output: str) -> bool:
    lowered = output.lower()
    retry_signals = [
        "is not a compatible payload",
        "no session was created",
        "exploit aborted",
        "cannot reliably check exploitability",
    ]
    return any(signal in lowered for signal in retry_signals)


def summarize_attempt(attempt: dict[str, Any]) -> dict[str, Any]:
    return {
        "payload": attempt.get("payload", ""),
        "proof_command": attempt.get("proof_command", ""),
        "returncode": attempt.get("returncode"),
        "verdict": attempt.get("verdict"),
        "session_created": attempt.get("session_created", False),
        "command_proof": attempt.get("command_proof", False),
        "command_executed": attempt.get("command_executed", False),
        "exploited": attempt.get("exploited", False),
        "elapsed_seconds": attempt.get("elapsed_seconds"),
        "last_line": last_interesting_line(f"{attempt.get('stdout', '')}\n{attempt.get('stderr', '')}"),
    }


def exploit_payload_options(target: str, payload: str) -> dict[str, str]:
    options: dict[str, str] = {}
    lhost = infer_lhost(target)
    if "reverse" in payload:
        if lhost:
            options["LHOST"] = lhost
        options["LPORT"] = "4445"
    if "/http/" in payload or "/https/" in payload:
        if lhost:
            options["SRVHOST"] = lhost
            options["FETCH_SRVHOST"] = lhost
        options["SRVPORT"] = "18080"
        options["FETCH_SRVPORT"] = "18080"
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


def exploit_reason(verdict: str, exploited: bool, session_created: bool, command_executed: bool) -> str:
    if exploited and session_created:
        return "Metasploit exploit opened a command or Meterpreter session in the isolated lab and cleanup was attempted."
    if exploited and command_executed:
        return "Metasploit reported command execution in the isolated lab."
    if exploited:
        return "Metasploit exploit produced command-execution proof in the isolated lab."
    if command_executed:
        return "Metasploit reported command execution, but no allowed proof-command output or session proof was collected."
    if verdict == "appears_vulnerable":
        return "Metasploit exploit reached a vulnerable target signal, but no session or command proof was collected."
    return check_reason(verdict)


def first_interesting_line(output: str, proof_command: str = "") -> str:
    for line in output.splitlines():
        lowered = line.lower()
        if "session" in lowered and "opened" in lowered:
            return line.strip()
    for line in output.splitlines():
        if re.search(r"\buid=\d+.*\bgid=\d+", line):
            return line.strip()
    proof_line = first_proof_command_line(output, proof_command)
    if proof_line:
        return proof_line
    for line in output.splitlines():
        if re.search(r"\[\+\]\s+command executed\b", line, flags=re.I):
            return line.strip()
    for line in output.splitlines():
        lowered = line.lower()
        if "appears to be vulnerable" in lowered or "is vulnerable" in lowered:
            return line.strip()
    return ""


def has_command_output_proof(output: str, command: str) -> bool:
    return any(
        proof_command_line_matches(line, command)
        for line in proof_output_lines(output)
    )


def first_proof_command_line(output: str, command: str) -> str:
    for line in proof_output_lines(output):
        stripped = line.strip()
        if proof_command_line_matches(stripped, command):
            return stripped
    return ""


def proof_output_lines(output: str) -> list[str]:
    return [
        line
        for line in output.splitlines()
        if line.strip()
        and not line.lstrip().startswith("[medflow_command_plan]")
    ]


def proof_command_line_matches(line: str, command: str) -> bool:
    stripped = line.strip()
    lowered = stripped.lower()
    if not stripped:
        return False
    if command == f"echo {PROOF_MARKER}":
        return stripped == PROOF_MARKER
    if command == "id":
        return bool(re.search(r"\buid=\d+.*\bgid=\d+", stripped))
    if command == "whoami":
        return bool(
            re.fullmatch(r"[A-Za-z0-9_.-]+(?:[\\/][A-Za-z0-9_.$-]+)?", stripped)
        )
    if command == "pwd":
        return bool(re.fullmatch(r"/[A-Za-z0-9_./ -]*", stripped))
    if command == "hostname":
        return bool(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", stripped)
        )
    if command == "uname -a":
        return any(
            platform in lowered
            for platform in (
                "linux",
                "gnu",
                "darwin",
                "freebsd",
                "openbsd",
                "netbsd",
                "sunos",
                "aix",
            )
        )
    if command == "cd":
        return bool(
            re.fullmatch(r"(?:[A-Za-z]:\\|\\\\)[^<>:\"|?*]*", stripped)
        )
    if command == "ver":
        return bool(
            re.search(r"(?:microsoft\s+)?windows\s+\[version\s+[^\]]+\]", lowered)
        )
    if command == "sw_vers":
        return lowered.startswith(("productname:", "productversion:", "buildversion:"))
    return False


def last_interesting_line(output: str) -> str:
    interesting = [line.strip() for line in output.splitlines() if line.strip()]
    return interesting[-1] if interesting else ""


def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", value)


def redact_command(command: list[str]) -> list[str]:
    return command[:]
