from __future__ import annotations

import ast
import importlib.util
import json
import multiprocessing
import os
import signal
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from queue import Empty
from typing import Any

from .command_planner import PROOF_MARKER, fallback_proof_command
from .config_loader import ROOT, load_lab_config
from .tool_quality import (
    EXECUTABLE_STATES,
    FINDING_STATES,
    artifact_hash,
    quality_for_spec,
    record_quality_outcome,
    register_artifact,
    registry_write_lock,
)


CONFIG_TOOL_DIR = ROOT / "config" / "generated_tools"
DATA_TOOL_DIR = ROOT / "data" / "generated_tools"
ALLOWED_IMPORTS = {
    "concurrent",
    "ftplib",
    "html",
    "ipaddress",
    "json",
    "re",
    "shutil",
    "socket",
    "subprocess",
    "time",
    "urllib",
    "xml",
}
BLOCKED_CALLS = {"eval", "exec", "compile", "input", "open", "__import__"}


@dataclass
class GeneratedToolValidation:
    ok: bool
    errors: list[str]


def generated_tool_proof_policy(
    spec: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    plan = fallback_proof_command(
        {
            "module": spec.get("module_path") or spec.get("id") or "",
            "platform": spec.get("platform") or [],
            "targets": spec.get("targets") or [],
            "description": spec.get("description") or "",
            "service": context.get("matched_service") or context.get("service") or {},
        }
    )
    return {
        "platform": plan["platform"],
        "default_command": plan["command"],
        "allowed_commands": plan["candidates"],
    }


def load_generated_tool_specs() -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for root in [CONFIG_TOOL_DIR, DATA_TOOL_DIR]:
        path = root / "tool_specs.json"
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("tools", []):
            spec = {
                **item,
                "provider": item.get("provider", "generated_python"),
                "runner": "generated_python_tool",
                "source": str(path),
                "execution": "on_demand_generated_python",
            }
            try:
                code_path = resolve_generated_tool_code(spec)
                initial_state = "shadow" if spec.get("generated_by") == "toolsmith_template" else "candidate"
                quality = quality_for_spec(spec, code_path, initial_state=initial_state)
                spec.update(
                    {
                        "artifact_hash": quality["artifact_hash"],
                        "quality_state": quality["state"],
                        "quality_score": quality["quality_score"],
                        "quality_stats": quality.get("stats", {}),
                    }
                )
            except (OSError, ValueError):
                spec.update({"quality_state": "quarantined", "quality_score": 0.0})
            specs.append(spec)
    return specs


def get_generated_tool_spec(tool_id: str) -> dict[str, Any]:
    for spec in load_generated_tool_specs():
        if spec.get("id") == tool_id:
            return spec
    raise KeyError(f"Generated tool not found: {tool_id}")


def get_generated_tool_spec_by_role(operation_role: str) -> dict[str, Any]:
    for spec in load_generated_tool_specs():
        if spec.get("operation_role") == operation_role:
            return spec
    raise KeyError(f"Generated tool role not found: {operation_role}")


def resolve_generated_tool_code(spec: dict[str, Any]) -> Path:
    code_path = spec.get("code_path")
    if not code_path:
        raise ValueError("Generated tool spec is missing code_path.")
    candidate = Path(code_path)
    roots = [CONFIG_TOOL_DIR, DATA_TOOL_DIR]
    if candidate.is_absolute():
        resolved = candidate.resolve()
        if not any(resolved.is_relative_to(root.resolve()) for root in roots):
            raise ValueError("Generated tool code path is outside approved generated tool directories.")
        return resolved
    for root in roots:
        resolved = (root / candidate).resolve()
        if resolved.exists() and resolved.is_relative_to(root.resolve()):
            return resolved
    raise FileNotFoundError(f"Generated tool code not found: {code_path}")


def validate_generated_tool_code(path: Path) -> GeneratedToolValidation:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")
    if len(text) > 20000:
        errors.append("Generated tool code exceeds 20k character limit.")
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        return GeneratedToolValidation(False, [f"Syntax error: {exc}"])

    has_run = any(isinstance(node, ast.FunctionDef) and node.name == "run" for node in tree.body)
    if not has_run:
        errors.append("Generated tool must define run(context: dict) -> dict.")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".", 1)[0] not in ALLOWED_IMPORTS:
                    errors.append(f"Import not allowed: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").split(".", 1)[0]
            if module not in ALLOWED_IMPORTS:
                errors.append(f"Import not allowed: {node.module}")
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in BLOCKED_CALLS:
                errors.append(f"Call not allowed: {node.func.id}")
            if isinstance(node.func, ast.Attribute):
                dotted = attribute_name(node.func)
                if dotted in {"subprocess.Popen", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}:
                    errors.append(f"Subprocess API not allowed: {dotted}; use subprocess.run with fixed argument lists.")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            errors.append("Dunder attribute access is not allowed.")
    return GeneratedToolValidation(not errors, sorted(set(errors)))


def attribute_name(node: ast.Attribute) -> str:
    parts = [node.attr]
    value = node.value
    while isinstance(value, ast.Attribute):
        parts.append(value.attr)
        value = value.value
    if isinstance(value, ast.Name):
        parts.append(value.id)
    return ".".join(reversed(parts))


def execute_generated_tool(target: str, spec: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    try:
        code_path = resolve_generated_tool_code(spec)
    except (OSError, ValueError) as exc:
        return {
            "allowed": False,
            "verified": False,
            "exploited": False,
            "tool_error": True,
            "reason": f"Generated tool code could not be resolved: {exc}",
            "quality_state": "quarantined",
        }
    initial_state = "shadow" if spec.get("generated_by") == "toolsmith_template" else "candidate"
    try:
        quality = quality_for_spec(spec, code_path, initial_state=initial_state)
    except ValueError as exc:
        return {
            "allowed": False,
            "verified": False,
            "exploited": False,
            "tool_error": True,
            "reason": f"Generated tool failed integrity validation: {exc}",
            "quality_state": "quarantined",
        }
    artifact = quality["artifact_hash"]
    quality_state = quality["state"]
    if quality_state not in EXECUTABLE_STATES:
        return {
            "allowed": False,
            "verified": False,
            "exploited": False,
            "reason": f"Generated tool is not executable while quality state is {quality_state}.",
            "artifact_hash": artifact,
            "quality_state": quality_state,
            "quality_score": quality["quality_score"],
        }
    validation = validate_generated_tool_code(code_path)
    if not validation.ok:
        updated = record_quality_outcome(artifact, "tool_error", reason="; ".join(validation.errors))
        return {
            "allowed": False,
            "verified": False,
            "exploited": False,
            "tool_error": True,
            "reason": "Generated tool failed static validation: " + "; ".join(validation.errors),
            "artifact_hash": artifact,
            "quality_state": updated["state"],
            "quality_score": updated["quality_score"],
        }

    lab = load_lab_config()
    proof_policy = generated_tool_proof_policy(spec, context)
    tool_context = {
        **context,
        "target": target,
        "capability": spec,
        "lab": lab,
        "proof_marker": PROOF_MARKER,
        "proof_command": proof_policy["default_command"],
        "proof_policy": proof_policy,
        "tmp_dir": tempfile.gettempdir(),
    }
    started = time.perf_counter()
    try:
        timeout_seconds = max(1, min(int(spec.get("timeout_seconds") or 15), 60))
    except (TypeError, ValueError):
        updated = record_quality_outcome(artifact, "tool_error", reason="timeout_seconds is not an integer.")
        return {
            "allowed": False,
            "verified": False,
            "exploited": False,
            "tool_error": True,
            "reason": "Generated tool has an invalid timeout_seconds value.",
            "artifact_hash": artifact,
            "quality_state": updated["state"],
            "quality_score": updated["quality_score"],
        }
    start_method = "fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn"
    process_context = multiprocessing.get_context(start_method)
    queue = process_context.Queue(maxsize=1)
    process = process_context.Process(target=_generated_tool_worker, args=(str(code_path), tool_context, queue))
    try:
        process.start()
    except (OSError, RuntimeError) as exc:
        updated = record_quality_outcome(artifact, "tool_error", reason=f"Worker start failed: {exc}")
        return {
            "allowed": True,
            "verified": False,
            "exploited": False,
            "tool_error": True,
            "reason": f"Generated tool worker could not start: {exc}",
            "artifact_hash": artifact,
            "quality_state": updated["state"],
            "quality_score": updated["quality_score"],
        }
    process.join(timeout_seconds)
    if process.is_alive():
        terminate_generated_tool_process(process)
        updated = record_quality_outcome(artifact, "tool_error", reason=f"Execution timed out after {timeout_seconds}s.")
        return {
            "allowed": True,
            "verified": False,
            "exploited": False,
            "tool_error": True,
            "reason": f"Generated tool timed out after {timeout_seconds}s.",
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "artifact_hash": artifact,
            "quality_state": updated["state"],
            "quality_score": updated["quality_score"],
        }
    try:
        envelope = queue.get(timeout=1)
    except Empty:
        envelope = {"ok": False, "error": f"Generated tool process exited with code {process.exitcode} without a result."}
    if not envelope.get("ok"):
        updated = record_quality_outcome(artifact, "tool_error", reason=str(envelope.get("error") or "Unknown worker error."))
        return {
            "allowed": True,
            "verified": False,
            "exploited": False,
            "tool_error": True,
            "reason": str(envelope.get("error") or "Generated tool worker failed."),
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "artifact_hash": artifact,
            "quality_state": updated["state"],
            "quality_score": updated["quality_score"],
        }
    result = envelope.get("result")
    result_validation = validate_generated_tool_result(result)
    if not result_validation.ok:
        reason = "Generated tool returned an invalid result: " + "; ".join(result_validation.errors)
        updated = record_quality_outcome(artifact, "tool_error", reason=reason)
        return {
            "allowed": True,
            "verified": False,
            "exploited": False,
            "tool_error": True,
            "reason": reason,
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "generated_tool_code": str(code_path),
            "artifact_hash": artifact,
            "quality_state": updated["state"],
            "quality_score": updated["quality_score"],
        }
    result = dict(result)
    if result.get("tool_error"):
        result["verified"] = False
        result["exploited"] = False
        outcome = "tool_error"
    elif result.get("inconclusive"):
        outcome = "inconclusive"
    else:
        outcome = "completed"
    updated = record_quality_outcome(artifact, outcome, reason=str(result.get("reason") or result.get("proof_output") or "")[:500])
    result.setdefault("allowed", True)
    result.setdefault("verified", False)
    result.setdefault("exploited", False)
    if outcome != "tool_error":
        apply_quality_result_gate(result, quality_state)
    result["elapsed_seconds"] = result.get("elapsed_seconds", round(time.perf_counter() - started, 3))
    result["generated_tool_code"] = str(code_path)
    result["artifact_hash"] = artifact
    result["quality_state"] = updated["state"]
    result["quality_score"] = updated["quality_score"]
    return result


def apply_quality_result_gate(result: dict[str, Any], quality_state: str) -> dict[str, Any]:
    if quality_state in FINDING_STATES:
        return result
    result["reported_verified"] = bool(result.get("verified"))
    result["reported_exploited"] = bool(result.get("exploited"))
    result["verified"] = False
    result["exploited"] = False
    result["quality_shadow"] = True
    reported_reason = str(result.get("reason") or "").strip()
    if reported_reason:
        result["reported_reason"] = reported_reason
    notice = (
        f"Tool ran in {quality_state} quality state; its self-reported result is retained as shadow evidence "
        "but cannot create a finding."
    )
    result["reason"] = f"{notice} Tool result: {reported_reason}" if reported_reason else notice
    return result


def validate_generated_tool_result(result: Any) -> GeneratedToolValidation:
    if not isinstance(result, dict):
        return GeneratedToolValidation(False, ["run(context) must return a dictionary."])
    errors: list[str] = []
    for field in ["allowed", "verified", "exploited", "inconclusive", "tool_error"]:
        if field in result and not isinstance(result[field], bool):
            errors.append(f"{field} must be a boolean.")
    verified = result.get("verified") is True
    exploited = result.get("exploited") is True
    if exploited and not verified:
        errors.append("exploited=true requires verified=true.")
    if result.get("allowed") is False and (verified or exploited):
        errors.append("A blocked result cannot be verified or exploited.")
    if result.get("tool_error") is True and (verified or exploited):
        errors.append("A tool error cannot be verified or exploited.")
    if verified or exploited:
        proof = result.get("proof_output") or result.get("evidence")
        if not proof:
            errors.append("Positive results require proof_output or evidence.")
    try:
        encoded = json.dumps(result, default=reject_non_json_value)
    except (TypeError, ValueError):
        errors.append("Result must contain only JSON-serializable values.")
    else:
        if len(encoded.encode("utf-8")) > 262_144:
            errors.append("Result exceeds the 256 KiB output limit.")
    return GeneratedToolValidation(not errors, sorted(set(errors)))


def reject_non_json_value(value: Any) -> Any:
    raise TypeError(f"Value is not JSON serializable: {type(value).__name__}")


def _generated_tool_worker(code_path: str, context: dict[str, Any], queue: Any) -> None:
    try:
        if hasattr(os, "setsid"):
            os.setsid()
        module_name = f"medflow_generated_{int(time.time() * 1000)}"
        import_spec = importlib.util.spec_from_file_location(module_name, code_path)
        if import_spec is None or import_spec.loader is None:
            raise RuntimeError("Could not import generated tool.")
        module = importlib.util.module_from_spec(import_spec)
        import_spec.loader.exec_module(module)
        if not hasattr(module, "run"):
            raise RuntimeError("Generated tool has no run(context) function.")
        result = module.run(context)
        validation = validate_generated_tool_result(result)
        if not validation.ok:
            raise ValueError("; ".join(validation.errors))
        queue.put({"ok": True, "result": result})
    except BaseException as exc:
        queue.put({"ok": False, "error": f"Generated tool raised {type(exc).__name__}: {exc}"})


def terminate_generated_tool_process(process: multiprocessing.Process) -> None:
    if hasattr(os, "killpg"):
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            process.terminate()
    else:
        process.terminate()
    process.join(2)
    if process.is_alive():
        if hasattr(os, "killpg"):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
        else:
            process.kill()
        process.join(1)


def execute_generated_tool_by_id(tool_id: str, target: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    spec = get_generated_tool_spec(tool_id)
    return execute_generated_tool(target, spec, context or {})


def execute_generated_tool_by_role(operation_role: str, target: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    spec = get_generated_tool_spec_by_role(operation_role)
    return execute_generated_tool(target, spec, context or {})


def save_generated_tool(
    tool_id: str,
    spec: dict[str, Any],
    code: str,
    overwrite: bool = False,
    *,
    initial_state: str = "candidate",
) -> dict[str, Path]:
    safe_id = safe_tool_id(tool_id)
    digest = artifact_hash(code, spec)
    code_dir = DATA_TOOL_DIR / "code"
    code_dir.mkdir(parents=True, exist_ok=True)
    code_path = code_dir / f"{safe_id}_{digest[:12]}.py"

    specs_path = DATA_TOOL_DIR / "tool_specs.json"
    with registry_write_lock(specs_path):
        if specs_path.exists():
            data = json.loads(specs_path.read_text(encoding="utf-8"))
        else:
            data = {"schema_version": 2, "tools": []}
        current = next((item for item in data.get("tools", []) if item.get("id") == spec["id"]), None)
        if current and current.get("artifact_hash") != digest and not overwrite:
            raise FileExistsError(
                f"Generated tool {spec['id']} already has a different cached version; "
                "use overwrite to create a new immutable version."
            )
        if code_path.exists() and code_path.read_text(encoding="utf-8") != code:
            raise ValueError(f"Generated tool hash collision at {code_path}.")
        created_code = not code_path.exists()
        if created_code:
            code_path.write_text(code, encoding="utf-8")
        validation = validate_generated_tool_code(code_path)
        if not validation.ok:
            if created_code:
                code_path.unlink(missing_ok=True)
            raise ValueError("Generated tool failed static validation: " + "; ".join(validation.errors))

        tools = [item for item in data.get("tools", []) if item.get("id") != spec["id"]]
        stored_spec = {**spec, "artifact_hash": digest, "code_path": f"code/{code_path.name}"}
        tools.append(stored_spec)
        data["schema_version"] = 2
        data["tools"] = sorted(tools, key=lambda item: item.get("id", ""))
        DATA_TOOL_DIR.mkdir(parents=True, exist_ok=True)
        temporary_specs = specs_path.with_suffix(".tmp")
        temporary_specs.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        temporary_specs.replace(specs_path)
    register_artifact(stored_spec, code_path, initial_state=initial_state)
    return {"specs": specs_path, "code": code_path}


def safe_tool_id(tool_id: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in tool_id.lower())
    cleaned = cleaned.strip("_")
    if not cleaned:
        raise ValueError("Tool id cannot be empty.")
    return cleaned[:120]


def tcp_banner_template(tool_id: str, service: str, port: int) -> tuple[dict[str, Any], str]:
    spec = {
        "id": f"generated:{tool_id}",
        "name": f"{service.upper()} TCP banner observation",
        "description": f"Generated Python TCP banner observation tool for {service} on port {port}.",
        "provider": "generated_python",
        "runner": "generated_python_tool",
        "risk": "safe observation",
        "safe_to_execute": True,
        "generated_by": "toolsmith_template",
        "allowed_execution_modes": ["safe", "aggressive_lab"],
        "match": {"service": service, "ports": [str(port)], "product_keywords": [service]},
        "proof_goal": f"Connect to {service} and capture a non-authenticated banner preview.",
    }
    code = f'''import socket
import time


def run(context: dict) -> dict:
    target = context["target"]
    capability = context["capability"]
    port = int((capability.get("match", {{}}).get("ports") or [{port}])[0])
    started = time.perf_counter()
    result = {{
        "allowed": True,
        "target": target,
        "service": "{service}",
        "port": port,
        "proof_goal": capability.get("proof_goal", "Capture TCP banner."),
        "verified": False,
        "exploited": False,
        "cleanup_verified": True,
    }}
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            sock.settimeout(3)
            banner = sock.recv(256)
        result["banner_hex_preview"] = banner[:128].hex()
        result["proof_output"] = "TCP banner or handshake bytes received."
        result["verified"] = bool(banner)
    except Exception as exc:
        result["reason"] = f"TCP banner observation failed: {{exc}}"
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result
'''
    return spec, code
