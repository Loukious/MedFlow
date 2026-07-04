from __future__ import annotations

import ast
import importlib.util
import json
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config_loader import ROOT, load_lab_config


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


def load_generated_tool_specs() -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for root in [CONFIG_TOOL_DIR, DATA_TOOL_DIR]:
        path = root / "tool_specs.json"
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("tools", []):
            specs.append(
                {
                    **item,
                    "provider": item.get("provider", "generated_python"),
                    "runner": "generated_python_tool",
                    "source": str(path),
                    "execution": "on_demand_generated_python",
                }
            )
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
        if not any(str(resolved).startswith(str(root.resolve())) for root in roots):
            raise ValueError("Generated tool code path is outside approved generated tool directories.")
        return resolved
    for root in roots:
        resolved = (root / candidate).resolve()
        if resolved.exists() and str(resolved).startswith(str(root.resolve())):
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
    code_path = resolve_generated_tool_code(spec)
    validation = validate_generated_tool_code(code_path)
    if not validation.ok:
        return {
            "allowed": False,
            "verified": False,
            "exploited": False,
            "reason": "Generated tool failed static validation: " + "; ".join(validation.errors),
        }

    module_name = f"medflow_generated_{int(time.time() * 1000)}"
    import_spec = importlib.util.spec_from_file_location(module_name, code_path)
    if import_spec is None or import_spec.loader is None:
        return {"allowed": False, "verified": False, "exploited": False, "reason": "Could not import generated tool."}
    module = importlib.util.module_from_spec(import_spec)
    import_spec.loader.exec_module(module)
    if not hasattr(module, "run"):
        return {"allowed": False, "verified": False, "exploited": False, "reason": "Generated tool has no run(context) function."}

    lab = load_lab_config()
    tool_context = {
        **context,
        "target": target,
        "capability": spec,
        "lab": lab,
        "proof_marker": "/tmp/medflow_langgraph_exploit_poc",
        "tmp_dir": tempfile.gettempdir(),
    }
    started = time.perf_counter()
    try:
        result = module.run(tool_context)
    except Exception as exc:
        return {
            "allowed": True,
            "verified": False,
            "exploited": False,
            "reason": f"Generated tool raised {type(exc).__name__}: {exc}",
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        }
    if not isinstance(result, dict):
        result = {"allowed": True, "verified": False, "exploited": False, "reason": "Generated tool returned a non-dict result."}
    result.setdefault("allowed", True)
    result.setdefault("verified", False)
    result.setdefault("exploited", False)
    result["elapsed_seconds"] = result.get("elapsed_seconds", round(time.perf_counter() - started, 3))
    result["generated_tool_code"] = str(code_path)
    return result


def execute_generated_tool_by_id(tool_id: str, target: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    spec = get_generated_tool_spec(tool_id)
    return execute_generated_tool(target, spec, context or {})


def execute_generated_tool_by_role(operation_role: str, target: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    spec = get_generated_tool_spec_by_role(operation_role)
    return execute_generated_tool(target, spec, context or {})


def save_generated_tool(tool_id: str, spec: dict[str, Any], code: str, overwrite: bool = False) -> dict[str, Path]:
    safe_id = safe_tool_id(tool_id)
    code_dir = DATA_TOOL_DIR / "code"
    code_dir.mkdir(parents=True, exist_ok=True)
    code_path = code_dir / f"{safe_id}.py"
    if code_path.exists() and not overwrite:
        raise FileExistsError(f"Generated tool code already exists: {code_path}")
    code_path.write_text(code, encoding="utf-8")
    validation = validate_generated_tool_code(code_path)
    if not validation.ok:
        code_path.unlink(missing_ok=True)
        raise ValueError("Generated tool failed static validation: " + "; ".join(validation.errors))

    specs_path = DATA_TOOL_DIR / "tool_specs.json"
    if specs_path.exists():
        data = json.loads(specs_path.read_text(encoding="utf-8"))
    else:
        data = {"schema_version": 1, "tools": []}
    tools = [item for item in data.get("tools", []) if item.get("id") != spec["id"]]
    tools.append({**spec, "code_path": f"code/{safe_id}.py"})
    data["tools"] = sorted(tools, key=lambda item: item.get("id", ""))
    DATA_TOOL_DIR.mkdir(parents=True, exist_ok=True)
    specs_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
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
