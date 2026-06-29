from __future__ import annotations

import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .capabilities import select_capabilities_for_services
from .config_loader import load_lab_config
from .generated_tools import execute_generated_tool, execute_generated_tool_by_role


_LAB_CONFIG = load_lab_config()
LOCAL_TARGETS = set(_LAB_CONFIG["safety"]["allowed_targets"])
ALLOWED_CIDRS = [ipaddress.ip_network(cidr) for cidr in _LAB_CONFIG["safety"]["allowed_cidrs"]]
DEFAULT_TARGET = _LAB_CONFIG["safety"]["default_target"]
CONTAINER_PORTS = [int(port) for port in _LAB_CONFIG["scan"]["container_ports"]]
HOST_PORTS = [int(port) for port in _LAB_CONFIG["scan"]["host_ports"]]
HTTP_CONTAINER_PORTS = [int(port) for port in _LAB_CONFIG["scan"]["http_container_ports"]]
HTTP_HOST_PORTS = [int(port) for port in _LAB_CONFIG["scan"]["http_host_ports"]]

@dataclass
class ToolResult:
    tool: str
    command: list[str] | None
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float


def default_ports_for_target(target: str) -> list[int]:
    if target in {"127.0.0.1", "localhost"}:
        return HOST_PORTS
    if target == DEFAULT_TARGET:
        return CONTAINER_PORTS
    return list(range(1, 1001))


def default_http_ports_for_target(target: str) -> list[int]:
    return HTTP_HOST_PORTS if target in {"127.0.0.1", "localhost"} else HTTP_CONTAINER_PORTS


def validate_target(target: str) -> str:
    if target in LOCAL_TARGETS:
        return target
    try:
        ip = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError(f"Refusing to scan target '{target}'. Target must be localhost or an allowed lab IP.") from exc
    if not any(ip in network for network in ALLOWED_CIDRS):
        allowed = [*sorted(LOCAL_TARGETS), *(str(network) for network in ALLOWED_CIDRS)]
        raise ValueError(f"Refusing to scan target '{target}'. Allowed lab targets/CIDRs: {', '.join(allowed)}")
    return target


def run_generated_operation(tool_id: str, target: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    target = validate_target(target)
    return execute_generated_tool_by_role(tool_id, target, context or {})


def generated_tool_result_to_tool_result(result: dict[str, Any], fallback_tool: str) -> ToolResult:
    payload = result.get("tool_result") or {}
    return ToolResult(
        tool=str(payload.get("tool") or fallback_tool),
        command=payload.get("command"),
        returncode=int(payload.get("returncode") if payload.get("returncode") is not None else (0 if result.get("verified") else 1)),
        stdout=str(payload.get("stdout") or result.get("proof_output") or ""),
        stderr=str(payload.get("stderr") or result.get("reason") or ""),
        elapsed_seconds=float(payload.get("elapsed_seconds") or result.get("elapsed_seconds") or 0.0),
    )


def tcp_connect_check(target: str, ports: list[int] | None = None, timeout: float = 1.0) -> dict:
    selected_ports = ports or default_ports_for_target(target)
    result = run_generated_operation("tcp_connect_check", target, {"ports": selected_ports, "timeout": timeout})
    return result.get("tcp", {})


def service_scan(target: str, ports: list[int] | None = None, profile: str | None = None) -> ToolResult:
    selected_ports = ports or default_ports_for_target(target)
    result = run_generated_operation("service_scan", target, {"ports": selected_ports, "profile": profile or "service_discovery"})
    return generated_tool_result_to_tool_result(result, "service_scan")


def safe_script_scan(target: str, ports: list[int] | None = None, profile: str | None = None) -> ToolResult:
    selected_ports = ports or default_ports_for_target(target)
    result = run_generated_operation("safe_script_scan", target, {"ports": selected_ports, "profile": profile or "safe_scripts"})
    return generated_tool_result_to_tool_result(result, "safe_script_scan")


def http_probe(target: str, ports: list[int] | None = None) -> dict:
    selected_ports = ports or default_http_ports_for_target(target)
    result = run_generated_operation("http_probe", target, {"ports": selected_ports})
    return {"http_probe": result.get("http_probe", [])}


def web_fingerprint(target: str, ports: list[int] | None = None) -> dict:
    selected_ports = ports or [80, 443, 8080, 8000, 5000, 8443]
    result = run_generated_operation("web_fingerprint", target, {"ports": selected_ports})
    return {"web_fingerprints": result.get("web_fingerprints", [])}


def web_route_discovery(target: str, ports: list[int] | None = None, paths: list[str] | None = None) -> dict:
    selected_ports = ports or [80, 443, 8080, 8000, 5000, 8443]
    context: dict[str, Any] = {"ports": selected_ports}
    if paths:
        context["paths"] = paths
    result = run_generated_operation("web_route_discovery", target, context)
    return {"web_routes": result.get("web_routes", [])}


def web_control_checks(web_routes: dict[str, Any] | None, fingerprints: dict[str, Any] | None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for item in (web_routes or {}).get("web_routes", []):
        if item.get("artifact_signal"):
            findings.append(
                {
                    "check": "artifact_exposure",
                    "title": item.get("artifact_signal"),
                    "url": item.get("url", ""),
                    "status": "confirmed_exposure",
                    "severity": "medium",
                    "confidence": "medium",
                    "evidence": f"{item.get('url')} returned {item.get('content_type')} with signal {item.get('artifact_signal')}",
                    "remediation": "Require authorization for downloadable artifacts and remove sensitive files from web-accessible paths.",
                    "references": ["web_route_discovery"],
                }
            )
    for item in (fingerprints or {}).get("web_fingerprints", []):
        if item.get("error"):
            continue
        headers = item.get("security_headers") or {}
        missing = [name for name, present in headers.items() if not present]
        if missing:
            findings.append(
                {
                    "check": "missing_security_headers",
                    "title": "Missing common browser security headers",
                    "url": item.get("url", ""),
                    "status": "confirmed_exposure",
                    "severity": "low",
                    "confidence": "medium",
                    "evidence": "Missing: " + ", ".join(sorted(missing)),
                    "remediation": "Set appropriate CSP, HSTS, X-Frame-Options, and X-Content-Type-Options headers where applicable.",
                    "references": ["web_fingerprint"],
                }
            )
        if item.get("set_cookie_present") and not headers.get("strict_transport_security"):
            findings.append(
                {
                    "check": "cookie_without_hsts_signal",
                    "title": "Cookie observed without HSTS signal",
                    "url": item.get("url", ""),
                    "status": "confirmed_exposure",
                    "severity": "low",
                    "confidence": "low",
                    "evidence": "Set-Cookie header was observed while Strict-Transport-Security was absent from the fingerprint.",
                    "remediation": "For HTTPS services, enable HSTS and review cookie Secure/HttpOnly/SameSite attributes.",
                    "references": ["web_fingerprint"],
                }
            )
    return {"findings": findings, "count": len(findings)}


def parse_zap_json_report(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    alerts = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            alerts.append(
                {
                    "tool": "zap",
                    "name": alert.get("alert") or alert.get("name"),
                    "risk": alert.get("riskdesc") or alert.get("riskcode"),
                    "confidence": alert.get("confidence"),
                    "description": alert.get("desc"),
                    "solution": alert.get("solution"),
                    "instances": alert.get("instances", []),
                }
            )
    return {"findings": alerts, "count": len(alerts)}


def parse_burp_xml_report(path: str | Path) -> dict[str, Any]:
    root = ET.fromstring(Path(path).read_text(encoding="utf-8"))
    findings = []
    for issue in root.findall(".//issue"):
        findings.append(
            {
                "tool": "burp",
                "name": text_or_empty(issue, "name"),
                "severity": text_or_empty(issue, "severity"),
                "confidence": text_or_empty(issue, "confidence"),
                "host": text_or_empty(issue, "host"),
                "path": text_or_empty(issue, "path"),
                "location": text_or_empty(issue, "location"),
                "issue_background": text_or_empty(issue, "issueBackground"),
                "remediation_background": text_or_empty(issue, "remediationBackground"),
            }
        )
    return {"findings": findings, "count": len(findings)}


def text_or_empty(node: ET.Element, child: str) -> str:
    found = node.find(child)
    return "".join(found.itertext()).strip() if found is not None else ""


def select_exploit_candidate(
    target: str,
    services: list[dict[str, str]],
    limit: int = 1,
    web_routes: dict[str, Any] | None = None,
    graph_memory: dict[str, Any] | None = None,
) -> dict:
    target = validate_target(target)
    return select_capabilities_for_services(
        target,
        services,
        limit=limit,
        web_routes=web_routes,
        graph_memory=graph_memory,
    )


def run_selected_exploit(
    target: str,
    selection: dict,
    use_sudo: bool = False,
    execution_mode: str = "safe",
) -> dict:
    selected_candidates = selection.get("selected_candidates") or ([selection.get("selected")] if selection and selection.get("selected") else [])
    if not selected_candidates:
        return {
            "allowed": True,
            "exploited": False,
            "verified": False,
            "reason": "No selected exploit candidate to execute.",
            "results": [],
        }
    results = []
    for selected in selected_candidates:
        results.append(run_one_selected_capability(target, selected, use_sudo=use_sudo, execution_mode=execution_mode))
    verified_results = [item for item in results if item.get("verified")]
    return {
        "allowed": True,
        "exploited": any(item.get("exploited") for item in results),
        "verified": bool(verified_results),
        "status_counts": status_counts(results),
        "proof_output": "\n".join(
            f"{item.get('selected_exploit_id')}: {item.get('proof_output')}"
            for item in verified_results
            if item.get("proof_output")
        ).strip(),
        "cleanup_verified": all(item.get("cleanup_verified", True) for item in results),
        "results": results,
        "attempted": len(results),
        "successful": len(verified_results),
        "execution_mode": execution_mode,
    }


def run_one_selected_capability(
    target: str,
    selected: dict,
    use_sudo: bool = False,
    execution_mode: str = "safe",
) -> dict:
    exploit_id = selected.get("id")
    runner = selected.get("runner")
    if runner != "generated_python_tool":
        result = {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": f"Runner '{runner}' is metadata-only until a generated Python tool is cached for it.",
        }
    elif not generated_tool_allowed_in_mode(selected, execution_mode):
        result = {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": f"Generated tool is not allowed in execution mode {execution_mode}.",
        }
    else:
        result = execute_generated_tool(
            validate_target(target),
            selected,
            {
                "execution_mode": execution_mode,
                "matched_service": selected.get("matched_service") or {},
            },
        )
    result["selected_exploit_id"] = exploit_id
    result["selected_exploit_name"] = selected.get("name")
    result["selection_score"] = selected.get("score")
    result["selection_reasons"] = selected.get("reasons", [])
    result["score_explanation"] = selected.get("score_explanation") or "; ".join(selected.get("reasons", []))
    result["provider"] = selected.get("provider")
    result["runner"] = selected.get("runner")
    result["status"] = normalize_validation_status(result, selected)
    return result


def generated_tool_allowed_in_mode(capability: dict[str, Any], execution_mode: str) -> bool:
    allowed_modes = capability.get("allowed_execution_modes") or ["safe"]
    return execution_mode in allowed_modes


def status_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def normalize_validation_status(result: dict[str, Any], capability: dict[str, Any] | None = None) -> str:
    if not result.get("allowed", True):
        return "blocked_by_safety_policy"
    if result.get("tool_error") or (result.get("stderr") and not result.get("reason") and not result.get("verified")):
        return "tool_error"
    if result.get("exploited"):
        return "confirmed_vulnerability"
    if result.get("verified"):
        return "confirmed_exposure"
    if result.get("reason"):
        return "ran_no_finding"
    return "not_applicable"


def parse_open_services(scan_output: str) -> list[dict[str, str]]:
    services = []
    for line in scan_output.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", line.strip())
        if match:
            services.append(
                {
                    "port": match.group(1),
                    "protocol": match.group(2),
                    "service": match.group(3),
                    "version": match.group(4).strip(),
                }
            )
    return services


def summarize_tool_result(result: ToolResult, max_chars: int = 3000) -> str:
    return json.dumps(
        {
            "tool": result.tool,
            "command": result.command,
            "returncode": result.returncode,
            "stdout": result.stdout[:max_chars],
            "stderr": result.stderr[:max_chars],
            "elapsed_seconds": round(result.elapsed_seconds, 3),
        },
        indent=2,
    )
