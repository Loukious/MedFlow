from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .capabilities import select_capabilities_for_services
from .config_loader import load_lab_config
from .generated_tools import DATA_TOOL_DIR, execute_generated_tool
from .metasploit_runner import run_metasploit_module


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


def tcp_connect_check(target: str, ports: list[int] | None = None, timeout: float = 1.0) -> dict:
    target = validate_target(target)
    selected_ports = ports or default_ports_for_target(target)
    output: dict[str, dict[str, Any]] = {}
    for port in selected_ports:
        started = time.perf_counter()
        try:
            with socket.create_connection((target, int(port)), timeout=timeout):
                output[str(port)] = {"open": True, "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}
        except OSError as exc:
            output[str(port)] = {"open": False, "error": str(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}
    return output


def service_scan(target: str, ports: list[int] | None = None, profile: str | None = None) -> ToolResult:
    target = validate_target(target)
    selected_ports = ports or default_ports_for_target(target)
    command = ["nmap", "-sV", "-Pn", "--version-light", "--reason", "-p", ",".join(str(port) for port in selected_ports), target]
    started = time.perf_counter()
    proc = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
    return ToolResult("nmap", command, proc.returncode, proc.stdout, proc.stderr, time.perf_counter() - started)


def safe_script_scan(target: str, ports: list[int] | None = None, profile: str | None = None) -> ToolResult:
    target = validate_target(target)
    selected_ports = ports or default_ports_for_target(target)
    command = ["nmap", "-sC", "-Pn", "--script", "default,safe", "-p", ",".join(str(port) for port in selected_ports), target]
    started = time.perf_counter()
    proc = subprocess.run(command, text=True, capture_output=True, timeout=180, check=False)
    return ToolResult("nmap", command, proc.returncode, proc.stdout, proc.stderr, time.perf_counter() - started)


def http_probe(target: str, ports: list[int] | None = None) -> dict:
    target = validate_target(target)
    selected_ports = ports or default_http_ports_for_target(target)
    return {"http_probe": [request_summary(url_for(target, port)) for port in selected_ports]}


def web_fingerprint(target: str, ports: list[int] | None = None) -> dict:
    target = validate_target(target)
    selected_ports = ports or [80, 443, 8080, 8000, 5000, 8443]
    fingerprints = []
    for port in selected_ports:
        result = request_summary(url_for(target, port), include_body=True)
        body = str(result.pop("body", ""))
        headers = result.pop("headers", {})
        if "error" in result and not body:
            result["technology_signals"] = technology_signals(str(result.get("error", "")))
        else:
            result.update(
                {
                    "server": headers.get("server", ""),
                    "powered_by": headers.get("x-powered-by", ""),
                    "set_cookie_present": bool(headers.get("set-cookie")),
                    "security_headers": {
                        "content_security_policy": bool(headers.get("content-security-policy")),
                        "strict_transport_security": bool(headers.get("strict-transport-security")),
                        "x_frame_options": bool(headers.get("x-frame-options")),
                        "x_content_type_options": bool(headers.get("x-content-type-options")),
                    },
                    "technology_signals": technology_signals(" ".join([json.dumps(headers), body[:4000]])),
                }
            )
        fingerprints.append(result)
    return {"web_fingerprints": fingerprints}


def web_route_discovery(target: str, ports: list[int] | None = None, paths: list[str] | None = None) -> dict:
    target = validate_target(target)
    selected_ports = ports or [80, 443, 8080, 8000, 5000, 8443]
    selected_paths = paths or ["/", "/login", "/admin", "/api", "/robots.txt", "/functionRouter", "/index.action", "/showcase.action"]
    routes = []
    for port in selected_ports:
        for path in selected_paths:
            normalized = path if str(path).startswith("/") else f"/{path}"
            result = request_summary(f"{url_for(target, port)}{normalized.lstrip('/')}", include_body=True)
            body = str(result.pop("body", ""))
            headers = result.pop("headers", {})
            title = title_from_html(body)
            result.update(
                {
                    "content_type": headers.get("content-type", ""),
                    "content_length": headers.get("content-length", ""),
                    "title": title,
                    "links": links_from_html(body)[:20],
                    "technology_signals": route_technology_signals(result.get("url", ""), title, body, result.get("status")),
                    "artifact_signal": artifact_signal(result.get("url", ""), headers.get("content-type", ""), body.encode(errors="replace")),
                }
            )
            routes.append(result)
    return {"web_routes": routes}


def url_for(target: str, port: int) -> str:
    scheme = "https" if int(port) in {443, 8443} else "http"
    return f"{scheme}://{target}:{int(port)}/"


def request_summary(url: str, *, include_body: bool = False) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        request = Request(url, headers={"User-Agent": "MedFlow-RedTeam/0.1"})
        with urlopen(request, timeout=4) as response:
            body = response.read(8192).decode("utf-8", errors="replace")
            headers = {key.lower(): value for key, value in response.headers.items()}
            result: dict[str, Any] = {"url": url, "status": response.status, "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}
            if include_body:
                result["body"] = body
                result["headers"] = headers
            return result
    except HTTPError as exc:
        body = exc.read(8192).decode("utf-8", errors="replace")
        headers = {key.lower(): value for key, value in exc.headers.items()}
        result = {"url": url, "status": exc.code, "http_error": True, "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}
        if include_body:
            result["body"] = body
            result["headers"] = headers
        return result
    except Exception as exc:
        return {"url": url, "error": str(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}


def technology_signals(text: str) -> list[str]:
    lowered = text.lower()
    checks = {
        "activemq": "activemq",
        "bootstrap": "bootstrap",
        "couchdb": "couchdb",
        "django": "django",
        "express": "express",
        "flask": "flask",
        "functionrouter": "functionrouter",
        "gunicorn": "gunicorn",
        "jquery": "jquery",
        "openwire": "openwire",
        "php": "php",
        "rocketmq": "rocketmq",
        "shiro": "rememberme=deleteme",
        "spring": "spring",
        "thinkphp": "thinkphp",
        "wordpress": "wp-content",
    }
    return sorted({name for name, marker in checks.items() if marker in lowered})


def route_technology_signals(url: str, title: str, body: str, status: int | None) -> list[str]:
    text = " ".join([title, body[:2000]]).lower()
    signals = set(technology_signals(text))
    lowered_url = url.lower()
    if "struts" in text or re.search(r"\bs2-\d{3}\b", text) or (status in {200, 500} and ".action" in lowered_url):
        signals.update({"struts", "ognl"})
    if "whitelabel error page" in text or (status in {200, 500} and "functionrouter" in lowered_url):
        signals.update({"spring", "spring cloud", "functionrouter"})
    return sorted(signals)


def title_from_html(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def links_from_html(body: str) -> list[str]:
    return sorted(set(re.findall(r"<a[^>]+href=[\"']([^\"']+)[\"']", body, flags=re.IGNORECASE)))


def artifact_signal(url: str, content_type: str, body: bytes) -> str:
    lowered_url = url.lower()
    lowered_type = content_type.lower()
    if "download" in lowered_url and ("octet-stream" in lowered_type or not lowered_type.startswith("text/html")):
        return "downloadable artifact"
    if any(term in lowered_url for term in ["backup", "config", "dump", "capture"]):
        return "sensitive path keyword"
    if any(body.startswith(magic) for magic in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"]):
        return "possible packet capture exposure"
    return ""


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
    metasploit_action: str = "check",
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
        results.append(
            run_one_selected_capability(
                target,
                selected,
                use_sudo=use_sudo,
                execution_mode=execution_mode,
                metasploit_action=metasploit_action,
            )
        )
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
        "metasploit_action": metasploit_action,
    }


def run_one_selected_capability(
    target: str,
    selected: dict,
    use_sudo: bool = False,
    execution_mode: str = "safe",
    metasploit_action: str = "check",
) -> dict:
    exploit_id = selected.get("id")
    runner = selected.get("runner")
    if runner == "metasploit_module":
        result = run_metasploit_module(
            validate_target(target),
            selected,
            execution_mode=execution_mode,
            action=metasploit_action,
        )
    elif runner != "generated_python_tool":
        result = {
            "allowed": True,
            "exploited": False,
            "verified": False,
            "metadata_only": True,
            "reason": f"Runner '{runner}' is metadata-only until an executable adapter or generated Python tool is cached for it.",
        }
    elif not generated_tool_allowed_in_mode(selected, execution_mode):
        result = {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": f"Generated tool is not allowed in execution mode {execution_mode}.",
        }
    elif not generated_tool_from_data_cache(selected):
        result = {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Generated tool execution is limited to on-demand tools stored under data/generated_tools.",
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


def generated_tool_from_data_cache(capability: dict[str, Any]) -> bool:
    source = str(capability.get("source") or "")
    code_path = str(capability.get("code_path") or "")
    return str(DATA_TOOL_DIR) in source or source.endswith("data/generated_tools/tool_specs.json") or code_path.startswith("code/")


def status_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def normalize_validation_status(result: dict[str, Any], capability: dict[str, Any] | None = None) -> str:
    if not result.get("allowed", True):
        return "blocked_by_safety_policy"
    if result.get("metadata_only"):
        return "metadata_only"
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
