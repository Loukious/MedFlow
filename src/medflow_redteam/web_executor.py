from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .web_browser import validate_dom_xss


MAX_PROBES = 4
MAX_PAYLOAD_CHARS = 180
MAX_RESPONSE_BYTES = 32768
ALLOWED_METHODS = {"GET", "POST"}
XSS_SENTINEL = "MEDFLOW_DOM_XSS"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def execute_planned_probes(plan: list[dict[str, Any]], observations: list[dict[str, Any]], auth_headers: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Execute a small, bounded set of planner-approved same-origin probes."""
    known_urls = {str(item.get("url")) for item in observations}
    results: list[dict[str, Any]] = []
    for probe in plan[:MAX_PROBES]:
        validated = validate_probe(probe, known_urls)
        if not validated:
            results.append({"status": "rejected", "reason": "Planner output exceeded the bounded executor policy."})
            continue
        baseline = request_observation(validated["url"], "GET", None, auth_headers)
        mutated_url, data = materialize_probe(validated)
        tested = request_observation(mutated_url, validated["method"], data, auth_headers)
        result = {
            "kind": validated["kind"],
            "url": validated["url"],
            "method": validated["method"],
            "parameter": validated["parameter"],
            "payload_label": "planner_selected_redacted",
            "baseline": baseline,
            "probe": tested,
            "status": "completed" if tested.get("ok") else "request_error",
        }
        if validated["kind"] == "xss_dom" and validated["method"] == "GET" and XSS_SENTINEL in validated["payload"]:
            result["browser"] = validate_dom_xss(mutated_url, XSS_SENTINEL)
        results.append(result)
        time.sleep(0.25)
    return results


def validate_probe(probe: dict[str, Any], known_urls: set[str]) -> dict[str, Any] | None:
    if not isinstance(probe, dict):
        return None
    kind = str(probe.get("kind") or "")
    url = str(probe.get("url") or "")
    method = str(probe.get("method") or "GET").upper()
    parameter = str(probe.get("parameter") or "")
    payload = str(probe.get("payload") or "")
    if kind not in {"sqli", "xss_dom"} or url not in known_urls or method not in ALLOWED_METHODS or not parameter:
        return None
    if not payload or len(payload) > MAX_PAYLOAD_CHARS or any(ord(char) < 32 and char not in "\t" for char in payload):
        return None
    if kind == "sqli":
        lowered = payload.lower()
        forbidden = ("union", "--", "/*", "*/", ";", " sleep", "benchmark", "waitfor", " or ", " and ")
        if any(token in lowered for token in forbidden):
            return None
    if kind == "xss_dom":
        lowered = payload.lower()
        forbidden = ("fetch(", "xmlhttprequest", "sendbeacon", "document.cookie", "localstorage", "sessionstorage", "window.open", "location=")
        if XSS_SENTINEL not in payload or "document.title" not in payload or any(token in lowered for token in forbidden):
            return None
    body = probe.get("body") if isinstance(probe.get("body"), dict) else {}
    if method == "POST" and (len(body) > 12 or any(len(str(key)) > 80 or len(str(value)) > 180 for key, value in body.items())):
        return None
    return {"kind": kind, "url": url, "method": method, "parameter": parameter, "payload": payload, "body": body}


def materialize_probe(probe: dict[str, Any]) -> tuple[str, bytes | None]:
    if probe["method"] == "GET":
        parsed = urlparse(probe["url"])
        values = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        mutated = []
        for key, value in values:
            if key == probe["parameter"]:
                mutated.append((key, probe["payload"]))
                replaced = True
            else:
                mutated.append((key, value))
        if not replaced:
            mutated.append((probe["parameter"], probe["payload"]))
        return urlunparse(parsed._replace(query=urlencode(mutated))), None
    body = {str(key): str(value) for key, value in probe["body"].items()}
    body[probe["parameter"]] = probe["payload"]
    return probe["url"], json.dumps(body).encode("utf-8")


def request_observation(url: str, method: str, data: bytes | None, auth_headers: dict[str, str] | None) -> dict[str, Any]:
    headers = {"User-Agent": "MedFlow-WebExecutor/0.1", **(auth_headers or {})}
    if data is not None:
        headers["Content-Type"] = "application/json"
    started = time.monotonic()
    try:
        request = Request(url, data=data, headers=headers, method=method)
        opener = build_opener(NoRedirect())
        with opener.open(request, timeout=6) as response:
            body = response.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
            return {
                "ok": True,
                "status": response.status,
                "content_type": response.headers.get("content-type", "")[:100],
                "bytes": len(body),
                "body_hash": hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16],
                "excerpt": redact_excerpt(body),
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
            }
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:220], "elapsed_ms": round((time.monotonic() - started) * 1000, 2)}


def redact_excerpt(body: str) -> str:
    compact = re.sub(r"\s+", " ", body)
    compact = re.sub(r"[\w.+-]+@[\w.-]+", "<redacted-email>", compact)
    compact = re.sub(r"(?i)(password|token|secret)\s*[:=]\s*[^,\s<>{}\"]+", r"\1=<redacted>", compact)
    return compact[:700]
