from __future__ import annotations

import json
from typing import Any

from medflow_compare.shared_tools import call_redteam_llm
from medflow_ti.config import load_settings


VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_STATUSES = {"suspected", "confirmed_exposure", "confirmed_vulnerability"}


def assess_web_observations(
    observations: list[dict[str, Any]], provider: str, probe_results: list[dict[str, Any]] | None = None
) -> list[dict[str, str]]:
    """Ask the selected LLM to classify neutral, redacted web observations."""
    prompt = f"""
You are the Web Evidence Analyst for an authorized web-security assessment.

Classify only evidence supported by the supplied observations. Do not infer vulnerabilities
from a product name, do not propose payloads, and do not include any returned data values.
An HTTP 200 alone is not a finding. You may identify exposed artifacts, directory indexes,
unauthenticated sensitive data fields, misconfigurations, or input-validation signals where
the facts justify it. Use `confirmed_exposure` only for directly observed exposure; reserve
`confirmed_vulnerability` for a demonstrated exploit outcome.

Observations (all response values are omitted; JSON field names only):
{json.dumps(observations[:100], indent=2)}

Bounded active probe results (response excerpts are redacted):
{json.dumps((probe_results or [])[:4], indent=2)}

Return at most 3 prioritized findings. Keep each evidence and proof field below 120 characters.
Return strict JSON only:
{{"findings":[{{"url":"observed URL", "type":"short snake_case name", "severity":"info|low|medium|high|critical", "confidence":"low|medium|high", "evidence":"fact-based explanation", "proof":"specific observed fact", "cwe":"optional CWE", "owasp":"optional OWASP", "status":"suspected|confirmed_exposure|confirmed_vulnerability"}}]}}
Return an empty findings list when the observations do not support a security finding.
"""
    try:
        raw = call_redteam_llm(prompt, settings=load_settings(), provider=provider)
        payload = parse_json_object(raw)
    except Exception:
        return []
    known_urls = {str(item.get("url")) for item in observations}
    findings: list[dict[str, str]] = []
    for item in payload.get("findings", [])[:3]:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        if url not in known_urls:
            continue
        severity = str(item.get("severity") or "info").lower()
        status = str(item.get("status") or "suspected").lower()
        if severity not in VALID_SEVERITIES or status not in VALID_STATUSES:
            continue
        finding_type = str(item.get("type") or "").strip().lower()
        if not finding_type:
            continue
        findings.append(
            {
                "url": url,
                "type": finding_type[:80],
                "severity": severity,
                "confidence": str(item.get("confidence") or "medium").lower()[:16],
                "evidence": str(item.get("evidence") or "")[:900],
                "proof": str(item.get("proof") or "")[:900],
                "cwe": str(item.get("cwe") or "")[:40],
                "owasp": str(item.get("owasp") or "")[:80],
                "status": status,
            }
        )
    return findings


def plan_web_probes(context: dict[str, Any], provider: str) -> list[dict[str, Any]]:
    """Let the LLM choose a small set of harmless active web checks from observed facts."""
    prompt = f"""
You are the Web Test Planner for an authorized, allowlisted laboratory assessment.

Choose at most 3 high-value, harmless validation probes from the observed routes, rendered DOM
controls, and same-origin browser requests below. Do not guess a host or route. Do not attempt
credential theft, data extraction, file writes, uploads, account changes, or destructive actions.

For SQL injection, choose a bounded syntax/differential probe only. The payload must not contain
UNION, OR, AND, comments, semicolons, delay functions, or data-extraction expressions. For DOM XSS, choose only a
GET request and a harmless payload that changes document.title to include the exact token
`MEDFLOW_DOM_XSS`; do not use network APIs, storage APIs, cookies, redirects, or popups.

Observed context:
{json.dumps(context, indent=2)}

Return strict JSON only:
{{"probes":[{{"kind":"sqli|xss_dom", "url":"an observed URL", "method":"GET|POST", "parameter":"observed or rendered input name", "payload":"bounded harmless payload", "body":{{"optional":"JSON fields for POST"}}, "rationale":"brief fact-based reason"}}]}}
Return an empty probes list when no safe evidence-based test is appropriate.
"""
    try:
        raw = call_redteam_llm(prompt, settings=load_settings(), provider=provider)
        payload = parse_json_payload(raw)
    except Exception:
        return []
    routes = {str(item.get("url")) for item in context.get("routes", [])}
    probes: list[dict[str, Any]] = []
    raw_probes = payload if isinstance(payload, list) else payload.get("probes", [])
    for item in raw_probes[:3]:
        if not isinstance(item, dict) or str(item.get("url") or "") not in routes:
            continue
        probes.append(
            {
                "kind": str(item.get("kind") or ""),
                "url": str(item.get("url") or ""),
                "method": str(item.get("method") or "GET").upper(),
                "parameter": str(item.get("parameter") or ""),
                "payload": str(item.get("payload") or ""),
                "body": item.get("body") if isinstance(item.get("body"), dict) else {},
                "rationale": str(item.get("rationale") or "")[:220],
            }
        )
    return probes


def parse_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`").removeprefix("json").strip()
    start, end = stripped.find("{"), stripped.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("Web Evidence Analyst did not return a JSON object.")
    payload = json.loads(stripped[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("Web Evidence Analyst returned an invalid JSON payload.")
    return payload


def parse_json_payload(text: str) -> dict[str, Any] | list[Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`").removeprefix("json").strip()
    starts = [index for index in (stripped.find("{"), stripped.find("[")) if index >= 0]
    if not starts:
        raise ValueError("Web planner did not return JSON.")
    start = min(starts)
    end = max(stripped.rfind("}"), stripped.rfind("]"))
    if end <= start:
        raise ValueError("Web planner returned incomplete JSON.")
    payload = json.loads(stripped[start : end + 1])
    if not isinstance(payload, (dict, list)):
        raise ValueError("Web planner returned an invalid JSON payload.")
    return payload
