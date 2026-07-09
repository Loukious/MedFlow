from __future__ import annotations

import json
from typing import Any

from medflow_compare.shared_tools import call_redteam_llm
from medflow_ti.config import load_settings


VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_STATUSES = {"suspected", "confirmed_exposure", "confirmed_vulnerability"}


def assess_web_observations(observations: list[dict[str, Any]], provider: str) -> list[dict[str, str]]:
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

Return at most 3 prioritized findings. Keep each evidence and proof field below 120 characters.
Return strict JSON only:
{{"findings":[{{"url":"observed URL", "type":"short snake_case name", "severity":"info|low|medium|high|critical", "confidence":"low|medium|high", "evidence":"fact-based explanation", "proof":"specific observed fact", "cwe":"optional CWE", "owasp":"optional OWASP", "status":"suspected|confirmed_exposure|confirmed_vulnerability"}}]}}
Return an empty findings list when the observations do not support a security finding.
"""
    try:
        raw = call_redteam_llm(prompt, settings=load_settings(), provider=provider)
        payload = parse_json_object(raw)
    except (RuntimeError, ValueError, json.JSONDecodeError):
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
