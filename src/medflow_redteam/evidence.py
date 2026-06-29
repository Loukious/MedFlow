from __future__ import annotations

from typing import Any


def severity_for_status(status: str) -> str:
    return {
        "confirmed_vulnerability": "high",
        "confirmed_exposure": "medium",
        "ran_no_finding": "informational",
        "blocked_by_safety_policy": "informational",
        "tool_error": "informational",
        "not_applicable": "informational",
    }.get(status, "informational")


def normalize_validation_evidence(validation: dict[str, Any] | None) -> list[dict[str, Any]]:
    evidence = []
    for item in (validation or {}).get("results", []):
        status = item.get("status") or ("confirmed_exposure" if item.get("verified") else "ran_no_finding")
        evidence.append(
            {
                "type": "capability_validation",
                "title": item.get("selected_exploit_name") or item.get("selected_exploit_id") or "Capability validation",
                "asset": f"{item.get('target', '')}:{item.get('port', '')}".strip(":"),
                "status": status,
                "severity": severity_for_status(status),
                "confidence": "high" if item.get("verified") else "medium",
                "proof_kind": "tool_output" if item.get("proof_output") else "tool_reason",
                "safe_summary": (item.get("proof_output") or item.get("reason") or "")[:900],
                "remediation": remediation_for_status(status),
                "references": [ref for ref in [item.get("selected_exploit_id")] if ref],
            }
        )
    return evidence


def normalize_web_evidence(web_checks: dict[str, Any] | None) -> list[dict[str, Any]]:
    evidence = []
    for finding in (web_checks or {}).get("findings", []):
        evidence.append(
            {
                "type": "web_control_check",
                "title": finding.get("title") or finding.get("check") or "Web control check",
                "asset": finding.get("url", ""),
                "status": finding.get("status", "confirmed_exposure"),
                "severity": finding.get("severity", "low"),
                "confidence": finding.get("confidence", "medium"),
                "proof_kind": "http_observation",
                "safe_summary": finding.get("evidence", "")[:900],
                "remediation": finding.get("remediation", ""),
                "references": finding.get("references", []),
            }
        )
    return evidence


def remediation_for_status(status: str) -> str:
    if status == "confirmed_vulnerability":
        return "Validate affected version/configuration, patch or disable the vulnerable component, and add detection coverage."
    if status == "confirmed_exposure":
        return "Restrict exposure, require authentication where appropriate, and monitor access to the affected asset."
    if status == "ran_no_finding":
        return "No immediate remediation from this check; keep evidence as negative validation context."
    if status == "blocked_by_safety_policy":
        return "Use a human-approved manual validation path if this check is required."
    if status == "tool_error":
        return "Fix local tool installation or command options, then rerun validation."
    return "Review context and decide whether follow-up validation is needed."


def render_findings_table(evidence: list[dict[str, Any]]) -> str:
    if not evidence:
        return "No normalized findings were produced."
    lines = ["| Severity | Status | Asset | Finding |", "| --- | --- | --- | --- |"]
    for item in evidence:
        lines.append(
            f"| {item.get('severity', '')} | {item.get('status', '')} | "
            f"{item.get('asset', '')} | {item.get('title', '')} |"
        )
    return "\n".join(lines)
