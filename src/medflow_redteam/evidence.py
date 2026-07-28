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


def normalize_web_assessment_evidence(web_assessment: dict[str, Any] | None) -> list[dict[str, Any]]:
    evidence = []
    for finding in (web_assessment or {}).get("findings", []):
        status = finding.get("status", "suspected")
        evidence.append(
            {
                "type": "web_app_assessment",
                "title": finding.get("type", "Web application finding"),
                "asset": finding.get("url", ""),
                "status": status,
                "severity": finding.get("severity", "informational"),
                "confidence": finding.get("confidence", "low"),
                "proof_kind": "safe_probe",
                "safe_summary": (finding.get("proof") or finding.get("evidence") or "")[:900],
                "remediation": remediation_for_web_finding(finding),
                "references": [item for item in [finding.get("cwe"), finding.get("owasp")] if item],
            }
        )
    return evidence


def normalize_authorization_evidence(
    authorization_assessment: dict[str, Any] | None,
    *,
    target_url: str | None,
) -> list[dict[str, Any]]:
    assessment = authorization_assessment or {}
    evidence = []
    for finding in assessment.get("findings", []):
        classifications = finding.get("classification") or []
        references = []
        for item in classifications:
            if not isinstance(item, dict):
                continue
            references.extend(
                value
                for value in [item.get("cwe"), item.get("owasp")]
                if value
            )
        evidence.append(
            {
                "type": "authorization_assessment",
                "title": finding.get("title") or "Authorization control failure",
                "asset": target_url or "",
                "status": "confirmed_vulnerability",
                "severity": finding.get("severity", "high"),
                "confidence": "high",
                "proof_kind": "bounded_http_differential",
                "safe_summary": (
                    f"Evidence actions: {', '.join(finding.get('evidence_action_ids') or [])}"
                )[:900],
                "remediation": " ".join(finding.get("remediation") or [])[:1_200],
                "references": list(dict.fromkeys(references)),
            }
        )
    return evidence


def normalize_wordlist_attack_evidence(
    result: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    evidence = []
    for success in (result or {}).get("successes", []):
        evidence.append(
            {
                "type": "password_wordlist_attack",
                "title": "Password from common wordlist accepted",
                "asset": (result or {}).get("endpoint", ""),
                "status": "confirmed_vulnerability",
                "severity": "high",
                "confidence": "high",
                "proof_kind": "bounded_authentication_attempt",
                "safe_summary": (
                    f"Identity {success.get('username')} authenticated using password "
                    f"wordlist position {success.get('password_index')}. "
                    f"{credential_retention_summary(success)}"
                ),
                "remediation": (
                    "Reset the affected lab credential, block common passwords, enforce MFA, "
                    "and detect repeated failures concentrated on one identity."
                ),
                "references": ["CWE-521", "MITRE ATT&CK T1110.001"],
            }
        )
    return evidence


def normalize_password_spray_evidence(
    result: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    evidence = []
    for success in (result or {}).get("successes", []):
        evidence.append(
            {
                "type": "password_spray",
                "title": "Common credential accepted by authentication endpoint",
                "asset": (result or {}).get("endpoint", ""),
                "status": "confirmed_vulnerability",
                "severity": "high",
                "confidence": "high",
                "proof_kind": "bounded_authentication_attempt",
                "safe_summary": (
                    f"Identity {success.get('username')} authenticated using password "
                    f"wordlist position {success.get('password_index')}. "
                    f"{credential_retention_summary(success)}"
                ),
                "remediation": (
                    "Reset the affected lab credential, enforce resistant password policy "
                    "and MFA, and monitor distributed low-rate authentication failures."
                ),
                "references": ["CWE-521", "MITRE ATT&CK T1110.003"],
            }
        )
    return evidence


def credential_retention_summary(success: dict[str, Any]) -> str:
    if "password" in success:
        return (
            "The accepted password was retained only in the owner-restricted "
            "campaign artifacts because explicit lab reporting was enabled; no "
            "session token was retained."
        )
    return "No password or session token was retained."


def remediation_for_web_finding(finding: dict[str, Any]) -> str:
    finding_type = str(finding.get("type", "")).lower()
    if "sqli" in finding_type:
        return "Use parameterized queries, validate server-side inputs, and review database error handling."
    if "xss" in finding_type:
        return "Apply context-aware output encoding, input validation, and content security controls."
    if "idor" in finding_type:
        return "Enforce object-level authorization checks and test with separate user contexts."
    return "Review the route and parameter evidence, then perform an authorized follow-up validation."


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
