from __future__ import annotations

import json
import re
from html import escape
from pathlib import Path
from typing import Any

from .credential_reporting import collect_revealed_credentials


CONFIRMED_STATUSES = {
    "confirmed_credential",
    "confirmed_exposure",
    "confirmed_vulnerability",
}
SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}
EMPTY_STATUSES = {
    "",
    "not_applicable",
    "not_enabled",
    "not_requested",
    "not_run",
    "not_selected",
}


def render_campaign_markdown(
    payload: dict[str, Any],
    *,
    artifact_paths: dict[str, str] | None = None,
) -> str:
    findings = dict_items(payload.get("normalized_evidence"))
    confirmed = [
        item
        for item in findings
        if normalized_status(item.get("status")) in CONFIRMED_STATUSES
    ]
    target = (
        payload.get("target_url")
        or payload.get("target")
        or "Tabletop campaign (no live target)"
    )
    lines = [
        "# MedFlow Red-Team Campaign Report",
        "",
        f"> **Outcome:** {campaign_outcome(payload, confirmed)}",
        "",
        "| Campaign | Value |",
        "| --- | --- |",
        table_row("Target", code(target)),
        table_row("Provider", code(payload.get("provider") or "not recorded")),
        table_row("Elapsed", format_duration(payload.get("elapsed_seconds"))),
        table_row(
            "Execution",
            "Failed" if payload.get("error") else "Completed",
        ),
        "",
        "## Objective",
        "",
        clean_text(payload.get("goal") or "No campaign objective was recorded.", 2_000),
        "",
    ]

    if payload.get("error"):
        lines.extend(
            [
                "## Execution Error",
                "",
                clean_text(payload["error"], 2_000),
                "",
            ]
        )

    append_executive_summary(lines, payload, findings, confirmed)
    append_findings(lines, findings)
    append_authorization(lines, payload.get("authorization_assessment"))
    append_authentication_discovery(
        lines,
        payload.get("authentication_discovery"),
    )
    append_identity_validation(
        lines,
        payload.get("wordlist_attack"),
        payload.get("password_spray"),
    )
    append_capability_validation(
        lines,
        payload.get("capability_validation"),
        payload.get("loop_summary"),
    )
    append_attack_surface(lines, payload)
    append_model_strategy(
        lines,
        payload.get("recon_strategy"),
        payload.get("validation_strategy"),
    )
    append_campaign_phases(lines, payload.get("phases"))
    append_routing_and_agents(
        lines,
        payload.get("campaign_routing"),
        payload.get("agents"),
    )
    append_execution_timeline(lines, payload.get("tool_timeline"))
    append_knowledge_context(
        lines,
        payload.get("graph_memory"),
        payload.get("sources"),
    )
    append_safety_review(lines, payload.get("safety_review"))
    append_artifacts(lines, payload, artifact_paths or {})

    return "\n".join(lines).rstrip() + "\n"


def append_executive_summary(
    lines: list[str],
    payload: dict[str, Any],
    findings: list[dict[str, Any]],
    confirmed: list[dict[str, Any]],
) -> None:
    negative = len(findings) - len(confirmed)
    highest = highest_severity(confirmed)
    services = dict_items(payload.get("services"))
    phases = dict_items(payload.get("phases"))
    authorization = as_dict(payload.get("authorization_assessment"))
    wordlist = as_dict(payload.get("wordlist_attack"))
    spray = as_dict(payload.get("password_spray"))
    validation = as_dict(payload.get("capability_validation"))
    web_assessment = as_dict(payload.get("web_assessment"))

    lines.extend(
        [
            "## Executive Summary",
            "",
            (
                f"The campaign produced **{counted(len(confirmed), 'confirmed result')}** "
                f"from {counted(len(findings), 'normalized evidence record')}."
            ),
            "",
            "| Measure | Result |",
            "| --- | --- |",
            table_row("Highest confirmed severity", title(highest or "none")),
            table_row("Confirmed results", len(confirmed)),
            table_row("Negative or informational results", negative),
            table_row("Services observed", len(services)),
            table_row("Campaign phases", len(phases)),
        ]
    )

    if authorization and normalized_status(
        authorization.get("status")
    ) not in EMPTY_STATUSES:
        tests = dict_items(authorization.get("tests"))
        counts = authorization_test_counts(tests)
        lines.append(
            table_row(
                "Authorization assessment",
                (
                    f"{title(authorization.get('overall_security_posture') or 'unknown')} "
                    f"({counts['failed']} failed, {counts['passed']} passed, "
                    f"{counts['inconclusive']} inconclusive)"
                ),
            )
        )
    if active_result(wordlist):
        lines.append(
            table_row(
                "Password wordlist",
                credential_result_summary(wordlist),
            )
        )
    if active_result(spray):
        lines.append(
            table_row(
                "Password spray",
                credential_result_summary(spray),
            )
        )
    if active_result(validation):
        lines.append(
            table_row(
                "Capability validation",
                (
                    f"{integer(validation.get('successful'))}/"
                    f"{integer(validation.get('attempted'))} positive"
                ),
            )
        )
    if web_assessment:
        lines.append(
            table_row(
                "Web application assessment",
                (
                    f"{len(dict_items(web_assessment.get('routes')))} routes, "
                    f"{len(dict_items(web_assessment.get('findings')))} findings"
                ),
            )
        )
    lines.append("")


def append_findings(
    lines: list[str],
    findings: list[dict[str, Any]],
) -> None:
    lines.extend(["## Findings", ""])
    if not findings:
        lines.extend(
            [
                "No normalized findings were produced. This means only that the "
                "executed checks did not create a normalized evidence record.",
                "",
            ]
        )
        return

    ordered = sorted(
        enumerate(findings, start=1),
        key=lambda pair: (
            SEVERITY_ORDER.get(
                normalized_status(pair[1].get("severity")),
                0,
            ),
            normalized_status(pair[1].get("status"))
            in CONFIRMED_STATUSES,
        ),
        reverse=True,
    )
    lines.extend(
        [
            "| ID | Severity | Status | Finding | Asset | Confidence |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for original_index, finding in ordered:
        lines.append(
            table_row(
                f"F{original_index}",
                title(finding.get("severity") or "informational"),
                title(finding.get("status") or "unknown"),
                clean_text(finding.get("title") or "Untitled finding", 180),
                clean_text(finding.get("asset") or "not recorded", 180),
                title(finding.get("confidence") or "not recorded"),
            )
        )
    lines.append("")

    for original_index, finding in ordered:
        if normalized_status(finding.get("status")) not in CONFIRMED_STATUSES:
            continue
        lines.extend(
            [
                f"### F{original_index}: "
                f"{clean_heading(finding.get('title') or 'Confirmed finding')}",
                "",
                f"- **Asset:** {code(finding.get('asset') or 'not recorded')}",
                f"- **Severity:** {title(finding.get('severity') or 'informational')}",
                f"- **Confidence:** {title(finding.get('confidence') or 'not recorded')}",
                f"- **Evidence type:** {title(finding.get('proof_kind') or 'not recorded')}",
            ]
        )
        summary = summarize_value(finding.get("safe_summary"), 800)
        remediation = clean_text(finding.get("remediation"), 1_200)
        references = string_items(finding.get("references"))
        if summary:
            lines.extend(["", "**Evidence**", "", summary])
        if remediation:
            lines.extend(["", "**Remediation**", "", remediation])
        if references:
            lines.extend(
                [
                    "",
                    "**References:** "
                    + ", ".join(code(reference) for reference in references),
                ]
            )
        lines.append("")

    negative = [
        (index, finding)
        for index, finding in ordered
        if normalized_status(finding.get("status")) not in CONFIRMED_STATUSES
    ]
    if negative:
        lines.extend(
            [
                "### Negative And Informational Checks",
                "",
                "| ID | Check | Result | Evidence |",
                "| --- | --- | --- | --- |",
            ]
        )
        for original_index, finding in negative:
            lines.append(
                table_row(
                    f"F{original_index}",
                    clean_text(finding.get("title") or "Validation check", 180),
                    title(finding.get("status") or "unknown"),
                    clean_text(finding.get("safe_summary") or "", 300),
                )
            )
        lines.append("")


def append_authorization(
    lines: list[str],
    raw_assessment: Any,
) -> None:
    assessment = as_dict(raw_assessment)
    status = normalized_status(assessment.get("status"))
    if not assessment or status in EMPTY_STATUSES:
        return

    tests = dict_items(assessment.get("tests"))
    counts = authorization_test_counts(tests)
    lines.extend(
        [
            "## Authorization Assessment",
            "",
            "| Measure | Result |",
            "| --- | --- |",
            table_row("Status", title(status)),
            table_row(
                "Security posture",
                title(assessment.get("overall_security_posture") or "unknown"),
            ),
            table_row("HTTP requests", integer(assessment.get("http_requests"))),
            table_row("Tests", len(tests)),
            table_row("Passed controls", counts["passed"]),
            table_row("Failed controls", counts["failed"]),
            table_row("Inconclusive controls", counts["inconclusive"]),
            "",
        ]
    )
    if tests:
        lines.extend(
            [
                "> A `FAIL` result means the tested authorization control failed; "
                "it is a security finding, not a tool failure.",
                "",
                "| Result | Test | Summary | Evidence actions |",
                "| --- | --- | --- | --- |",
            ]
        )
        for test in tests:
            lines.append(
                table_row(
                    title(test.get("result") or "unknown"),
                    clean_text(test.get("name") or test.get("test_id"), 200),
                    clean_text(test.get("summary"), 400),
                    ", ".join(string_items(test.get("action_ids")))
                    or "not recorded",
                )
            )
        lines.append("")

    limitations = string_items(assessment.get("limitations"))
    if limitations:
        lines.extend(["### Authorization Limitations", ""])
        lines.extend(f"- {clean_text(item, 1_000)}" for item in limitations)
        lines.append("")


def append_authentication_discovery(
    lines: list[str],
    raw_discovery: Any,
) -> None:
    discovery = as_dict(raw_discovery)
    status = normalized_status(discovery.get("status"))
    if not discovery or status in EMPTY_STATUSES:
        return
    contract = as_dict(discovery.get("contract"))
    fields = [
        value
        for value in [
            contract.get("username_field"),
            contract.get("password_field"),
        ]
        if value
    ]
    lines.extend(
        [
            "## Authentication Contract Discovery",
            "",
            "| Field | Discovered value |",
            "| --- | --- |",
            table_row("Status", title(status)),
            table_row(
                "Generated by",
                code(discovery.get("generated_by") or "not recorded"),
            ),
            table_row(
                "Confidence",
                title(discovery.get("confidence") or "not recorded"),
            ),
            table_row(
                "Endpoint",
                code(contract.get("endpoint") or "not discovered"),
            ),
            table_row(
                "Request format",
                code(contract.get("request_format") or "not discovered"),
            ),
            table_row(
                "Credential fields",
                ", ".join(code(item) for item in fields) or "not discovered",
            ),
            table_row(
                "Success statuses",
                join_values(contract.get("success_statuses")),
            ),
            table_row(
                "Failure statuses",
                join_values(contract.get("failure_statuses")),
            ),
            table_row(
                "Resources inspected",
                len(dict_items(discovery.get("evidence"))),
            ),
        ]
    )
    missing = string_items(discovery.get("missing_prerequisites"))
    if missing:
        lines.append(table_row("Missing prerequisites", "; ".join(missing)))
    lines.append("")


def append_identity_validation(
    lines: list[str],
    raw_wordlist: Any,
    raw_spray: Any,
) -> None:
    wordlist = as_dict(raw_wordlist)
    spray = as_dict(raw_spray)
    results = [
        ("Password wordlist", wordlist),
        ("Password spray", spray),
    ]
    results = [(name, result) for name, result in results if active_result(result)]
    if not results:
        return

    lines.extend(
        [
            "## Credential Validation",
            "",
            (
                "| Attack | Status | HTTP attempts | Accounts tested | "
                "Password candidates | Accepted | Lockout | Stop reason |"
            ),
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for name, result in results:
        accounts_tested = result.get("unique_identities_attempted")
        if accounts_tested is None:
            accounts_tested = 1 if integer(result.get("attempted")) else 0
        password_candidates = result.get("password_candidates_attempted")
        if password_candidates is None:
            password_candidates = result.get("attempted")
        lines.append(
            table_row(
                name,
                title(result.get("status") or "unknown"),
                integer(result.get("attempted")),
                integer(accounts_tested),
                integer(password_candidates),
                integer(result.get("successful")),
                yes_no(result.get("lockout_detected")),
                title(result.get("stop_reason") or "not recorded"),
            )
        )
    lines.append("")

    revealed = render_revealed_credentials_section(
        wordlist,
        spray,
        heading="### Plaintext Lab Credentials",
    )
    if revealed:
        lines.extend([*revealed.splitlines(), ""])

    for name, result in results:
        lines.extend(
            [
                f"### {name}",
                "",
                f"- **Endpoint:** {code(result.get('endpoint') or 'not recorded')}",
            ]
        )
        if result.get("username"):
            lines.append(f"- **Identity:** {code(result['username'])}")
        if result.get("trace_path"):
            lines.append(f"- **Attempt trace:** {code(result['trace_path'])}")
        if name == "Password spray":
            lines.extend(
                [
                    (
                        "- **Username candidates:** "
                        f"{integer(result.get('username_candidates_loaded'))} loaded; "
                        f"{integer(result.get('unique_identities_attempted'))} tested"
                    ),
                    (
                        "- **Password candidates:** "
                        f"{integer(result.get('password_candidates_loaded'))} loaded; "
                        f"{integer(result.get('password_candidates_attempted'))} reached"
                    ),
                ]
            )
            username_sources = dict_items(result.get("username_wordlists"))
            if username_sources:
                lines.append(
                    "- **Username source:** "
                    + ", ".join(
                        code(source.get("path") or "not recorded")
                        for source in username_sources
                    )
                )
        limits = as_dict(result.get("limits"))
        if limits:
            lines.append(
                "- **Limits:** "
                + ", ".join(
                    f"{title(key)}={clean_text(value, 80)}"
                    for key, value in limits.items()
                )
            )
        attempted_identities = string_items(
            result.get("attempted_identities")
        )
        if attempted_identities:
            lines.extend(
                [
                    "",
                    "**Accounts tested:** "
                    + ", ".join(code(identity) for identity in attempted_identities),
                ]
            )
        successes = dict_items(result.get("successes"))
        if successes:
            lines.extend(
                [
                    "",
                    "| Identity | Password position | HTTP status | Proof |",
                    "| --- | --- | --- | --- |",
                ]
            )
            for success in successes:
                lines.append(
                    table_row(
                        code(success.get("username") or "not retained"),
                        integer(success.get("password_index")),
                        integer(success.get("status")),
                        clean_text(success.get("proof"), 320),
                    )
                )
        lines.append("")


def render_revealed_credentials_section(
    raw_wordlist: Any,
    raw_spray: Any,
    *,
    heading: str = "## Confirmed Lab Credentials",
) -> str:
    credentials = collect_revealed_credentials(raw_wordlist, raw_spray)
    if not credentials:
        return ""

    lines = [
        heading,
        "",
        (
            "> **Sensitive lab output:** Plaintext credentials were intentionally "
            "retained for this disposable private-lab run. Rotate them after testing "
            "and restrict access to the report artifacts."
        ),
        "",
        "| Attack | Identity | Password | Endpoint | Password position | HTTP status |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for credential in credentials:
        lines.append(
            table_row(
                credential["attack"],
                code(credential["username"]),
                secret_code(credential["password"]),
                code(credential["endpoint"]),
                integer(credential.get("password_index")),
                integer(credential.get("status")),
            )
        )
    return "\n".join(lines)


def append_capability_validation(
    lines: list[str],
    raw_validation: Any,
    raw_loop: Any,
) -> None:
    validation = as_dict(raw_validation)
    results = dict_items(validation.get("results"))
    if not active_result(validation) and not results:
        return

    lines.extend(
        [
            "## Capability Validation",
            "",
            "| Measure | Result |",
            "| --- | --- |",
            table_row("Execution mode", code(validation.get("execution_mode") or "not recorded")),
            table_row("Attempted", integer(validation.get("attempted") or len(results))),
            table_row("Positive evidence", integer(validation.get("successful"))),
            table_row("Command execution verified", yes_no(validation.get("exploited"))),
            table_row("Cleanup verified", yes_no(validation.get("cleanup_verified"))),
            "",
        ]
    )
    if results:
        lines.extend(
            [
                "| Status | Capability | Target | Provider | Evidence |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for result in results:
            target = str(result.get("target") or "")
            if result.get("port"):
                target = f"{target}:{result['port']}"
            lines.append(
                table_row(
                    title(result.get("status") or "unknown"),
                    clean_text(
                        result.get("selected_exploit_name")
                        or result.get("selected_exploit_id")
                        or "unnamed capability",
                        220,
                    ),
                    code(target or "not recorded"),
                    code(result.get("provider") or "not recorded"),
                    summarize_value(
                        result.get("proof_output")
                        or result.get("reason")
                        or result.get("proof_goal")
                        or "",
                        420,
                    ),
                )
            )
        lines.append("")

    loop = as_dict(raw_loop)
    if loop and loop.get("enabled"):
        lines.extend(
            [
                "### Closed-Loop Execution",
                "",
                "| Rounds | Stop reason | Unique capabilities attempted |",
                "| --- | --- | --- |",
                table_row(
                    integer(loop.get("rounds")),
                    title(loop.get("stop_reason") or "unknown"),
                    len(string_items(loop.get("attempted_ids"))),
                ),
                "",
            ]
        )


def append_attack_surface(
    lines: list[str],
    payload: dict[str, Any],
) -> None:
    services = dict_items(payload.get("services"))
    fingerprints = dict_items(
        as_dict(payload.get("web_fingerprint")).get("web_fingerprints")
    )
    web_routes = dict_items(as_dict(payload.get("web_routes")).get("web_routes"))
    web_assessment = as_dict(payload.get("web_assessment"))
    assessed_routes = dict_items(web_assessment.get("routes"))
    routes = assessed_routes or web_routes
    web_checks = as_dict(payload.get("web_checks"))
    has_web_data = bool(
        routes
        or fingerprints
        or web_assessment
        or web_checks
    )
    if not services and not has_web_data:
        return

    lines.extend(["## Observed Attack Surface", ""])
    if services:
        lines.extend(
            [
                "### Services",
                "",
                "| Port | Protocol | Service | Version |",
                "| --- | --- | --- | --- |",
            ]
        )
        for service in services:
            lines.append(
                table_row(
                    service.get("port") or "",
                    service.get("protocol") or "tcp",
                    service.get("service") or "unknown",
                    clean_text(service.get("version"), 260),
                )
            )
        lines.append("")

    responsive_fingerprints = [
        item
        for item in fingerprints
        if item.get("status") and not item.get("error")
    ]
    if fingerprints:
        lines.extend(
            [
                "### Web Fingerprints",
                "",
                (
                    f"Collected {counted(len(fingerprints), 'fingerprint record')}; "
                    f"{counted(len(responsive_fingerprints), 'target')} responded."
                ),
                "",
            ]
        )
        if responsive_fingerprints:
            lines.extend(
                [
                    "| URL | Status | Server | Technology | Missing security headers |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for fingerprint in responsive_fingerprints[:20]:
                security_headers = as_dict(fingerprint.get("security_headers"))
                missing_headers = [
                    title(name)
                    for name, present in security_headers.items()
                    if not present
                ]
                technologies = string_items(
                    fingerprint.get("technology_signals")
                )
                lines.append(
                    table_row(
                        clean_text(fingerprint.get("url"), 240),
                        fingerprint.get("status") or "",
                        clean_text(
                            fingerprint.get("server")
                            or fingerprint.get("powered_by")
                            or "not disclosed",
                            160,
                        ),
                        ", ".join(technologies) or "none observed",
                        ", ".join(missing_headers) or "none observed",
                    )
                )
            lines.append("")

    if routes:
        responsive = [
            route
            for route in routes
            if route.get("status") and not route.get("error")
        ]
        errors = [route for route in routes if route.get("error")]
        lines.extend(
            [
                "### Web Routes",
                "",
                (
                    f"Observed {counted(len(routes), 'route record')}: "
                    f"{len(responsive)} responsive and "
                    f"{counted(len(errors), 'transport error')}."
                ),
                "",
            ]
        )
        display_routes = responsive[:25]
        if display_routes:
            lines.extend(
                [
                    "| Method | Status | URL | Signal |",
                    "| --- | --- | --- | --- |",
                ]
            )
            for route in display_routes:
                signal = (
                    route.get("artifact_signal")
                    or route.get("title")
                    or route.get("content_type")
                    or ""
                )
                lines.append(
                    table_row(
                        route.get("method") or "GET",
                        route.get("status") or "",
                        clean_text(route.get("url"), 240),
                        clean_text(signal, 180),
                    )
                )
            lines.append("")
        if len(responsive) > len(display_routes):
            lines.extend(
                [
                    f"_Showing {len(display_routes)} of {len(responsive)} responsive routes._",
                    "",
                ]
            )

    web_findings = dict_items(web_assessment.get("findings"))
    control_findings = dict_items(web_checks.get("findings"))
    if web_findings or control_findings:
        lines.extend(
            [
                "### Web Validation Coverage",
                "",
                "| Source | Checks or findings |",
                "| --- | --- |",
                table_row("Application assessment", len(web_findings)),
                table_row("Control checks", len(control_findings)),
                "",
            ]
        )


def append_model_strategy(
    lines: list[str],
    raw_recon: Any,
    raw_validation: Any,
) -> None:
    recon = as_dict(raw_recon)
    validation = as_dict(raw_validation)
    if not recon and not validation:
        return

    lines.extend(
        [
            "## Model-Selected Strategy",
            "",
            (
                "> This section records planning decisions. Confirmed observations and "
                "tool results are reported separately above."
            ),
            "",
        ]
    )
    if recon:
        lines.extend(
            [
                "### Reconnaissance Plan",
                "",
                "| Field | Selection |",
                "| --- | --- |",
                table_row(
                    "Generated by",
                    code(recon.get("generated_by") or "not recorded"),
                ),
                table_row(
                    "Service scan ports",
                    join_values(recon.get("service_scan_ports")),
                ),
                table_row(
                    "HTTP probe ports",
                    join_values(recon.get("http_probe_ports")),
                ),
                table_row(
                    "Reason",
                    clean_text(recon.get("reason"), 700) or "not recorded",
                ),
                "",
            ]
        )
        focus = string_items(recon.get("validation_focus"))
        if focus:
            lines.extend(["**Validation focus**", ""])
            lines.extend(f"- {clean_text(item, 600)}" for item in focus)
            lines.append("")

    if validation:
        selected_ids = string_items(validation.get("selected_ids"))
        lines.extend(
            [
                "### Validation Plan",
                "",
                "| Field | Selection |",
                "| --- | --- |",
                table_row(
                    "Generated by",
                    code(validation.get("generated_by") or "not recorded"),
                ),
                table_row(
                    "Selected capabilities",
                    ", ".join(code(item) for item in selected_ids)
                    or "none recorded",
                ),
                table_row(
                    "Reason",
                    clean_text(validation.get("reason"), 900) or "not recorded",
                ),
                "",
            ]
        )


def append_campaign_phases(
    lines: list[str],
    raw_phases: Any,
) -> None:
    phases = dict_items(raw_phases)
    if not phases:
        return
    lines.extend(
        [
            "## Campaign Phases",
            "",
            "| Phase | Status | Evidence |",
            "| --- | --- | --- |",
        ]
    )
    for phase in phases:
        lines.append(
            table_row(
                title(phase.get("phase") or "unnamed"),
                title(phase.get("status") or "unknown"),
                clean_text(phase.get("evidence"), 420),
            )
        )
    lines.append("")


def append_routing_and_agents(
    lines: list[str],
    raw_routing: Any,
    raw_agents: Any,
) -> None:
    routing = as_dict(raw_routing)
    agents = dict_items(raw_agents)
    if not routing and not agents:
        return
    lines.extend(["## Agent Collaboration", ""])
    if routing:
        selected = string_items(routing.get("selected_agents"))
        lines.extend(
            [
                f"- **Selected specialists:** "
                f"{', '.join(code(item) for item in selected) or 'none recorded'}",
                f"- **Router:** {code(routing.get('generated_by') or 'not recorded')}",
            ]
        )
        reason = clean_text(routing.get("authorization_reason"), 700)
        if reason:
            lines.append(f"- **Authorization routing:** {reason}")
        lines.append("")

    if agents:
        lines.extend(
            [
                "| Agent | Objective | Tools | Handoff |",
                "| --- | --- | --- | --- |",
            ]
        )
        for agent in agents:
            lines.append(
                table_row(
                    clean_text(agent.get("role") or "Unnamed agent", 120),
                    clean_text(agent.get("objective"), 300),
                    ", ".join(string_items(agent.get("tools"))[:6])
                    or "none recorded",
                    clean_text(agent.get("handoff"), 300),
                )
            )
        lines.append("")


def append_execution_timeline(
    lines: list[str],
    raw_timeline: Any,
) -> None:
    timeline = dict_items(raw_timeline)
    if not timeline:
        return
    lines.extend(
        [
            "## Execution Timeline",
            "",
            "| # | Tool or agent | Status | Input | Result |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for index, item in enumerate(timeline, start=1):
        lines.append(
            table_row(
                index,
                clean_text(item.get("tool") or "unnamed", 120),
                title(item.get("status") or "unknown"),
                summarize_value(item.get("input"), 180),
                summarize_value(item.get("evidence"), 420),
            )
        )
    lines.append("")


def append_knowledge_context(
    lines: list[str],
    raw_graph: Any,
    raw_sources: Any,
) -> None:
    graph = as_dict(raw_graph)
    hits = dict_items(graph.get("hits"))
    sources = dict_items(raw_sources)
    if not hits and not sources:
        return
    lines.extend(["## Knowledge Context", ""])

    if hits:
        lines.extend(
            [
                "### Graph Memory Matches",
                "",
                "| Type | Name | Score |",
                "| --- | --- | --- |",
            ]
        )
        for hit in hits[:12]:
            lines.append(
                table_row(
                    hit.get("type") or "unknown",
                    clean_text(hit.get("name"), 260),
                    decimal(hit.get("score"), 3),
                )
            )
        lines.append("")

    if sources:
        lines.extend(
            [
                "### Retrieved Sources",
                "",
                f"Retrieved {len(sources)} knowledge item(s). Showing the highest-ranked entries.",
                "",
                "| Collection | Source | Reference | Score |",
                "| --- | --- | --- | --- |",
            ]
        )
        for source in sources[:15]:
            metadata = as_dict(source.get("metadata"))
            source_name = (
                metadata.get("name")
                or metadata.get("mitre_id")
                or source.get("id")
                or "unnamed"
            )
            reference = metadata.get("url") or metadata.get("mitre_id") or source.get("id")
            lines.append(
                table_row(
                    source.get("collection") or "unknown",
                    clean_text(source_name, 220),
                    markdown_reference(reference),
                    decimal(source.get("score"), 3),
                )
            )
        lines.append("")


def append_safety_review(
    lines: list[str],
    raw_review: Any,
) -> None:
    if not raw_review:
        return
    review = parse_json_object(raw_review)
    lines.extend(["## Safety Review", ""])
    if review:
        lines.extend(
            [
                "| Field | Value |",
                "| --- | --- |",
                table_row("Verdict", title(review.get("verdict") or "not recorded")),
                table_row(
                    "Guidance",
                    clean_text(review.get("guidance"), 800) or "none recorded",
                ),
            ]
        )
        review_findings = review.get("findings")
        if isinstance(review_findings, list):
            lines.append(table_row("Safety findings", len(review_findings)))
        lines.append("")
    else:
        lines.extend([summarize_value(raw_review, 1_000), ""])


def append_artifacts(
    lines: list[str],
    payload: dict[str, Any],
    artifact_paths: dict[str, str],
) -> None:
    artifacts: list[tuple[str, str]] = []
    json_path = artifact_paths.get("json")
    if json_path:
        artifacts.append(
            (
                "Machine-readable campaign record",
                f"[{escape_cell(Path(json_path).name)}]({markdown_link_target(json_path)})",
            )
        )

    authorization = as_dict(payload.get("authorization_assessment"))
    for label, path in as_dict(authorization.get("artifacts")).items():
        if path:
            artifacts.append((f"Authorization {title(label)}", code(path)))

    for label, result in [
        ("Wordlist attempt trace", as_dict(payload.get("wordlist_attack"))),
        ("Password spray attempt trace", as_dict(payload.get("password_spray"))),
    ]:
        if result.get("trace_path"):
            artifacts.append((label, code(result["trace_path"])))

    lines.extend(
        [
            "## Artifacts And Audit Notes",
            "",
            (
                "This Markdown report is the human-readable view. The companion JSON "
                "retains the full model narrative, complete tool payloads, traces, and "
                "structured evidence for detailed review."
            ),
            "",
        ]
    )
    if artifacts:
        lines.extend(["| Artifact | Location |", "| --- | --- |"])
        for label, location in artifacts:
            lines.append(table_row(label, location))
        lines.append("")

    steps = string_items(payload.get("steps"))
    if steps:
        lines.extend(
            [
                "<details>",
                "<summary>Recorded workflow steps</summary>",
                "",
            ]
        )
        lines.extend(f"{index}. {clean_text(step, 600)}" for index, step in enumerate(steps, 1))
        lines.extend(["", "</details>", ""])


def campaign_outcome(
    payload: dict[str, Any],
    confirmed: list[dict[str, Any]],
) -> str:
    if payload.get("error"):
        return "Execution failed"
    if confirmed:
        highest = highest_severity(confirmed)
        if any(
            normalized_status(item.get("status")) == "confirmed_vulnerability"
            for item in confirmed
        ):
            return f"Confirmed vulnerability ({title(highest)})"
        return f"Confirmed exposure ({title(highest)})"
    authorization = as_dict(payload.get("authorization_assessment"))
    if normalized_status(authorization.get("overall_security_posture")) == "vulnerable":
        return "Vulnerable"
    phases = dict_items(payload.get("phases"))
    if any(
        normalized_status(phase.get("status"))
        in {"failed", "tool_error", "execution_error"}
        for phase in phases
    ):
        return "Completed with execution errors"
    return "No confirmed finding"


def authorization_test_counts(tests: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"passed": 0, "failed": 0, "inconclusive": 0}
    for test in tests:
        result = normalized_status(test.get("result"))
        if result in {"pass", "passed"}:
            counts["passed"] += 1
        elif result in {"fail", "failed"}:
            counts["failed"] += 1
        else:
            counts["inconclusive"] += 1
    return counts


def credential_result_summary(result: dict[str, Any]) -> str:
    return (
        f"{integer(result.get('successful'))}/"
        f"{integer(result.get('attempted'))} accepted; "
        f"stop={title(result.get('stop_reason') or 'not recorded')}"
    )


def active_result(result: dict[str, Any]) -> bool:
    if not result:
        return False
    status = normalized_status(result.get("status"))
    if status and status not in EMPTY_STATUSES:
        return True
    return any(
        result.get(key)
        for key in ("attempted", "results", "successes", "endpoint")
    )


def highest_severity(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return ""
    return max(
        (
            normalized_status(item.get("severity")) or "informational"
            for item in findings
        ),
        key=lambda value: SEVERITY_ORDER.get(value, 0),
    )


def summarize_value(value: Any, limit: int) -> str:
    parsed = parse_json_value(value)
    if isinstance(parsed, dict):
        return summarize_mapping(parsed, limit)
    if isinstance(parsed, list):
        return clean_text(f"{len(parsed)} item(s)", limit)
    if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        return summarize_json_fragment(value, limit)
    return clean_text(parsed, limit)


def summarize_mapping(value: dict[str, Any], limit: int) -> str:
    parts: list[str] = []
    command = value.get("command")
    if isinstance(command, list):
        parts.append("command=" + " ".join(str(item) for item in command))
    for key in (
        "status",
        "template-id",
        "name",
        "severity",
        "endpoint",
        "attempted",
        "successful",
        "stop_reason",
        "returncode",
        "elapsed_seconds",
        "error",
        "reason",
    ):
        item = value.get(key)
        if item not in (None, "", [], {}):
            parts.append(f"{key}={clean_text(item, 180)}")
    for key in ("http_probe", "web_fingerprints", "web_routes", "findings", "results"):
        item = value.get(key)
        if isinstance(item, list):
            errors = sum(1 for entry in item if isinstance(entry, dict) and entry.get("error"))
            summary = f"{key}={len(item)} item(s)"
            if errors:
                summary += f", {errors} error(s)"
            parts.append(summary)
    selected = value.get("selected_agents")
    if isinstance(selected, list):
        parts.append("selected_agents=" + ", ".join(str(item) for item in selected))
    info = value.get("info")
    if isinstance(info, dict):
        for key in ("name", "severity"):
            item = info.get(key)
            if item not in (None, ""):
                parts.append(f"{key}={clean_text(item, 180)}")
    if not parts:
        for key, item in value.items():
            if isinstance(item, (str, int, float, bool)) and item not in ("", None):
                parts.append(f"{key}={clean_text(item, 140)}")
            if len(parts) >= 5:
                break
    return clean_text("; ".join(parts) or "Structured result recorded", limit)


def summarize_json_fragment(value: str, limit: int) -> str:
    parts: list[str] = []
    for key in (
        "status",
        "posture",
        "generated_by",
        "confidence",
        "template-id",
        "name",
        "severity",
        "endpoint",
        "attempted",
        "successful",
        "stop_reason",
        "returncode",
        "error",
        "reason",
    ):
        pattern = rf'"{re.escape(key)}"\s*:\s*(?:"([^"]*)"|(-?\d+(?:\.\d+)?)|(true|false|null))'
        match = re.search(pattern, value, flags=re.IGNORECASE)
        if not match:
            continue
        captured = next(
            (group for group in match.groups() if group is not None),
            "",
        )
        if captured not in ("", "null"):
            parts.append(f"{key}={captured}")
    selected_match = re.search(
        r'"selected_agents"\s*:\s*\[([^\]]*)\]',
        value,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if selected_match:
        selected = re.findall(r'"([^"]+)"', selected_match.group(1))
        if selected:
            parts.append("selected_agents=" + ", ".join(selected))
    if parts:
        return clean_text("; ".join(parts), limit)
    return "Structured result recorded; see the companion JSON for full details."


def parse_json_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{":
        return value
    try:
        return json.loads(stripped)
    except (TypeError, ValueError):
        return value


def parse_json_object(value: Any) -> dict[str, Any]:
    parsed = parse_json_value(value)
    return parsed if isinstance(parsed, dict) else {}


def dict_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def string_items(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item not in (None, "")]


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def clean_text(value: Any, limit: int = 400) -> str:
    if value in (None, ""):
        return ""
    text = " ".join(str(value).split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def clean_heading(value: Any) -> str:
    return clean_text(value, 180).replace("#", "").strip()


def normalized_status(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def title(value: Any) -> str:
    text = (
        str(value or "")
        .strip()
        .replace("_", " ")
        .replace("-", " ")
        .replace(":", ": ")
    )
    if not text:
        return "Not Recorded"
    rendered = " ".join(text.title().split())
    for ordinary, acronym in {
        "Api": "API",
        "Cwe": "CWE",
        "Ftp": "FTP",
        "Http": "HTTP",
        "Idor": "IDOR",
        "Json": "JSON",
        "Llm": "LLM",
        "Mfa": "MFA",
        "Owasp": "OWASP",
        "Rbac": "RBAC",
        "Rce": "RCE",
        "Siem": "SIEM",
        "Tcp": "TCP",
        "Url": "URL",
    }.items():
        rendered = rendered.replace(ordinary, acronym)
    return rendered


def integer(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def counted(count: int, singular: str) -> str:
    suffix = "" if count == 1 else "s"
    return f"{count} {singular}{suffix}"


def decimal(value: Any, places: int) -> str:
    try:
        return f"{float(value):.{places}f}"
    except (TypeError, ValueError):
        return "n/a"


def format_duration(value: Any) -> str:
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return "not recorded"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    minutes, remaining = divmod(seconds, 60)
    return f"{int(minutes)}m {remaining:.1f}s"


def yes_no(value: Any) -> str:
    if value is None:
        return "Not recorded"
    return "Yes" if bool(value) else "No"


def join_values(value: Any) -> str:
    if not isinstance(value, list) or not value:
        return "not recorded"
    return ", ".join(code(item) for item in value)


def code(value: Any) -> str:
    text = clean_text(value, 500).replace("`", "'")
    return f"`{text}`"


def secret_code(value: Any) -> str:
    return f"<code>{escape(str(value), quote=False)}</code>"


def table_row(*values: Any) -> str:
    return "| " + " | ".join(escape_cell(value) for value in values) + " |"


def escape_cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", r"\|").replace("\n", "<br>")


def markdown_reference(value: Any) -> str:
    text = clean_text(value, 300)
    if text.startswith(("https://", "http://")):
        return f"[source]({markdown_link_target(text)})"
    return code(text or "not recorded")


def markdown_link_target(value: Any) -> str:
    return str(value).replace(" ", "%20").replace("(", "%28").replace(")", "%29")
