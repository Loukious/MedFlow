from __future__ import annotations

import json
import stat

from medflow_redteam.campaign import CampaignRun, save_campaign_run
from medflow_redteam.campaign_report import render_campaign_markdown


def representative_payload() -> dict:
    return {
        "goal": "Review authorization | identity controls",
        "target": None,
        "target_url": "http://127.0.0.1:3000/",
        "provider": "local_qwen",
        "elapsed_seconds": 125.5,
        "error": None,
        "report": "SUPER_SECRET_MODEL_NARRATIVE",
        "services": [
            {
                "port": "3000",
                "protocol": "tcp",
                "service": "http",
                "version": "Example service",
            }
        ],
        "normalized_evidence": [
            {
                "type": "authorization_assessment",
                "title": "Role header | privilege escalation",
                "asset": "http://127.0.0.1:3000/admin",
                "status": "confirmed_vulnerability",
                "severity": "critical",
                "confidence": "high",
                "proof_kind": "bounded_http_differential",
                "safe_summary": "Patient role was replaced with admin and access was granted.",
                "remediation": "Resolve roles from a trusted server-side identity.",
                "references": ["CWE-269", "A01:2021"],
            },
            {
                "type": "capability_validation",
                "title": "Negative FTP check",
                "asset": "127.0.0.1:21",
                "status": "ran_no_finding",
                "severity": "informational",
                "confidence": "medium",
                "safe_summary": "The check completed without positive evidence.",
            },
        ],
        "authorization_assessment": {
            "status": "completed",
            "overall_security_posture": "vulnerable",
            "http_requests": 8,
            "test_summary": "Incorrect model-generated counts must not be used.",
            "tests": [
                {
                    "name": "Object access",
                    "result": "PASS",
                    "summary": "Cross-object access was denied.",
                    "action_ids": ["object-1"],
                },
                {
                    "name": "Admin escalation",
                    "result": "FAIL",
                    "summary": "An untrusted role claim was accepted.",
                    "action_ids": ["admin-1", "admin-2"],
                },
                {
                    "name": "Uncovered write",
                    "result": "INCONCLUSIVE",
                    "summary": "The requested variant was not executed.",
                    "action_ids": [],
                },
            ],
            "limitations": ["Only declared routes were assessed."],
            "artifacts": {"evidence": "reports/auth/raw_http_evidence.json"},
        },
        "authentication_discovery": {
            "status": "ready",
            "generated_by": "llm:local_qwen",
            "confidence": "high",
            "contract": {
                "endpoint": "/rest/user/login",
                "username_field": "email",
                "password_field": "password",
                "request_format": "json",
                "success_statuses": [200],
                "failure_statuses": [400, 401],
            },
            "evidence": [{"url": "http://127.0.0.1:3000/"}],
            "missing_prerequisites": [],
        },
        "wordlist_attack": {
            "status": "confirmed_credential",
            "endpoint": "http://127.0.0.1:3000/rest/user/login",
            "username": "root@example.test",
            "attempted": 2,
            "successful": 1,
            "stop_reason": "credential_confirmed",
            "lockout_detected": False,
            "trace_path": "reports/identity/wordlist.jsonl",
            "successes": [
                {
                    "username": "root@example.test",
                    "password_index": 2,
                    "status": 200,
                    "proof": "Success signal matched; no password was retained.",
                }
            ],
        },
        "password_spray": {},
        "capability_validation": {},
        "loop_summary": {},
        "web_routes": {
            "web_routes": [
                {
                    "url": "http://127.0.0.1:3000/",
                    "status": 200,
                    "title": "Example",
                },
                {
                    "url": "http://127.0.0.1:3000/missing",
                    "error": "connection refused",
                },
            ]
        },
        "web_fingerprint": {
            "web_fingerprints": [
                {
                    "url": "http://127.0.0.1:3000/",
                    "status": 200,
                    "server": "example",
                    "technology_signals": ["python"],
                    "security_headers": {
                        "content_security_policy": False,
                        "x_frame_options": True,
                    },
                }
            ]
        },
        "web_assessment": {},
        "web_checks": {},
        "recon_strategy": {
            "service_scan_ports": [3000],
            "http_probe_ports": [3000],
            "validation_focus": ["Inspect the observed HTTP application."],
            "reason": "Port 3000 responded over HTTP.",
            "generated_by": "llm",
            "llm_raw": '{"raw":"must not be rendered"}',
        },
        "validation_strategy": {
            "selected_ids": ["generated:example"],
            "reason": "The capability matches the observed service.",
            "generated_by": "llm",
            "llm_raw": '{"raw":"must not be rendered"}',
        },
        "campaign_routing": {
            "selected_agents": ["identity_attack", "reporting"],
            "generated_by": "llm:local_qwen",
            "authorization_reason": "The goal requested access-control checks.",
        },
        "agents": [
            {
                "role": "Reporting Agent",
                "objective": "Summarize observed evidence.",
                "tools": ["Markdown report", "JSON trace"],
                "decisions": ["Do not confuse plans with observations."],
                "outputs": ["Campaign report"],
                "handoff": "Report ready for review.",
            }
        ],
        "phases": [
            {
                "phase": "authorization assessment",
                "status": "confirmed_exposure",
                "evidence": "Eight bounded HTTP requests completed.",
            }
        ],
        "tool_timeline": [
            {
                "tool": "campaign_specialist_router",
                "status": "llm:local_qwen",
                "input": "authorization campaign",
                "evidence": json.dumps(
                    {
                        "selected_agents": ["identity_attack", "reporting"],
                        "status": "success",
                    }
                ),
            },
            {
                "tool": "authentication_contract_agent",
                "status": "success",
                "input": "http://127.0.0.1:3000/",
                "evidence": (
                    '{"status":"ready","generated_by":"llm:local_qwen",'
                    '"endpoint":"/rest/user/login","contract":{'
                ),
            },
        ],
        "graph_memory": {
            "hits": [
                {
                    "type": "Service",
                    "name": "127.0.0.1 3000/tcp http",
                    "score": 0.91,
                }
            ]
        },
        "sources": [
            {
                "collection": "attack_db",
                "id": "T1110.003",
                "metadata": {
                    "name": "Password Spraying",
                    "url": "https://attack.mitre.org/techniques/T1110/003/",
                },
                "score": 0.88,
            }
        ],
        "safety_review": json.dumps(
            {
                "verdict": "approved_for_lab",
                "findings": [],
                "guidance": "Remain within the authorized target.",
            }
        ),
        "steps": ["validated scope", "executed bounded checks"],
    }


def test_human_report_uses_structured_sections_instead_of_json_dumps() -> None:
    markdown = render_campaign_markdown(
        representative_payload(),
        artifact_paths={"json": "redteam_campaign_test.json"},
    )

    assert markdown.startswith("# MedFlow Red-Team Campaign Report\n")
    assert "> **Outcome:** Confirmed vulnerability (Critical)" in markdown
    assert "## Executive Summary" in markdown
    assert "## Findings" in markdown
    assert "## Authorization Assessment" in markdown
    assert "## Credential Validation" in markdown
    assert "## Observed Attack Surface" in markdown
    assert "### Web Fingerprints" in markdown
    assert "## Model-Selected Strategy" in markdown
    assert "## Execution Timeline" in markdown
    assert "| Passed controls | 1 |" in markdown
    assert "| Failed controls | 1 |" in markdown
    assert "| Inconclusive controls | 1 |" in markdown
    assert "Role header \\| privilege escalation" in markdown
    assert "[redteam_campaign_test.json](redteam_campaign_test.json)" in markdown
    assert "status=ready; generated_by=llm:local_qwen; endpoint=/rest/user/login" in markdown
    assert '{"status":"ready"' not in markdown
    assert "must not be rendered" not in markdown
    assert '"selected_agents": [' not in markdown
    assert "SUPER_SECRET_MODEL_NARRATIVE" not in markdown
    assert "## Report" not in markdown


def test_capability_report_keeps_proof_concise() -> None:
    payload = representative_payload()
    payload["authorization_assessment"] = {}
    payload["wordlist_attack"] = {}
    payload["normalized_evidence"] = [
        {
            "title": "Provider finding",
            "asset": "127.0.0.1:21",
            "status": "confirmed_exposure",
            "severity": "medium",
            "confidence": "high",
            "proof_kind": "tool_output",
            "safe_summary": (
                '{"template-id":"CVE-2024-0001","info":'
                '{"name":"Example provider finding","severity":"high",'
                '"description":"truncated provider output'
            ),
        }
    ]
    payload["capability_validation"] = {
        "execution_mode": "aggressive_lab",
        "attempted": 1,
        "successful": 1,
        "exploited": True,
        "cleanup_verified": True,
        "results": [
            {
                "status": "confirmed_vulnerability",
                "selected_exploit_name": "Controlled command proof",
                "target": "127.0.0.1",
                "port": 6667,
                "provider": "generated_tool",
                "proof_output": "uid=1000(test) " + ("x" * 2_000),
            }
        ],
    }

    markdown = render_campaign_markdown(payload)

    assert "## Capability Validation" in markdown
    assert "Controlled command proof" in markdown
    assert "uid=1000(test)" in markdown
    assert "template-id=CVE-2024-0001" in markdown
    assert "name=Example provider finding" in markdown
    assert '{"template-id"' not in markdown
    assert "x" * 500 not in markdown


def test_save_campaign_run_retains_full_narrative_only_in_json(tmp_path) -> None:
    run = CampaignRun(
        goal="Create a readable report",
        target=None,
        target_url="http://127.0.0.1:3000/",
        provider="local_qwen",
        report="FULL_MODEL_NARRATIVE",
        steps=[],
        agents=[],
        sources=[],
        tool_traces=[],
        elapsed_seconds=1.25,
    )

    paths = save_campaign_run(run, tmp_path)
    markdown = paths["markdown"].read_text(encoding="utf-8")
    payload = json.loads(paths["json"].read_text(encoding="utf-8"))

    assert payload["report"] == "FULL_MODEL_NARRATIVE"
    assert "FULL_MODEL_NARRATIVE" not in markdown
    assert f"[{paths['json'].name}]({paths['json'].name})" in markdown
    assert "No confirmed finding" in markdown


def test_plaintext_lab_credentials_are_visible_and_owner_only(tmp_path) -> None:
    run = CampaignRun(
        goal="Validate disposable lab credentials",
        target=None,
        target_url="http://127.0.0.1:3000/",
        provider="local_qwen",
        report="Campaign complete.",
        steps=[],
        agents=[],
        sources=[],
        tool_traces=[],
        wordlist_attack={
            "status": "confirmed_credential",
            "endpoint": "http://127.0.0.1:3000/login",
            "attempted": 2,
            "successful": 1,
            "successes": [
                {
                    "username": "root@medflow-agent.test",
                    "password": "synthetic-password",
                    "password_index": 2,
                    "status": 200,
                }
            ],
        },
    )

    paths = save_campaign_run(run, tmp_path)
    markdown = paths["markdown"].read_text(encoding="utf-8")
    payload = json.loads(paths["json"].read_text(encoding="utf-8"))

    assert "## Credential Validation" in markdown
    assert "### Plaintext Lab Credentials" in markdown
    assert "root@medflow-agent.test" in markdown
    assert "synthetic-password" in markdown
    assert (
        payload["wordlist_attack"]["successes"][0]["password"]
        == "synthetic-password"
    )
    assert stat.S_IMODE(paths["json"].stat().st_mode) == 0o600
    assert stat.S_IMODE(paths["markdown"].stat().st_mode) == 0o600


def test_password_spray_report_distinguishes_users_from_http_attempts() -> None:
    payload = representative_payload()
    payload["wordlist_attack"] = {}
    payload["password_spray"] = {
        "status": "confirmed_credential",
        "endpoint": "http://127.0.0.1:3000/login",
        "attempted": 11,
        "successful": 1,
        "username_candidates_loaded": 10,
        "unique_identities_attempted": 10,
        "password_candidates_loaded": 3,
        "password_candidates_attempted": 2,
        "attempted_identities": [
            "root@medflow-agent.test",
            "admin@medflow-agent.test",
        ],
        "username_template": "{username}@medflow-agent.test",
        "username_wordlists": [
            {
                "path": "data/wordlists/SecLists/Usernames/"
                "top-usernames-shortlist.txt"
            }
        ],
        "stop_reason": "success_threshold_reached",
        "lockout_detected": False,
        "successes": [
            {
                "username": "admin@medflow-agent.test",
                "password_index": 2,
                "status": 200,
            }
        ],
    }

    markdown = render_campaign_markdown(payload)

    assert "| Password spray | Confirmed Credential | 11 | 10 | 2 | 1 |" in markdown
    assert "**Username candidates:** 10 loaded; 10 tested" in markdown
    assert "**Password candidates:** 3 loaded; 2 reached" in markdown
    assert "top-usernames-shortlist.txt" in markdown
    assert "root@medflow-agent.test" in markdown
    assert "admin@medflow-agent.test" in markdown
