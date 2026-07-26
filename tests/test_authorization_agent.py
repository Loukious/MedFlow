from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from medflow_redteam.authorization_agent import (
    EventLogger,
    GenericAuthorizationAgent,
    GenericHttpPlanTool,
    PromptDocument,
    apply_verdict_audit,
    build_inline_prompt_document,
    compact_observations,
    extract_prompt_origins,
    is_json_validation_error,
    is_tool_argument_error,
    load_prompt_document,
    normalize_origin,
    reduced_completion_budget,
    retry_duration_from_message,
    safe_plan_for_log,
    validate_assessment,
)


SYNTHETIC_PROMPT = """
Authorized target: https://demo.invalid/api/reference

Supplied identity headers:
X-Principal: alice
X-Access-Level: reader

Reference identities include alice (reader) and bob (editor). The agent may vary the
X-Access-Level header using values supplied above.

Available operations:
GET /records/{id}
PATCH /records/{id}

Required test: determine whether a reader can update another user's record while claiming an
elevated supplied access level. Establish baseline behavior first.
""".strip()


def prompt_document(source: Path) -> PromptDocument:
    return PromptDocument(
        source=source,
        text=SYNTHETIC_PROMPT,
        sha256=hashlib.sha256(SYNTHETIC_PROMPT.encode()).hexdigest(),
        allowed_origins=("https://demo.invalid",),
    )


def valid_plan() -> dict:
    return {
        "target_origin": "https://demo.invalid",
        "baseline_headers": {
            "X-Principal": "alice",
            "X-Access-Level": "reader",
        },
        "mutable_headers": ["X-Access-Level"],
        "tests": [
            {
                "test_id": "cross_record_write",
                "name": "Cross-record write authorization",
                "objective": "Check whether a reader can update another record.",
                "pass_condition": "The unauthorized update is denied.",
                "fail_condition": "The unauthorized update is accepted.",
            }
        ],
        "requests": [
            {
                "action_id": "baseline_record",
                "test_id": "recon",
                "objective": "Establish baseline record behavior.",
                "method": "GET",
                "path": "/records/alpha",
                "header_overrides": {},
                "body": {},
            },
            {
                "action_id": "cross_record_update",
                "test_id": "cross_record_write",
                "objective": "Attempt the declared cross-record write.",
                "method": "PATCH",
                "path": "/records/beta",
                "header_overrides": {"X-Access-Level": "editor"},
                "body": {"note": "AUTONOMOUS_SECURITY_TEST_ONLY"},
            },
        ],
    }


class AuthorizationAgentTests(unittest.TestCase):
    def test_qwen_uses_prompted_schema_and_json_object_mode(self) -> None:
        captured = {}

        class Message:
            content = '{"ok":true}'

            def model_dump(self, **_: object) -> dict:
                return {"role": "assistant", "content": self.content}

        class Completions:
            @staticmethod
            def create(**kwargs: object) -> object:
                captured.update(kwargs)
                return SimpleNamespace(
                    choices=[
                        SimpleNamespace(
                            message=Message(),
                            finish_reason="stop",
                        )
                    ],
                    usage=None,
                )

        settings = SimpleNamespace(
            groq_api_key="test-key",
            gpt_oss_model="openai/gpt-oss-120b",
            qwen_model="qwen/qwen3.6-27b",
        )
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            with patch(
                "medflow_redteam.authorization_agent.load_settings",
                return_value=settings,
            ):
                agent = GenericAuthorizationAgent(
                    prompt_document(run_dir / "scenario.txt"),
                    EventLogger(run_dir),
                    provider="qwen",
                )
            agent.client = SimpleNamespace(
                chat=SimpleNamespace(completions=Completions())
            )
            agent.complete(
                [{"role": "user", "content": "Return the result."}],
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "schema": {
                            "type": "object",
                            "properties": {"ok": {"type": "boolean"}},
                            "required": ["ok"],
                            "additionalProperties": False,
                        }
                    },
                },
                max_completion_tokens=512,
                purpose="qwen_schema_test",
            )

        self.assertEqual(captured["model"], "qwen/qwen3.6-27b")
        self.assertEqual(captured["response_format"], {"type": "json_object"})
        self.assertEqual(captured["reasoning_effort"], "none")
        self.assertEqual(len(captured["messages"]), 2)
        self.assertEqual(captured["messages"][0]["role"], "user")
        self.assertIn("matching this schema", captured["messages"][-1]["content"])

    def test_prompt_loader_extracts_origin_from_full_urls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "scenario.txt"
            source.write_text(SYNTHETIC_PROMPT, encoding="utf-8")
            document = load_prompt_document(source)

        self.assertEqual(document.allowed_origins, ("https://demo.invalid",))
        self.assertEqual(
            extract_prompt_origins("Use http://127.0.0.1:8080/api?q=1 for this test."),
            {"http://127.0.0.1:8080"},
        )
        self.assertEqual(normalize_origin("https://[::1]:9443"), "https://[::1]:9443")

    def test_prompt_addenda_are_combined_and_hash_tracked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "scenario.txt"
            addendum = Path(tmp) / "semantics.md"
            source.write_text(SYNTHETIC_PROMPT, encoding="utf-8")
            addendum.write_text(
                "Treat header overrides as claims by the baseline subject.",
                encoding="utf-8",
            )
            document = load_prompt_document(source, addenda=(addendum,))

        self.assertIn("Treat header overrides", document.text)
        self.assertEqual(document.supplemental_sources, (addendum.resolve(),))
        self.assertNotEqual(document.sha256, document.primary_sha256)

    def test_inline_campaign_prompt_uses_explicit_url_and_read_only_discovery(self) -> None:
        document = build_inline_prompt_document(
            "Autonomously assess applicable authorization boundaries.",
            "https://demo.invalid/api/start",
        )
        plan = {
            "target_origin": "https://demo.invalid",
            "baseline_headers": {},
            "mutable_headers": [],
            "tests": [
                {
                    "test_id": "public_surface",
                    "name": "Public authorization surface",
                    "objective": "Discover whether protected functionality is public.",
                    "pass_condition": "Protected functionality requires authorization.",
                    "fail_condition": "Protected functionality is exposed anonymously.",
                }
            ],
            "requests": [
                {
                    "action_id": "discover_start",
                    "test_id": "public_surface",
                    "objective": "Inspect the supplied starting route.",
                    "method": "GET",
                    "path": "/api/start",
                    "header_overrides": {},
                    "body": {},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            tool = GenericHttpPlanTool(
                document,
                EventLogger(Path(tmp)),
                request_budget=10,
            )
            validated = tool.validate_plan(plan)

        self.assertTrue(document.discovery_mode)
        self.assertEqual(document.allowed_origins, ("https://demo.invalid",))
        self.assertIn("GET", document.allowed_methods)
        self.assertNotIn("POST", document.allowed_methods)
        self.assertEqual(validated["requests"][0]["path"], "/api/start")

    def test_inline_discovery_accepts_only_evidence_derived_headers(self) -> None:
        document = build_inline_prompt_document(
            "Assess authorization boundaries.",
            "https://demo.invalid/",
        )
        initial = {
            "target_origin": "https://demo.invalid",
            "baseline_headers": {},
            "mutable_headers": [],
            "tests": [
                {
                    "test_id": "role_boundary",
                    "name": "Role boundary",
                    "objective": "Assess an observed role boundary.",
                    "pass_condition": "The boundary is enforced.",
                    "fail_condition": "The boundary can be bypassed.",
                }
            ],
            "requests": [
                {
                    "action_id": "discover_root",
                    "test_id": "role_boundary",
                    "objective": "Inspect the public root.",
                    "method": "GET",
                    "path": "/",
                    "header_overrides": {},
                    "body": {},
                }
            ],
        }
        followup = {
            **initial,
            "baseline_headers": {"X-Role": "patient"},
            "mutable_headers": ["X-Role"],
            "requests": [
                {
                    "action_id": "observed_patient_role",
                    "test_id": "role_boundary",
                    "objective": "Use the role context documented by the target.",
                    "method": "GET",
                    "path": "/account",
                    "header_overrides": {"X-Role": "patient"},
                    "body": {},
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            tool = GenericHttpPlanTool(
                document,
                EventLogger(Path(tmp)),
                request_budget=10,
            )
            tool.validate_plan(initial)
            tool.observations.append(
                {
                    "response": {
                        "body": "API usage: send X-Role: patient",
                        "headers": {"content-type": "text/plain"},
                    }
                }
            )
            validated = tool.validate_plan(followup)
            unsupported = {
                **followup,
                "baseline_headers": {"X-Role": "administrator"},
                "requests": [
                    {
                        **followup["requests"][0],
                        "action_id": "invented_admin_role",
                        "header_overrides": {"X-Role": "administrator"},
                    }
                ],
            }
            with self.assertRaisesRegex(ValueError, "prior target evidence"):
                tool.validate_plan(unsupported)

        self.assertEqual(validated["baseline_headers"], {"x-role": "patient"})

    def test_valid_plan_is_derived_from_synthetic_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            tool = GenericHttpPlanTool(
                prompt_document(run_dir / "scenario.txt"),
                EventLogger(run_dir),
                request_budget=10,
            )
            plan = tool.validate_plan(valid_plan())

        self.assertEqual(plan["target_origin"], "https://demo.invalid")
        self.assertEqual(
            [request["action_id"] for request in plan["requests"]],
            ["baseline_record", "cross_record_update"],
        )
        self.assertEqual(set(tool.declared_tests), {"cross_record_write"})

    def test_rejected_batch_does_not_partially_commit_scope_or_tests(self) -> None:
        plan = valid_plan()
        plan["requests"][1]["action_id"] = plan["requests"][0]["action_id"]
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            tool = GenericHttpPlanTool(
                prompt_document(run_dir / "scenario.txt"),
                EventLogger(run_dir),
                request_budget=10,
            )
            with self.assertRaisesRegex(ValueError, "Duplicate action_id"):
                tool.validate_plan(plan)

        self.assertEqual(tool.target_origin, "")
        self.assertEqual(tool.baseline_headers, {})
        self.assertEqual(tool.declared_tests, {})

    def test_followup_cannot_change_scope_identity_or_test_definition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            tool = GenericHttpPlanTool(
                prompt_document(run_dir / "scenario.txt"),
                EventLogger(run_dir),
                request_budget=10,
            )
            tool.validate_plan(valid_plan())
            changed = valid_plan()
            changed["tests"][0]["fail_condition"] = "A different definition."
            changed["requests"] = [changed["requests"][0]]
            changed["requests"][0]["action_id"] = "new_baseline_record"
            with self.assertRaisesRegex(ValueError, "changed declared test"):
                tool.validate_plan(changed)

        self.assertEqual(
            tool.declared_tests["cross_record_write"]["fail_condition"],
            "The unauthorized update is accepted.",
        )

    def test_plan_rejects_unprompted_methods_headers_and_external_urls(self) -> None:
        cases = []

        method = valid_plan()
        method["requests"][0]["method"] = "DELETE"
        cases.append((method, "not explicitly present"))

        header = valid_plan()
        header["requests"][1]["header_overrides"] = {"X-Access-Level": "administrator"}
        cases.append((header, "values must be present"))

        external = valid_plan()
        external["requests"][0]["path"] = "https://outside.invalid/records/alpha"
        cases.append((external, "remain relative"))

        with tempfile.TemporaryDirectory() as tmp:
            for plan, expected in cases:
                run_dir = Path(tmp)
                tool = GenericHttpPlanTool(
                    prompt_document(run_dir / "scenario.txt"),
                    EventLogger(run_dir),
                    request_budget=10,
                )
                with self.subTest(expected=expected):
                    with self.assertRaisesRegex(ValueError, expected):
                        tool.validate_plan(plan)

    def test_write_requires_an_obvious_test_marker(self) -> None:
        plan = valid_plan()
        plan["requests"][1]["body"] = {"note": "ordinary update"}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            tool = GenericHttpPlanTool(
                prompt_document(run_dir / "scenario.txt"),
                EventLogger(run_dir),
                request_budget=10,
            )
            with self.assertRaisesRegex(ValueError, "test marker"):
                tool.validate_plan(plan)

    def test_recon_is_reserved_for_baseline_requests(self) -> None:
        plan = valid_plan()
        plan["tests"][0]["test_id"] = "recon"
        plan["requests"] = [plan["requests"][0]]
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            tool = GenericHttpPlanTool(
                prompt_document(run_dir / "scenario.txt"),
                EventLogger(run_dir),
                request_budget=10,
            )
            with self.assertRaisesRegex(ValueError, "reserved"):
                tool.validate_plan(plan)

    def test_debug_plan_redacts_secret_headers(self) -> None:
        logged = safe_plan_for_log(
            {
                "baseline_headers": {
                    "Authorization": "Bearer supplied-secret",
                    "X-Principal": "alice",
                },
                "requests": [
                    {
                        "header_overrides": {
                            "Authorization": "Bearer alternate-secret",
                            "X-Principal": "bob",
                        }
                    }
                ],
            }
        )
        self.assertEqual(logged["baseline_headers"]["authorization"], "<redacted>")
        self.assertEqual(
            logged["requests"][0]["header_overrides"]["authorization"],
            "<redacted>",
        )
        self.assertEqual(logged["requests"][0]["header_overrides"]["x-principal"], "bob")

    def test_assessment_validator_uses_dynamic_test_and_action_ids(self) -> None:
        assessment = {
            "overall_security_posture": "secure",
            "tests": [
                {
                    "test_id": "object_boundary",
                    "result": "PASS",
                    "root_cause": "Server-side ownership check was observed.",
                    "remediation": ["Retain the ownership check."],
                }
            ],
            "response_interpretations": [
                {
                    "action_id": "baseline_alpha",
                },
                {
                    "action_id": "attempt_beta",
                },
            ],
        }
        observations = [
            {"action_id": "baseline_alpha"},
            {"action_id": "attempt_beta"},
        ]
        self.assertEqual(
            validate_assessment(
                assessment,
                expected_test_ids={"object_boundary"},
                observations=observations,
            ),
            [],
        )

    def test_completion_budget_adapts_to_provider_tpm_limit(self) -> None:
        class RequestTooLarge(Exception):
            status_code = 413

        error = RequestTooLarge("Limit 8,000, Requested 9,287")
        self.assertEqual(reduced_completion_budget(error, 8_000), 6_457)

        unrelated = RequestTooLarge("Request body is invalid")
        unrelated.status_code = 400
        self.assertIsNone(reduced_completion_budget(unrelated, 2_000))

    def test_provider_tool_json_failure_is_retryable(self) -> None:
        class MalformedToolCall(Exception):
            status_code = 400

        self.assertTrue(
            is_tool_argument_error(
                MalformedToolCall("tool_use_failed: Failed to parse tool call arguments")
            )
        )
        self.assertFalse(is_tool_argument_error(MalformedToolCall("invalid API key")))
        self.assertTrue(
            is_json_validation_error(
                MalformedToolCall("json_validate_failed: Failed to validate JSON")
            )
        )

    def test_structural_coverage_requires_evidence_for_each_declared_test(self) -> None:
        settings = SimpleNamespace(
            groq_api_key="test-key",
            gpt_oss_model="openai/gpt-oss-120b",
        )
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            with patch(
                "medflow_redteam.authorization_agent.load_settings",
                return_value=settings,
            ):
                agent = GenericAuthorizationAgent(
                    prompt_document(run_dir / "scenario.txt"),
                    EventLogger(run_dir),
                )
            agent.http_tool.declared_tests = {
                "object_boundary": {
                    "test_id": "object_boundary",
                    "name": "Object boundary",
                }
            }
            agent.http_tool.observations = [
                {
                    "action_id": "baseline",
                    "test_id": "recon",
                    "response": {"status": 200},
                }
            ]

            gaps = agent.structural_coverage_gaps()

        self.assertEqual(
            gaps,
            ["Declared test 'object_boundary' has no executed evidence."],
        )

    def test_discovery_scope_guard_prevents_false_secure_posture(self) -> None:
        settings = SimpleNamespace(
            groq_api_key="test-key",
            qwen_model="qwen/qwen3.6-27b",
        )
        document = build_inline_prompt_document(
            "Assess the authorized application.",
            "https://demo.invalid/",
        )
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            with patch(
                "medflow_redteam.authorization_agent.load_settings",
                return_value=settings,
            ):
                agent = GenericAuthorizationAgent(
                    document,
                    EventLogger(run_dir),
                    provider="qwen",
                )
            agent.http_tool.observations = [
                {
                    "response": {
                        "status": 401,
                    }
                }
            ]
            guarded = agent.apply_discovery_scope_guard(
                {
                    "overall_security_posture": "secure",
                    "executive_summary": "The tested request was denied.",
                    "limitations": [],
                }
            )

        self.assertEqual(guarded["overall_security_posture"], "inconclusive")
        self.assertIn("authenticated context", guarded["limitations"][0])
        self.assertTrue(
            guarded["executive_summary"].startswith(
                "Overall scope is inconclusive"
            )
        )

    def test_long_provider_reset_window_is_parsed(self) -> None:
        self.assertEqual(
            retry_duration_from_message("Please try again in 30m6.624s."),
            1_806.624,
        )
        self.assertEqual(
            retry_duration_from_message("Please try again in 53.88s."),
            53.88,
        )

    def test_model_evidence_is_bounded_while_preserving_each_response(self) -> None:
        observations = []
        for index in range(3):
            observations.append(
                {
                    "action_id": f"action_{index}",
                    "test_id": "dynamic_test",
                    "objective": "Inspect behavior.",
                    "request": {
                        "method": "GET",
                        "path": f"/objects/{index}",
                        "headers": {"x-principal": "alice"},
                        "header_overrides": {},
                        "body": {},
                    },
                    "response": {
                        "status": 200,
                        "headers": {
                            "content-type": "application/json",
                            "server": "not-needed-by-model",
                        },
                        "body": "x" * 1_000,
                        "body_sha256": "abc",
                        "body_bytes": 1_000,
                        "elapsed_ms": 1.0,
                        "transport_error": "",
                    },
                }
            )

        compact = compact_observations(
            observations,
            total_body_chars=120,
            per_body_chars=100,
        )
        self.assertEqual(len(compact), 3)
        self.assertLessEqual(
            sum(len(item["response"]["body"]) for item in compact),
            120,
        )
        self.assertEqual(
            compact[0]["response"]["headers"],
            {"content-type": "application/json"},
        )

    def test_independent_audit_can_correct_a_semantic_verdict(self) -> None:
        tests = [
            {
                "test_id": "role_boundary",
                "result": "PASS",
                "summary": "Claimed role was allowed.",
                "root_cause": "No issue.",
                "vulnerability_classification": [],
                "remediation": ["Retain controls."],
            }
        ]
        interpretations = [
            {
                "action_id": "claim_elevated_role",
                "observed_behavior": "Protected data was returned.",
                "authorization_outcome": "allowed",
                "security_significance": "No issue.",
            }
        ]
        audit = {
            "test_reviews": [
                {
                    "test_id": "role_boundary",
                    "result": "FAIL",
                    "summary": "The baseline subject gained access through an untrusted claim.",
                    "root_cause": "Behavior is consistent with trusting a client claim.",
                    "vulnerability_classification": [
                        {
                            "name": "Broken Access Control",
                            "cwe": "CWE-284",
                            "owasp": "A01:2021",
                        }
                    ],
                    "remediation": ["Derive privileges from an authenticated principal."],
                }
            ],
            "action_reviews": [
                {
                    "action_id": "claim_elevated_role",
                    "authorization_outcome": "allowed",
                    "security_significance": "Unauthorized function access.",
                }
            ],
        }
        corrected_tests, corrected_interpretations = apply_verdict_audit(
            tests,
            interpretations,
            audit,
            expected_test_ids=["role_boundary"],
            expected_action_ids=["claim_elevated_role"],
        )
        self.assertEqual(corrected_tests[0]["result"], "FAIL")
        self.assertIn(
            "Unauthorized",
            corrected_interpretations[0]["security_significance"],
        )


if __name__ == "__main__":
    unittest.main()
