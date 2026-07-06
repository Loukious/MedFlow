from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from medflow_graph.memory import GraphStore
from medflow_redteam.campaign import http_ports_from_services, observation_status
from medflow_redteam.capabilities import capability_match_score, select_capabilities_for_services
from medflow_redteam.generated_tools import load_generated_tool_specs, resolve_generated_tool_code, validate_generated_tool_code
from medflow_redteam.identity import analyze_identity_logs
from medflow_redteam.tools import normalize_validation_status, web_control_checks


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


if __name__ == "__main__":
    unittest.main()
