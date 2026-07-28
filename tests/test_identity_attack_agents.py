from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from medflow_redteam.lab_http import load_wordlist, validate_lab_url
from medflow_redteam.password_spray_agent import (
    PasswordSprayAgent,
    PasswordSprayConfig,
)
from medflow_redteam.wordlist_attack_agent import (
    WordlistAttackAgent,
    WordlistAttackConfig,
)
from medflow_ti.embeddings import _local_model_path


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        payload = json.loads(self.rfile.read(length))
        if payload.get("email") == "locked@medflow.test":
            body = b'{"error":"Too many attempts"}'
            status = 429
        elif (
            self.path == "/login"
            and payload.get("email") == "test@medflow.test"
            and payload.get("password") == "password"
        ):
            body = b'{"authentication":{"token":"must-not-be-retained"}}'
            status = 200
        else:
            body = b'{"error":"Invalid credentials"}'
            status = 401
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class IdentityAttackAgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_lab_scope_rejects_public_targets(self) -> None:
        with self.assertRaises(ValueError):
            validate_lab_url("https://example.com/")

    def test_wordlist_loader_rejects_paths_outside_allowed_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "allowed"
            allowed.mkdir()
            outside = root / "outside.txt"
            outside.write_text("do-not-read\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_wordlist(
                    [outside],
                    limit=1,
                    allowed_roots=[allowed],
                )

    def test_cached_embedding_snapshot_resolves_without_remote_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = "abc123"
            snapshot = (
                root
                / "models--example--model"
                / "snapshots"
                / revision
            )
            snapshot.mkdir(parents=True)
            (snapshot / "modules.json").write_text("[]", encoding="utf-8")
            (snapshot / "config.json").write_text("{}", encoding="utf-8")
            (snapshot / "tokenizer.json").write_text("{}", encoding="utf-8")
            (snapshot / "model.safetensors").write_bytes(b"fixture")
            refs = root / "models--example--model" / "refs"
            refs.mkdir()
            (refs / "main").write_text(revision, encoding="utf-8")
            self.assertEqual(
                _local_model_path("example/model", root),
                snapshot,
            )

    def test_wordlist_agent_tries_many_passwords_for_one_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secrets = root / "secrets.txt"
            secrets.write_text("123456\npassword\n", encoding="utf-8")
            blocked = WordlistAttackConfig(
                target_url=self.url,
                endpoint="/login",
                username="test@medflow.test",
                password_wordlist_paths=[secrets],
                wordlist_roots=(root,),
            )
            with self.assertRaises(PermissionError):
                WordlistAttackAgent(blocked).run()

            trace = root / "wordlist.jsonl"
            result = WordlistAttackAgent(
                WordlistAttackConfig(
                    target_url=self.url,
                    endpoint="/login",
                    username="test@medflow.test",
                    password_wordlist_paths=[secrets],
                    wordlist_roots=(root,),
                    username_field="email",
                    success_json_paths=("authentication.token",),
                    max_passwords=2,
                    max_attempts=2,
                    delay_seconds=0,
                    execution_mode="aggressive_lab",
                    execute=True,
                    trace_path=trace,
                )
            ).run()
            self.assertEqual(result["attempted"], 2)
            self.assertEqual(result["successful"], 1)
            self.assertEqual(result["successes"][0]["password_index"], 2)
            trace_text = trace.read_text(encoding="utf-8")
            self.assertNotIn("123456", trace_text)
            self.assertNotIn("must-not-be-retained", trace_text)
            self.assertNotIn('"password":', trace_text)

    def test_password_spray_is_gated_and_does_not_retain_passwords(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            users = root / "users.txt"
            secrets = root / "secrets.txt"
            users.write_text("other\ntest\n", encoding="utf-8")
            secrets.write_text("password\n", encoding="utf-8")
            blocked = PasswordSprayConfig(
                target_url=self.url,
                endpoint="/login",
                username_wordlist_paths=[users],
                password_wordlist_paths=[secrets],
                wordlist_roots=(root,),
            )
            with self.assertRaises(PermissionError):
                PasswordSprayAgent(blocked).run()

            trace = root / "spray.jsonl"
            result = PasswordSprayAgent(
                PasswordSprayConfig(
                    target_url=self.url,
                    endpoint="/login",
                    username_wordlist_paths=[users],
                    password_wordlist_paths=[secrets],
                    wordlist_roots=(root,),
                    username_template="{username}@medflow.test",
                    username_field="email",
                    success_json_paths=("authentication.token",),
                    max_users=2,
                    max_passwords=1,
                    max_attempts=2,
                    delay_seconds=0,
                    execution_mode="aggressive_lab",
                    execute=True,
                    trace_path=trace,
                )
            ).run()
            self.assertEqual(result["attempted"], 2)
            self.assertEqual(result["successful"], 1)
            self.assertEqual(result["successes"][0]["username_index"], 2)
            self.assertEqual(result["successes"][0]["password_index"], 1)
            trace_text = trace.read_text(encoding="utf-8")
            self.assertNotIn("123456", trace_text)
            self.assertNotIn("must-not-be-retained", trace_text)
            self.assertNotIn('"password":', trace_text)

    def test_wordlist_agent_stops_on_rate_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secrets = root / "secrets.txt"
            secrets.write_text("one\ntwo\nthree\n", encoding="utf-8")
            result = WordlistAttackAgent(
                WordlistAttackConfig(
                    target_url=self.url,
                    endpoint="/login",
                    username="locked@medflow.test",
                    password_wordlist_paths=[secrets],
                    wordlist_roots=(root,),
                    username_field="email",
                    max_passwords=3,
                    max_attempts=3,
                    delay_seconds=0,
                    execution_mode="aggressive_lab",
                    execute=True,
                )
            ).run()
            self.assertEqual(result["attempted"], 1)
            self.assertEqual(result["status"], "lockout_observed")
            self.assertTrue(result["lockout_detected"])


if __name__ == "__main__":
    unittest.main()
