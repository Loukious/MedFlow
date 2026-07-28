from __future__ import annotations

import argparse
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

from medflow_redteam.config_loader import ROOT
from medflow_redteam.lab_http import load_wordlist
from medflow_redteam.password_spray_agent import (
    DEFAULT_PASSWORD_WORDLISTS,
    DEFAULT_USERNAME_WORDLISTS,
)


MAX_REQUEST_BYTES = 64 * 1024


def load_fixture_accounts() -> dict[str, str]:
    usernames, _ = load_wordlist(
        [ROOT / path for path in DEFAULT_USERNAME_WORDLISTS],
        limit=4,
        allowed_roots=[ROOT / "data" / "wordlists"],
    )
    passwords, _ = load_wordlist(
        [ROOT / path for path in DEFAULT_PASSWORD_WORDLISTS],
        limit=2,
        allowed_roots=[ROOT / "data" / "wordlists"],
    )
    if len(usernames) < 4 or len(passwords) < 2:
        raise RuntimeError(
            "The SecLists subset is incomplete. Run "
            "scripts/download_redteam_wordlists.py first."
        )
    return {username: passwords[1] for username in usernames[1:4]}


class IdentityLabHandler(BaseHTTPRequestHandler):
    accounts: dict[str, str] = {}

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        if self.path == "/":
            self.send_body(
                200,
                """
<!doctype html>
<html>
  <head><title>Authorized Identity Training Lab</title></head>
  <body>
    <form method="post" action="/login">
      <label>Username <input name="username" autocomplete="username"></label>
      <label>Password <input name="password" type="password"></label>
      <button type="submit">Sign in</button>
    </form>
    <a href="/openapi.json">API description</a>
  </body>
</html>
""".strip().encode(),
                "text/html; charset=utf-8",
            )
            return
        if self.path == "/openapi.json":
            self.send_json(
                200,
                {
                    "openapi": "3.0.3",
                    "paths": {
                        "/login": {
                            "post": {
                                "requestBody": {
                                    "content": {
                                        "application/json": {
                                            "schema": {
                                                "required": [
                                                    "username",
                                                    "password",
                                                ],
                                                "properties": {
                                                    "username": {
                                                        "type": "string"
                                                    },
                                                    "password": {
                                                        "type": "string"
                                                    },
                                                },
                                            }
                                        }
                                    }
                                },
                                "responses": {
                                    "200": {
                                        "description": "Authentication accepted",
                                    },
                                    "401": {
                                        "description": "Invalid credentials",
                                    },
                                },
                            }
                        }
                    },
                },
            )
            return
        if self.path == "/health":
            self.send_json(
                200,
                {
                    "status": "ok",
                    "synthetic_accounts": sorted(self.accounts),
                },
            )
            return
        self.send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != "/login":
            self.send_json(404, {"error": "not_found"})
            return
        try:
            payload = self.read_payload()
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "invalid_request"})
            return
        username = str(payload.get("username") or "")
        password = str(payload.get("password") or "")
        expected = self.accounts.get(username)
        if expected is not None and hmac.compare_digest(password, expected):
            self.send_json(
                200,
                {
                    "authentication": {
                        "accepted": True,
                        "username": username,
                    }
                },
            )
            return
        self.send_json(401, {"error": "invalid_credentials"})

    def read_payload(self) -> dict[str, Any]:
        length = int(self.headers.get("content-length", "0"))
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("Request body is outside the fixture limit.")
        body = self.rfile.read(length)
        content_type = self.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("JSON body must be an object.")
            return payload
        parsed = parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
            max_num_fields=20,
        )
        return {key: values[-1] for key, values in parsed.items()}

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        self.send_body(
            status,
            json.dumps(payload, separators=(",", ":")).encode(),
            "application/json",
        )

    def send_body(
        self,
        status: int,
        body: bytes,
        content_type: str,
    ) -> None:
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the loopback-only MedFlow identity training fixture."
    )
    parser.add_argument("--host", choices=["127.0.0.1"], default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3000)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535.")

    IdentityLabHandler.accounts = load_fixture_accounts()
    server = ThreadingHTTPServer((args.host, args.port), IdentityLabHandler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
