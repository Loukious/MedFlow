from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from medflow_redteam.password_spray_agent import (
    DEFAULT_PASSWORD_WORDLISTS,
    DEFAULT_USERNAME_WORDLISTS,
    PasswordSprayAgent,
    PasswordSprayConfig,
)


def parse_json_object(value: str) -> dict:
    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise argparse.ArgumentTypeError("Expected a JSON object.")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run a bounded, lockout-aware password spray against an allowlisted lab URL. "
            "Passwords and response values are never persisted."
        )
    )
    parser.add_argument("url")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--username-wordlist", action="append", type=Path)
    parser.add_argument("--password-wordlist", action="append", type=Path)
    parser.add_argument("--username-template", default="{username}")
    parser.add_argument("--username-field", default="username")
    parser.add_argument("--password-field", default="password")
    parser.add_argument("--request-format", choices=["json", "form"], default="json")
    parser.add_argument("--static-fields", type=parse_json_object, default={})
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--success-json-path", action="append", default=[])
    parser.add_argument("--success-status", action="append", type=int, default=[])
    parser.add_argument("--failure-status", action="append", type=int, default=[])
    parser.add_argument("--max-users", type=int, default=10)
    parser.add_argument("--max-passwords", type=int, default=3)
    parser.add_argument("--max-attempts", type=int, default=30)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--stop-after-successes", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--trace", type=Path)
    parser.add_argument(
        "--execution-mode",
        choices=["safe", "aggressive_lab"],
        default="safe",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Required acknowledgement for sending authentication attempts.",
    )
    args = parser.parse_args()
    headers = {}
    for item in args.header:
        if ":" not in item:
            parser.error("--header values must use NAME:VALUE.")
        name, value = item.split(":", 1)
        headers[name.strip()] = value.strip()
    trace = args.trace or Path(
        f"reports/identity_agents/password_spray_attempts_{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
    )
    result = PasswordSprayAgent(
        PasswordSprayConfig(
            target_url=args.url,
            endpoint=args.endpoint,
            username_wordlist_paths=(
                args.username_wordlist or list(DEFAULT_USERNAME_WORDLISTS)
            ),
            password_wordlist_paths=(
                args.password_wordlist or list(DEFAULT_PASSWORD_WORDLISTS)
            ),
            username_template=args.username_template,
            username_field=args.username_field,
            password_field=args.password_field,
            request_format=args.request_format,
            static_fields=args.static_fields,
            headers=headers,
            success_statuses=tuple(args.success_status or [200]),
            failure_statuses=tuple(args.failure_status or [400, 401, 403]),
            success_json_paths=tuple(args.success_json_path),
            max_users=args.max_users,
            max_passwords=args.max_passwords,
            max_attempts=args.max_attempts,
            delay_seconds=args.delay,
            timeout_seconds=args.timeout,
            stop_after_successes=args.stop_after_successes,
            verify_tls=not args.insecure,
            execution_mode=args.execution_mode,
            execute=args.execute,
            trace_path=trace,
        )
    ).run()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
