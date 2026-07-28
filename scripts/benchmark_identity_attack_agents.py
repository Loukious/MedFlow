from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from medflow_redteam.lab_http import load_wordlist, validate_lab_url
from medflow_redteam.password_spray_agent import (
    DEFAULT_PASSWORD_WORDLISTS,
    DEFAULT_USERNAME_WORDLISTS,
    PasswordSprayAgent,
    PasswordSprayConfig,
)
from medflow_redteam.wordlist_attack_agent import (
    DEFAULT_PASSWORD_WORDLISTS as DEFAULT_WORDLIST_PASSWORD_WORDLISTS,
    WordlistAttackAgent,
    WordlistAttackConfig,
)

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the two generic identity agents against the loopback-only "
            "username/password training fixture."
        )
    )
    parser.add_argument("--url", default="http://172.19.0.2:3000/")
    parser.add_argument("--max-wordlist-passwords", type=int, default=10)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/plain_identity_agent_benchmark"),
    )
    args = parser.parse_args()
    target_url = validate_lab_url(args.url)
    usernames, _ = load_wordlist(DEFAULT_USERNAME_WORDLISTS, limit=4)
    passwords, _ = load_wordlist(DEFAULT_PASSWORD_WORDLISTS, limit=2)
    if len(usernames) < 4 or len(passwords) < 2:
        raise RuntimeError("Downloaded SecLists subset is incomplete.")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    wordlist = WordlistAttackAgent(
        WordlistAttackConfig(
            target_url=target_url,
            endpoint="/login",
            username=usernames[2],
            password_wordlist_paths=list(DEFAULT_WORDLIST_PASSWORD_WORDLISTS),
            username_field="username",
            password_field="password",
            success_json_paths=("authentication.accepted",),
            max_passwords=args.max_wordlist_passwords,
            max_attempts=args.max_wordlist_passwords,
            delay_seconds=0.1,
            timeout_seconds=10,
            execution_mode="aggressive_lab",
            execute=True,
            trace_path=args.output_dir / f"wordlist_attempts_{stamp}.jsonl",
        )
    ).run()
    time.sleep(0.5)
    spray = PasswordSprayAgent(
        PasswordSprayConfig(
            target_url=target_url,
            endpoint="/login",
            username_wordlist_paths=list(DEFAULT_USERNAME_WORDLISTS),
            password_wordlist_paths=list(DEFAULT_PASSWORD_WORDLISTS),
            username_field="username",
            password_field="password",
            success_json_paths=("authentication.accepted",),
            max_users=4,
            max_passwords=2,
            max_attempts=8,
            delay_seconds=0.1,
            timeout_seconds=10,
            execution_mode="aggressive_lab",
            execute=True,
            trace_path=args.output_dir / f"password_spray_attempts_{stamp}.jsonl",
        )
    ).run()
    payload = {
        "lab": "MedFlow loopback identity fixture",
        "target_url": target_url,
        "synthetic_accounts": usernames[1:4],
        "wordlist_attack": wordlist,
        "password_spray": spray,
        "passed": wordlist["successful"] > 0 and spray["successful"] > 0,
    }
    report = args.output_dir / f"benchmark_{stamp}.json"
    report.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({**payload, "report": str(report)}, indent=2))
    if not payload["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
