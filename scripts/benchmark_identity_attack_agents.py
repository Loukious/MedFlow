from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import httpx

from medflow_redteam.lab_http import load_wordlist, same_origin_url, validate_lab_url
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


def seed_juice_shop_fixture(
    target_url: str,
    *,
    usernames: list[str],
    fixture_password: str,
) -> list[dict[str, str | int]]:
    """Create disposable synthetic accounts for this benchmark only."""
    registration_url = same_origin_url(target_url, "/api/Users")
    login_url = same_origin_url(target_url, "/rest/user/login")
    results = []
    with httpx.Client(timeout=5, follow_redirects=False) as client:
        for username in usernames:
            identity = f"{username}@medflow-agent.test"
            response = client.post(
                registration_url,
                json={
                    "email": identity,
                    "password": fixture_password,
                    "passwordRepeat": fixture_password,
                },
            )
            if response.status_code == 201:
                status = "created"
            else:
                login = client.post(
                    login_url,
                    json={"email": identity, "password": fixture_password},
                )
                if login.status_code != 200:
                    raise RuntimeError(
                        f"Could not create or verify synthetic account {identity}: "
                        f"registration={response.status_code}, login={login.status_code}"
                    )
                status = "existing_verified"
            results.append(
                {
                    "identity": identity,
                    "status": status,
                    "registration_status": response.status_code,
                }
            )
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the two generic identity agents against a disposable OWASP Juice Shop "
            "fixture. Execute this inside the lab network namespace when the Docker "
            "network is internal."
        )
    )
    parser.add_argument("--url", default="http://172.19.0.2:3000/")
    parser.add_argument("--max-wordlist-passwords", type=int, default=10)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/identity_agent_benchmark"),
    )
    args = parser.parse_args()
    target_url = validate_lab_url(args.url)
    usernames, _ = load_wordlist(DEFAULT_USERNAME_WORDLISTS, limit=3)
    passwords, _ = load_wordlist(DEFAULT_PASSWORD_WORDLISTS, limit=2)
    if len(usernames) < 3 or len(passwords) < 2:
        raise RuntimeError("Downloaded SecLists subset is incomplete.")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    seeded = seed_juice_shop_fixture(
        target_url,
        usernames=usernames,
        fixture_password=passwords[1],
    )
    wordlist = WordlistAttackAgent(
        WordlistAttackConfig(
            target_url=target_url,
            endpoint="/rest/user/login",
            username=f"{usernames[0]}@medflow-agent.test",
            password_wordlist_paths=list(DEFAULT_WORDLIST_PASSWORD_WORDLISTS),
            username_field="email",
            password_field="password",
            success_json_paths=("authentication.token",),
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
            endpoint="/rest/user/login",
            username_wordlist_paths=list(DEFAULT_USERNAME_WORDLISTS),
            password_wordlist_paths=list(DEFAULT_PASSWORD_WORDLISTS),
            username_template="{username}@medflow-agent.test",
            username_field="email",
            password_field="password",
            success_json_paths=("authentication.token",),
            max_users=3,
            max_passwords=2,
            max_attempts=6,
            delay_seconds=0.1,
            timeout_seconds=10,
            execution_mode="aggressive_lab",
            execute=True,
            trace_path=args.output_dir / f"password_spray_attempts_{stamp}.jsonl",
        )
    ).run()
    payload = {
        "lab": "OWASP Juice Shop",
        "target_url": target_url,
        "synthetic_accounts": seeded,
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
