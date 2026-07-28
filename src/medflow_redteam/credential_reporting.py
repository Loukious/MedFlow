from __future__ import annotations

from typing import Any


REDACTED_PASSWORD = "<redacted-from-llm-and-traces>"


def redact_plaintext_passwords(value: Any) -> Any:
    """Copy nested report data while replacing explicitly retained passwords."""

    if isinstance(value, dict):
        return {
            key: (
                REDACTED_PASSWORD
                if str(key).casefold() == "password"
                else redact_plaintext_passwords(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_plaintext_passwords(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_plaintext_passwords(item) for item in value)
    return value


def collect_revealed_credentials(
    wordlist_result: Any,
    spray_result: Any,
) -> list[dict[str, Any]]:
    credentials: list[dict[str, Any]] = []
    for attack, raw_result in (
        ("Password wordlist", wordlist_result),
        ("Password spray", spray_result),
    ):
        if not isinstance(raw_result, dict):
            continue
        successes = raw_result.get("successes")
        if not isinstance(successes, list):
            continue
        for success in successes:
            if not isinstance(success, dict) or "password" not in success:
                continue
            credentials.append(
                {
                    "attack": attack,
                    "username": str(success.get("username") or ""),
                    "password": str(success.get("password") or ""),
                    "endpoint": str(raw_result.get("endpoint") or ""),
                    "password_index": success.get("password_index"),
                    "status": success.get("status"),
                }
            )
    return credentials
