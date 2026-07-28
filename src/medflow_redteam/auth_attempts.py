from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import httpx


MAX_AUTH_RESPONSE_BYTES = 128 * 1024


def validate_auth_contract(
    *,
    username_field: str,
    password_field: str,
    request_format: str,
    success_statuses: tuple[int, ...],
    failure_statuses: tuple[int, ...],
    success_json_paths: tuple[str, ...],
    headers: dict[str, str],
) -> None:
    if request_format not in {"json", "form"}:
        raise ValueError("request_format must be json or form.")
    if not username_field.strip() or not password_field.strip():
        raise ValueError("Authentication field names must not be empty.")
    if username_field == password_field:
        raise ValueError("Username and password fields must be different.")
    if not success_statuses:
        raise ValueError("At least one success status is required.")
    statuses = [*success_statuses, *failure_statuses]
    if any(status < 100 or status > 599 for status in statuses):
        raise ValueError("Authentication status codes must be between 100 and 599.")
    overlap = set(success_statuses) & set(failure_statuses)
    if overlap:
        raise ValueError(
            f"Success and failure status sets overlap: {sorted(overlap)}"
        )
    if any(not path.strip() for path in success_json_paths):
        raise ValueError("Success JSON paths must not be empty.")
    forbidden_headers = {
        name.lower()
        for name in headers
        if name.lower() in {"host", "content-length", "transfer-encoding"}
    }
    if forbidden_headers:
        raise ValueError(
            "Authentication headers cannot override: "
            + ", ".join(sorted(forbidden_headers))
        )


def json_path_present(payload: Any, path: str) -> bool:
    value = payload
    for part in path.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return False
    return value is not None and value != "" and value is not False


def response_keys(
    value: Any,
    *,
    prefix: str = "",
    limit: int = 40,
) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            keys.append(path)
            if len(keys) >= limit:
                break
            keys.extend(
                response_keys(
                    nested,
                    prefix=path,
                    limit=limit - len(keys),
                )
            )
            if len(keys) >= limit:
                break
    elif isinstance(value, list) and value and limit:
        keys.extend(
            response_keys(
                value[0],
                prefix=f"{prefix}[]" if prefix else "[]",
                limit=limit,
            )
        )
    return keys[:limit]


def classify_auth_response(
    response: httpx.Response,
    *,
    success_statuses: tuple[int, ...],
    failure_statuses: tuple[int, ...],
    success_json_paths: tuple[str, ...],
    body: bytes | None = None,
) -> tuple[str, list[str]]:
    if response.status_code in {423, 429}:
        return "lockout_detected", []
    payload: Any = None
    keys: list[str] = []
    try:
        payload = (
            json.loads(body.decode("utf-8", errors="strict"))
            if body is not None
            else response.json()
        )
        keys = response_keys(payload)
    except (UnicodeDecodeError, ValueError):
        pass
    if response.status_code in failure_statuses:
        return "rejected", keys
    if response.status_code in success_statuses:
        if success_json_paths and not any(
            json_path_present(payload, path) for path in success_json_paths
        ):
            return "inconclusive", keys
        return "authenticated", keys
    if response.status_code >= 500:
        return "server_error", keys
    return "inconclusive", keys


def execute_auth_attempt(
    client: httpx.Client,
    *,
    endpoint: str,
    identity: str,
    password: str,
    username_index: int,
    password_index: int,
    username_field: str,
    password_field: str,
    request_format: str,
    static_fields: dict[str, Any],
    success_statuses: tuple[int, ...],
    failure_statuses: tuple[int, ...],
    success_json_paths: tuple[str, ...],
) -> dict[str, Any]:
    body = {
        **static_fields,
        username_field: identity,
        password_field: password,
    }
    started = time.perf_counter()
    try:
        kwargs = {"json": body} if request_format == "json" else {"data": body}
        with client.stream("POST", endpoint, **kwargs) as response:
            response_body = bytearray()
            truncated = False
            for chunk in response.iter_bytes():
                remaining = MAX_AUTH_RESPONSE_BYTES - len(response_body)
                if remaining <= 0:
                    truncated = True
                    break
                response_body.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break
            safe_body = bytes(response_body)
            outcome, keys = classify_auth_response(
                response,
                success_statuses=success_statuses,
                failure_statuses=failure_statuses,
                success_json_paths=success_json_paths,
                body=safe_body,
            )
            return {
                "username": identity,
                "username_index": username_index,
                "password_index": password_index,
                "status": response.status_code,
                "outcome": outcome,
                "response_keys": keys,
                "response_sha256": hashlib.sha256(safe_body).hexdigest(),
                "response_truncated": truncated,
                "retry_after": response.headers.get("retry-after", ""),
                "elapsed_ms": round((time.perf_counter() - started) * 1_000, 2),
            }
    except httpx.HTTPError as exc:
        return {
            "username": identity,
            "username_index": username_index,
            "password_index": password_index,
            "outcome": "transport_error",
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": round((time.perf_counter() - started) * 1_000, 2),
        }
