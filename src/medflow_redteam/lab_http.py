from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit

from .tools import validate_target


def validate_lab_url(value: str) -> str:
    """Return a normalized HTTP URL only when its host is in the lab allowlist."""
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Lab URL must use http or https.")
    if not parsed.hostname:
        raise ValueError("Lab URL requires a hostname.")
    if parsed.username or parsed.password:
        raise ValueError("Credentials must not be embedded in a lab URL.")
    if parsed.query or parsed.fragment:
        raise ValueError("Lab base URL must not contain a query string or fragment.")
    validate_target(parsed.hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Lab URL contains an invalid port.") from exc
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    netloc = f"{host}:{port}" if port else host
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, netloc, path, "", ""))


def same_origin_url(base_url: str, endpoint: str) -> str:
    base = validate_lab_url(base_url)
    target = urljoin(base.rstrip("/") + "/", endpoint)
    base_parts = urlsplit(base)
    target_parts = urlsplit(target)
    if (
        target_parts.scheme,
        target_parts.hostname,
        target_parts.port,
    ) != (
        base_parts.scheme,
        base_parts.hostname,
        base_parts.port,
    ):
        raise ValueError("Endpoint must remain on the authorized lab origin.")
    if target_parts.username or target_parts.password or target_parts.fragment:
        raise ValueError("Endpoint contains unsupported URL components.")
    return target


def load_wordlist(
    paths: Iterable[str | Path],
    *,
    limit: int,
    keep_comments: bool = False,
    allowed_roots: Iterable[str | Path] | None = None,
) -> tuple[list[str], list[dict[str, Any]]]:
    values: list[str] = []
    seen: set[str] = set()
    sources: list[dict[str, Any]] = []
    roots = [
        Path(root).expanduser().resolve()
        for root in (allowed_roots or [])
    ]
    for raw_path in paths:
        path = Path(raw_path).expanduser().resolve()
        if roots and not any(path.is_relative_to(root) for root in roots):
            raise ValueError(
                f"Wordlist path must stay inside: {', '.join(str(root) for root in roots)}"
            )
        if not path.is_file():
            raise FileNotFoundError(f"Wordlist not found: {path}")
        digest = hashlib.sha256()
        accepted = 0
        with path.open("rb") as handle:
            for raw_line in handle:
                digest.update(raw_line)
                if len(values) >= limit:
                    continue
                value = raw_line.decode("utf-8", errors="ignore").strip()
                if not value or (not keep_comments and value.startswith("#")):
                    continue
                if value in seen:
                    continue
                seen.add(value)
                values.append(value)
                accepted += 1
        sources.append(
            {
                "path": str(path),
                "sha256": digest.hexdigest(),
                "accepted_entries": accepted,
            }
        )
    return values, sources


def write_jsonl(path: str | Path | None, rows: Iterable[dict[str, Any]]) -> str | None:
    if path is None:
        return None
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, default=str))
            handle.write("\n")
    return str(output)
