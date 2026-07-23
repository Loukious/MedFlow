from __future__ import annotations

import fcntl
import hashlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from .config_loader import ROOT


REGISTRY_PATH = ROOT / "data" / "generated_tools" / "quality_registry.json"
QUALITY_POLICY_VERSION = 1
QUALITY_STATES = {
    "candidate",
    "fixture_passed",
    "shadow",
    "trusted",
    "degraded",
    "quarantined",
}
EXECUTABLE_STATES = {"shadow", "trusted", "degraded"}
FINDING_STATES = {"trusted"}
STATE_BASE_SCORE = {
    "candidate": 0.0,
    "fixture_passed": 0.25,
    "shadow": 0.45,
    "trusted": 0.8,
    "degraded": 0.15,
    "quarantined": 0.0,
}
RUNTIME_SPEC_FIELDS = {
    "artifact_hash",
    "code_path",
    "execution",
    "matched_service",
    "quality",
    "quality_score",
    "quality_state",
    "quality_stats",
    "reasons",
    "score",
    "score_explanation",
    "source",
}


def artifact_hash(code: str, spec: dict[str, Any]) -> str:
    canonical_spec = {
        key: value
        for key, value in spec.items()
        if key not in RUNTIME_SPEC_FIELDS and not key.startswith("quality_")
    }
    payload = code.encode("utf-8") + b"\0" + json.dumps(
        canonical_spec,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_quality_registry(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": 1, "policy_version": QUALITY_POLICY_VERSION, "artifacts": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": 1, "policy_version": QUALITY_POLICY_VERSION, "artifacts": {}}
    payload.setdefault("schema_version", 1)
    payload.setdefault("policy_version", QUALITY_POLICY_VERSION)
    payload.setdefault("artifacts", {})
    return payload


def save_quality_registry(registry: dict[str, Any], path: Path = REGISTRY_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(registry, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def register_artifact(
    spec: dict[str, Any],
    code_path: Path,
    *,
    initial_state: str = "candidate",
    registry_path: Path = REGISTRY_PATH,
) -> dict[str, Any]:
    if initial_state not in QUALITY_STATES:
        raise ValueError(f"Unknown generated-tool quality state: {initial_state}")
    code = code_path.read_text(encoding="utf-8")
    digest = artifact_hash(code, spec)
    declared = str(spec.get("artifact_hash") or "")
    if declared and declared != digest:
        raise ValueError("Generated-tool artifact hash does not match its code and specification.")
    with registry_write_lock(registry_path):
        registry = load_quality_registry(registry_path)
        now = utc_now()
        entry = registry["artifacts"].get(digest)
        if entry is None:
            entry = {
                "artifact_hash": digest,
                "tool_id": str(spec.get("id") or ""),
                "code_path": str(code_path),
                "state": initial_state,
                "created_at": now,
                "updated_at": now,
                "policy_version": QUALITY_POLICY_VERSION,
                "stats": empty_stats(),
                "evidence": {},
                "history": [
                    {
                        "at": now,
                        "action": "registered",
                        "state": initial_state,
                        "reason": "Generated tool entered the quality registry.",
                    }
                ],
                "spec_snapshot": {
                    key: value
                    for key, value in spec.items()
                    if key not in RUNTIME_SPEC_FIELDS and not key.startswith("quality_")
                },
            }
            registry["artifacts"][digest] = entry
            save_quality_registry(registry, registry_path)
        elif int(entry.get("policy_version") or 0) != QUALITY_POLICY_VERSION:
            previous = str(entry.get("state") or "candidate")
            entry["policy_version"] = QUALITY_POLICY_VERSION
            entry["state"] = "degraded" if previous in EXECUTABLE_STATES else "candidate"
            entry["updated_at"] = now
            entry.setdefault("history", []).append(
                {
                    "at": now,
                    "action": "policy_changed",
                    "from": previous,
                    "state": entry["state"],
                    "reason": "Quality policy changed; cached tool requires revalidation.",
                }
            )
            registry["artifacts"][digest] = entry
            save_quality_registry(registry, registry_path)
    return enrich_entry(entry)


def quality_for_spec(
    spec: dict[str, Any],
    code_path: Path,
    *,
    initial_state: str = "candidate",
    registry_path: Path = REGISTRY_PATH,
) -> dict[str, Any]:
    return register_artifact(spec, code_path, initial_state=initial_state, registry_path=registry_path)


def set_quality_state(
    reference: str,
    state: str,
    *,
    reason: str,
    force: bool = False,
    registry_path: Path = REGISTRY_PATH,
) -> dict[str, Any]:
    if state not in QUALITY_STATES:
        raise ValueError(f"Unknown generated-tool quality state: {state}")
    with registry_write_lock(registry_path):
        registry = load_quality_registry(registry_path)
        digest, entry = resolve_entry(registry, reference)
        current = str(entry.get("state") or "candidate")
        allowed = {
            "candidate": {"quarantined"},
            "fixture_passed": {"shadow", "candidate", "quarantined"},
            "shadow": {"degraded", "quarantined"},
            "trusted": {"degraded", "quarantined"},
            "degraded": {"quarantined"},
            "quarantined": set(),
        }
        if not force and state != current and state not in allowed.get(current, set()):
            raise ValueError(f"Quality transition {current} -> {state} is not allowed.")
        now = utc_now()
        entry["state"] = state
        entry["updated_at"] = now
        entry.setdefault("history", []).append(
            {"at": now, "action": "state_changed", "from": current, "state": state, "reason": reason[:500]}
        )
        registry["artifacts"][digest] = entry
        save_quality_registry(registry, registry_path)
    return enrich_entry(entry)


def record_quality_outcome(
    reference: str,
    outcome: str,
    *,
    reason: str = "",
    evidence_id: str = "",
    registry_path: Path = REGISTRY_PATH,
) -> dict[str, Any]:
    valid_outcomes = {"completed", "confirmed", "contradicted", "fixture_passed", "inconclusive", "tool_error"}
    if outcome not in valid_outcomes:
        raise ValueError(f"Unknown generated-tool quality outcome: {outcome}")
    normalized_evidence_id = evidence_id.strip()
    if outcome in {"confirmed", "contradicted"} and not normalized_evidence_id:
        raise ValueError(f"{outcome} outcomes require a unique independent evidence ID.")
    with registry_write_lock(registry_path):
        registry = load_quality_registry(registry_path)
        digest, entry = resolve_entry(registry, reference)
        current = str(entry.get("state") or "candidate")
        if outcome == "confirmed" and current not in {"shadow", "trusted"}:
            raise ValueError(f"Independent confirmation cannot be recorded while quality state is {current}.")
        evidence = entry.setdefault("evidence", {})
        if normalized_evidence_id and normalized_evidence_id in evidence:
            raise ValueError(f"Evidence ID was already recorded for this artifact: {normalized_evidence_id}")

        stats = entry.setdefault("stats", empty_stats())
        stats["executions"] = int(stats.get("executions", 0)) + (
            1 if outcome in {"completed", "inconclusive", "tool_error"} else 0
        )
        if outcome == "confirmed":
            stats["independent_confirmations"] = int(stats.get("independent_confirmations", 0)) + 1
            stats["consecutive_errors"] = 0
        elif outcome == "contradicted":
            stats["contradictions"] = int(stats.get("contradictions", 0)) + 1
        elif outcome == "fixture_passed":
            stats["fixture_passes"] = int(stats.get("fixture_passes", 0)) + 1
        elif outcome == "tool_error":
            stats["tool_errors"] = int(stats.get("tool_errors", 0)) + 1
            stats["consecutive_errors"] = int(stats.get("consecutive_errors", 0)) + 1
        else:
            stats["consecutive_errors"] = 0
            if outcome == "inconclusive":
                stats["inconclusive"] = int(stats.get("inconclusive", 0)) + 1

        previous = current
        next_state = automatic_state(previous, stats, outcome)
        now = utc_now()
        entry["state"] = next_state
        entry["updated_at"] = now
        if normalized_evidence_id:
            evidence[normalized_evidence_id] = {
                "at": now,
                "outcome": outcome,
                "reason": reason[:500],
            }
        entry.setdefault("history", []).append(
            {
                "at": now,
                "action": "outcome_recorded",
                "outcome": outcome,
                "evidence_id": normalized_evidence_id or None,
                "from": previous,
                "state": next_state,
                "reason": reason[:500],
            }
        )
        registry["artifacts"][digest] = entry
        save_quality_registry(registry, registry_path)
    return enrich_entry(entry)


def list_quality_entries(registry_path: Path = REGISTRY_PATH) -> list[dict[str, Any]]:
    registry = load_quality_registry(registry_path)
    return sorted(
        (enrich_entry(entry) for entry in registry["artifacts"].values()),
        key=lambda item: str(item.get("updated_at") or ""),
        reverse=True,
    )


def resolve_entry(registry: dict[str, Any], reference: str) -> tuple[str, dict[str, Any]]:
    artifacts = registry.get("artifacts", {})
    if reference in artifacts:
        return reference, artifacts[reference]
    tool_matches = [
        (digest, entry)
        for digest, entry in artifacts.items()
        if entry.get("tool_id") == reference
    ]
    if tool_matches:
        tool_matches.sort(key=lambda item: str(item[1].get("created_at") or ""), reverse=True)
        return tool_matches[0]
    hash_matches = [(digest, entry) for digest, entry in artifacts.items() if digest.startswith(reference)]
    if not hash_matches:
        raise KeyError(f"Generated-tool quality record not found: {reference}")
    if len(hash_matches) > 1:
        raise KeyError(f"Generated-tool artifact hash prefix is ambiguous: {reference}")
    return hash_matches[0]


def automatic_state(current: str, stats: dict[str, Any], outcome: str) -> str:
    contradictions = int(stats.get("contradictions", 0))
    consecutive_errors = int(stats.get("consecutive_errors", 0))
    confirmations = int(stats.get("independent_confirmations", 0))
    if contradictions >= 2 or consecutive_errors >= 3:
        return "quarantined"
    if outcome == "contradicted":
        if current in {"candidate", "fixture_passed"}:
            return "quarantined"
        return "degraded"
    if current == "candidate" and outcome == "fixture_passed":
        return "fixture_passed"
    if current == "shadow" and confirmations >= 3 and contradictions == 0:
        return "trusted"
    return current


def quality_score(entry: dict[str, Any]) -> float:
    state = str(entry.get("state") or "candidate")
    stats = entry.get("stats") or {}
    score = STATE_BASE_SCORE.get(state, 0.0)
    confirmations = int(stats.get("independent_confirmations", 0))
    contradictions = int(stats.get("contradictions", 0))
    errors = int(stats.get("tool_errors", 0))
    executions = max(1, int(stats.get("executions", 0)))
    score += min(0.15, confirmations * 0.05)
    score -= min(0.35, contradictions * 0.15)
    score -= min(0.25, (errors / executions) * 0.25)
    return round(max(0.0, min(1.0, score)), 3)


def enrich_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {**entry, "quality_score": quality_score(entry)}


def empty_stats() -> dict[str, int]:
    return {
        "executions": 0,
        "fixture_passes": 0,
        "independent_confirmations": 0,
        "contradictions": 0,
        "tool_errors": 0,
        "consecutive_errors": 0,
        "inconclusive": 0,
    }


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


@contextmanager
def registry_write_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
