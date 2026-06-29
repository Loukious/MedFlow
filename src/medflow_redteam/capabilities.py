from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config_loader import ROOT, load_internal_capabilities_config


INVENTORY_PATH = ROOT / "data" / "capabilities" / "capability_inventory.json"


@dataclass
class CapabilityMatch:
    capability: dict[str, Any]
    score: int
    reasons: list[str]
    matched_service: dict[str, str]


def load_internal_capabilities() -> list[dict[str, Any]]:
    config = load_internal_capabilities_config()
    capabilities = []
    for item in config.get("capabilities", []):
        capabilities.append(
            {
                **item,
                "provider": "internal",
                "source": "config/internal_capabilities.json",
                "execution": "registered_runner",
                "safe_to_execute": True,
            }
        )
    return capabilities


def load_capability_inventory(path: Path | None = None) -> list[dict[str, Any]]:
    inventory_path = path or INVENTORY_PATH
    capabilities = load_internal_capabilities()
    if inventory_path.exists():
        data = json.loads(inventory_path.read_text(encoding="utf-8"))
        capabilities.extend(data.get("capabilities", []))
    return capabilities


def normalize_text(value: str | None) -> str:
    return (value or "").lower()


def keyword_matches(keyword: str, observed_text: str) -> bool:
    lowered = normalize_text(keyword).strip()
    if not lowered:
        return False
    if len(lowered) <= 3:
        return re.search(rf"(?<![a-z0-9]){re.escape(lowered)}(?![a-z0-9])", observed_text) is not None
    return lowered in observed_text


def has_blocked_provider_indicator(capability: dict[str, Any]) -> bool:
    runner = capability.get("runner")
    if runner not in {"metasploit_module", "nuclei_template"}:
        return False
    text = " ".join(
        str(capability.get(key, ""))
        for key in ["id", "name", "module_path", "template_path", "description"]
    ).lower()
    tokens = set(re.split(r"[^a-z0-9]+", text))
    blocked = {
        "brute",
        "cred",
        "creds",
        "credential",
        "credentials",
        "dump",
        "hash",
        "hashdump",
        "login",
        "passwd",
        "password",
        "persistence",
        "priv",
        "privesc",
        "example",
        "relay",
        "dos",
    }
    return bool(tokens & blocked)


def capability_match_score(
    capability: dict[str, Any],
    service: dict[str, str],
    web_routes: dict[str, Any] | None = None,
    graph_memory: dict[str, Any] | None = None,
) -> tuple[int, list[str]]:
    if has_blocked_provider_indicator(capability):
        return 0, []

    match = capability.get("match", {})
    observed_port = normalize_text(service.get("port"))
    observed_service = normalize_text(service.get("service"))
    observed_version = normalize_text(service.get("version"))
    observed_text = f"{observed_service} {observed_version}"
    score = 0
    reasons: list[str] = []
    primary_matched = False

    configured_ports = {str(port) for port in match.get("ports", [])}
    if configured_ports and observed_port in configured_ports:
        score += 50
        primary_matched = True
        reasons.append(f"port {observed_port} matched")

    configured_service = normalize_text(match.get("service"))
    if configured_service and observed_service == configured_service:
        score += 30
        primary_matched = True
        reasons.append(f"service {observed_service} matched")

    if (configured_ports or configured_service) and not primary_matched:
        return 0, []

    for keyword in match.get("product_keywords", []):
        lowered = normalize_text(str(keyword))
        if keyword_matches(lowered, observed_text):
            score += 10
            reasons.append(f"keyword {lowered} matched")

    for pattern in match.get("version_patterns", []):
        if re.search(pattern, observed_text, flags=re.IGNORECASE):
            score += 15
            reasons.append(f"version pattern {pattern} matched")

    for cve in capability.get("cves", []):
        if cve and cve.lower() in observed_text:
            score += 20
            reasons.append(f"CVE {cve} appeared in service text")

    if capability.get("provider") == "internal":
        score += 30
        reasons.append("registered internal runner")
    elif capability.get("safe_to_execute"):
        score += 5
        reasons.append("provider marked safe to execute")

    categories = {normalize_text(str(item)) for item in capability.get("categories", [])}
    if {"vuln", "exploit"} & categories:
        score += 15
        reasons.append("vulnerability/exploit validation category")

    if capability.get("runner") in {"metasploit_module", "nuclei_template"}:
        score += 10
        reasons.append("external provider runner available")

    if capability.get("module_type") == "exploit":
        score += 15
        reasons.append("Metasploit exploit check capability")

    if capability.get("cves"):
        score += 10
        reasons.append("CVE-linked capability")

    route_score, route_reasons = web_route_score(capability, service, web_routes)
    score += route_score
    reasons.extend(route_reasons)

    memory_score, memory_reasons = graph_memory_score(capability, graph_memory)
    score += memory_score
    reasons.extend(memory_reasons)

    return score, reasons


def web_route_score(capability: dict[str, Any], service: dict[str, str], web_routes: dict[str, Any] | None) -> tuple[int, list[str]]:
    if not web_routes:
        return 0, []
    runner = capability.get("runner")
    capability_text = " ".join(
        str(capability.get(key, ""))
        for key in ["id", "name", "description", "template_path", "module_path"]
    ).lower()
    routes = web_routes.get("web_routes") or []
    score = 0
    reasons: list[str] = []
    service_text = str((capability.get("match") or {}).get("service", "")).lower()
    observed_service = normalize_text(service.get("service"))
    observed_port = normalize_text(service.get("port"))
    observed_is_web = observed_service in {"http", "https", "http-proxy"} or observed_port in {"80", "443", "5000", "8000", "8080", "8443"}
    is_web_relevant = observed_is_web and any(term in f"{capability_text} {service_text}" for term in ["http", "web", "api", "cookie", "header", "file", "download"])
    if any(route.get("artifact_signal") for route in routes):
        if is_web_relevant:
            score += 18
            reasons.append("web artifact signal observed")
    if any(str(route.get("status")) == "200" and route.get("url", "").lower().rstrip("/").endswith("/login") for route in routes):
        if any(term in capability_text for term in ["auth", "login", "session", "cookie", "http"]):
            score += 12
            reasons.append("login route observed")
    if any("application/json" in str(route.get("content_type", "")).lower() for route in routes):
        if any(term in capability_text for term in ["api", "json", "http"]):
            score += 10
            reasons.append("API-like response observed")
    return score, reasons


def graph_memory_score(capability: dict[str, Any], graph_memory: dict[str, Any] | None) -> tuple[int, list[str]]:
    if not graph_memory:
        return 0, []
    cap_id = str(capability.get("id") or "")
    if not cap_id:
        return 0, []
    score = 0
    reasons: list[str] = []
    successful = {
        str(hit.get("attributes", {}).get("capability_id") or hit.get("name"))
        for hit in graph_memory.get("successful_capabilities", [])
    }
    failed = {
        str(hit.get("attributes", {}).get("capability_id") or hit.get("name"))
        for hit in graph_memory.get("failed_capabilities", [])
    }
    if cap_id in successful:
        score += 20
        reasons.append("graph memory shows previous positive validation")
    if cap_id in failed:
        score -= 8
        reasons.append("graph memory shows previous non-finding; deprioritized but not blocked")
    return score, reasons


def select_capabilities_for_services(
    target: str,
    services: list[dict[str, str]],
    limit: int = 1,
    inventory_path: Path | None = None,
    web_routes: dict[str, Any] | None = None,
    graph_memory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    capabilities = load_capability_inventory(inventory_path)
    matches: list[CapabilityMatch] = []
    for capability in capabilities:
        for service in services:
            score, reasons = capability_match_score(capability, service, web_routes=web_routes, graph_memory=graph_memory)
            if score:
                matches.append(CapabilityMatch(capability, score, reasons, service))

    best_by_id: dict[str, CapabilityMatch] = {}
    for item in matches:
        cap_id = str(item.capability.get("id"))
        existing = best_by_id.get(cap_id)
        if existing is None or item.score > existing.score:
            best_by_id[cap_id] = item

    deduped_matches = sorted(best_by_id.values(), key=lambda item: item.score, reverse=True)
    candidates = [
        {
            **item.capability,
            "score": item.score,
            "matched_service": item.matched_service,
            "reasons": item.reasons,
            "score_explanation": "; ".join(item.reasons),
        }
        for item in deduped_matches
    ]
    selected_candidates = select_diverse_candidates(candidates, max(1, limit))
    return {
        "target": target,
        "inventory_path": str(inventory_path or INVENTORY_PATH),
        "catalog_size": len(capabilities),
        "candidates": candidates,
        "selected_candidates": selected_candidates,
        "selected": selected_candidates[0] if selected_candidates else None,
        "decision": "selected" if selected_candidates else "no_matching_capability",
        "reason": "Selected highest-scoring candidates from observed services, web evidence, and graph memory."
        if selected_candidates
        else "No capability matched the observed services.",
        "graph_memory_used": bool(graph_memory),
        "web_routes_used": bool(web_routes),
    }


def select_diverse_candidates(candidates: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    if len(candidates) <= limit:
        return candidates

    by_provider: dict[str, list[dict[str, Any]]] = {}
    for item in candidates:
        by_provider.setdefault(str(item.get("provider") or "unknown"), []).append(item)

    provider_order = sorted(
        by_provider,
        key=lambda provider: by_provider[provider][0].get("score", 0),
        reverse=True,
    )
    selected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    while len(selected) < limit:
        added = False
        for provider in provider_order:
            bucket = by_provider[provider]
            while bucket and str(bucket[0].get("id")) in seen_ids:
                bucket.pop(0)
            if not bucket:
                continue
            item = bucket.pop(0)
            selected.append(item)
            seen_ids.add(str(item.get("id")))
            added = True
            if len(selected) >= limit:
                break
        if not added:
            break
    return selected
