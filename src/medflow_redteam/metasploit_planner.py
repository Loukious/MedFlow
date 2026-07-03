from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PayloadCandidate:
    payload: str
    score: int
    reasons: tuple[str, ...]


COMMON_OPTIONS = {"RHOSTS", "RPORT", "SSL", "TARGETURI", "VHOST"}


def plan_metasploit_execution(
    capability: dict[str, Any],
    service: dict[str, Any],
    *,
    lhost: str = "auto",
    lport: int = 4444,
) -> dict[str, Any]:
    module_path = str(capability.get("module_path") or capability.get("id", "").removeprefix("metasploit:"))
    option_plan = plan_module_options(capability, service, lhost=lhost, lport=lport)
    payloads = select_payload_candidates(capability, service)
    return {
        "module_path": module_path,
        "module_id": f"metasploit:{module_path}",
        "options": option_plan,
        "payload_candidates": [candidate.__dict__ for candidate in payloads],
        "selected_payload": payloads[0].payload if payloads else "",
        "decision": "planned" if module_path and payloads else "insufficient_metadata",
        "execution_note": "Plan only. The benchmark does not execute Metasploit modules.",
    }


def plan_module_options(capability: dict[str, Any], service: dict[str, Any], *, lhost: str, lport: int) -> dict[str, Any]:
    matched = capability.get("matched_service") or service or {}
    port = str(matched.get("port") or service.get("port") or "")
    scheme = "https" if str(matched.get("service") or service.get("service")).lower() == "https" else "http"
    target_uri = infer_target_uri(capability, service)
    options = {
        "RHOSTS": "<target>",
        "RPORT": port,
        "SSL": "true" if scheme == "https" else "false",
        "TARGETURI": target_uri,
        "VHOST": "",
        "LHOST": lhost,
        "LPORT": str(lport),
    }
    return {key: value for key, value in options.items() if value != ""}


def infer_target_uri(capability: dict[str, Any], service: dict[str, Any]) -> str:
    uri = str(service.get("target_uri") or service.get("path") or "").strip()
    if uri:
        return uri if uri.startswith("/") else f"/{uri}"
    return "/"


def select_payload_candidates(capability: dict[str, Any], service: dict[str, Any] | None = None) -> list[PayloadCandidate]:
    text = capability_text(capability, service)
    candidates: dict[str, tuple[int, list[str]]] = {}

    def add(payload: str, score: int, reason: str) -> None:
        current_score, reasons = candidates.get(payload, (0, []))
        candidates[payload] = (current_score + score, [*reasons, reason])

    for payload in capability.get("default_payloads") or []:
        add(str(payload), 90, "Metasploit module declares this default payload")

    if has_any(text, ["arch_cmd", " cmd ", "command", "ognl", "struts", "metabase", "shiro", "unix"]):
        add("cmd/unix/reverse_bash", 70, "Unix command execution path")
        add("cmd/unix/generic", 45, "Generic command payload remains useful for check/proof mode")

    if has_any(text, ["php", "drupal"]):
        add("php/meterpreter/reverse_tcp", 65, "PHP-capable web module")
        add("cmd/unix/reverse_bash", 35, "Drupal/PHP modules often expose Unix command targets too")

    if has_any(text, ["java", "solr", "struts", "tomcat"]):
        add("java/meterpreter/reverse_tcp", 68, "Java-capable target or module")

    if has_any(text, ["linux", "x64", "x86", "rocketmq", "couchdb"]):
        add("linux/x64/shell_reverse_tcp", 58, "Linux shell payload candidate")

    if "rocketmq" in text or "cmd/linux/http" in text:
        add("cmd/linux/http/x64/meterpreter/reverse_tcp", 72, "HTTP-capable Linux command target candidate")

    if "windows" in text or " win " in text:
        add("windows/meterpreter/reverse_tcp", 45, "Windows target candidate")
    else:
        add("windows/meterpreter/reverse_tcp", -35, "No Windows evidence; keep low priority")

    add("generic/shell_reverse_tcp", 20, "Fallback reverse shell payload")

    ranked = sorted(
        (PayloadCandidate(payload, score, tuple(reasons)) for payload, (score, reasons) in candidates.items()),
        key=lambda item: item.score,
        reverse=True,
    )
    return [item for item in ranked if item.score > 0]


def capability_text(capability: dict[str, Any], service: dict[str, Any] | None = None) -> str:
    parts: list[str] = []
    for key in ["id", "name", "module_path", "module_type", "description", "platform", "arch"]:
        value = capability.get(key)
        if value:
            parts.append(" ".join(value) if isinstance(value, list) else str(value))
    for item in (capability.get("targets") or []):
        if isinstance(item, dict):
            parts.extend(str(value) for value in item.values())
    match = capability.get("match") or {}
    parts.extend(str(item) for item in match.get("product_keywords", []))
    if service:
        parts.extend(str(value) for value in service.values())
    return " ".join(parts).lower()


def has_any(text: str, needles: list[str]) -> bool:
    return any(needle.lower() in text for needle in needles)


def payload_rank(payloads: list[dict[str, Any]], expected: list[str]) -> int | None:
    expected_set = set(expected)
    for index, item in enumerate(payloads, start=1):
        if item.get("payload") in expected_set:
            return index
    return None


def acceptable_payloads_for_module(module_path: str, default_payloads: list[str] | None = None) -> list[str]:
    text = module_path.lower()
    payloads = list(default_payloads or [])
    if any(word in text for word in ["struts", "shiro", "metabase"]):
        payloads.extend(["cmd/unix/reverse_bash", "cmd/unix/generic"])
    if "drupal" in text:
        payloads.extend(["php/meterpreter/reverse_tcp", "cmd/unix/reverse_bash"])
    if "solr" in text:
        payloads.extend(["java/meterpreter/reverse_tcp", "cmd/unix/reverse_bash"])
    if "rocketmq" in text:
        payloads.extend(["cmd/linux/http/x64/meterpreter/reverse_tcp", "cmd/unix/reverse_bash"])
    if "couchdb" in text:
        payloads.extend(["linux/x64/shell_reverse_tcp", "cmd/unix/reverse_openssl", "cmd/unix/reverse_bash"])
    if not payloads:
        payloads.append("cmd/unix/reverse_bash")
    return sorted(set(payloads))
