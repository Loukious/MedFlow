from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def load_records(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    for key in ["records", "events", "value", "data"]:
        if isinstance(data.get(key), list):
            return [item for item in data[key] if isinstance(item, dict)]
    return [data]


def analyze_identity_logs(path: str | Path) -> dict[str, Any]:
    records = load_records(path)
    user_failures: Counter[str] = Counter()
    user_mfa_pushes: Counter[str] = Counter()
    suspicious = []
    for row in records:
        text = " ".join(str(value) for value in row.values()).lower()
        user = first_present(row, ["user", "username", "userPrincipalName", "principal", "account", "actor"]) or "unknown"
        if any(term in text for term in ["mfa", "push", "approve", "authenticator"]):
            user_mfa_pushes[user] += 1
        if any(term in text for term in ["failure", "failed", "deny", "denied", "timeout", "fraud"]):
            user_failures[user] += 1
    for user, count in user_mfa_pushes.items():
        failures = user_failures[user]
        if count >= 5 or failures >= 3:
            suspicious.append(
                {
                    "type": "mfa_fatigue_signal",
                    "user": user,
                    "mfa_events": count,
                    "failure_events": failures,
                    "status": "needs_review",
                    "summary": "Repeated MFA/failure-like events for the same principal in imported logs.",
                }
            )
    return {
        "source": str(path),
        "records": len(records),
        "top_mfa_users": user_mfa_pushes.most_common(10),
        "top_failure_users": user_failures.most_common(10),
        "findings": suspicious,
    }


def analyze_bloodhound_export(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    nodes, edges = extract_graph_parts(data)
    high_value = []
    inbound_admin_edges: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in nodes:
        props = node.get("Properties") or node.get("properties") or node
        if props.get("highvalue") is True or str(props.get("highvalue", "")).lower() == "true":
            high_value.append(node)
    for edge in edges:
        label = str(edge.get("Label") or edge.get("label") or edge.get("kind") or "").lower()
        target = str(edge.get("EndNode") or edge.get("end") or edge.get("target") or "")
        if any(term in label for term in ["admin", "owner", "genericall", "write", "allowedtoact"]):
            inbound_admin_edges[target].append(edge)
    findings = []
    for node in high_value[:25]:
        node_id = str(node.get("ObjectIdentifier") or node.get("id") or node.get("Id") or "")
        props = node.get("Properties") or node.get("properties") or node
        if inbound_admin_edges.get(node_id):
            findings.append(
                {
                    "type": "privileged_path_signal",
                    "principal": props.get("name") or props.get("Name") or node_id,
                    "inbound_edges": len(inbound_admin_edges[node_id]),
                    "status": "needs_review",
                    "summary": "High-value node has inbound administrative/control edges in imported BloodHound data.",
                }
            )
    return {
        "source": str(path),
        "nodes": len(nodes),
        "edges": len(edges),
        "high_value_nodes": len(high_value),
        "findings": findings,
    }


def extract_graph_parts(data: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)], []
    if not isinstance(data, dict):
        return [], []
    nodes = data.get("nodes") or data.get("Nodes") or data.get("data", {}).get("nodes") or []
    edges = data.get("edges") or data.get("Edges") or data.get("relationships") or data.get("data", {}).get("edges") or []
    return (
        [item for item in nodes if isinstance(item, dict)],
        [item for item in edges if isinstance(item, dict)],
    )


def first_present(row: dict[str, Any], keys: list[str]) -> str:
    lower_map = {key.lower(): value for key, value in row.items()}
    for key in keys:
        value = lower_map.get(key.lower())
        if value:
            return str(value)
    return ""
