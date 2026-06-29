from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


MERGE_THRESHOLD = 0.95
REVIEW_THRESHOLD = 0.85


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha1_short(value: str, length: int = 16) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:length]


def normalize_text(value: str) -> str:
    normalized = value.strip().lower()
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized


def normalize_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if not parsed.scheme or not parsed.netloc:
        return normalize_text(value)
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"


def canonicalize(node_type: str, name: str) -> str:
    if node_type in {"Route", "Artifact"}:
        return normalize_url(name)
    return normalize_text(name)


def token_set(text: str) -> set[str]:
    return {item for item in re.findall(r"[a-z0-9_./:-]+", text.lower()) if len(item) > 1}


def text_similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()


def jaccard_similarity(left: str, right: str) -> float:
    left_tokens = token_set(left)
    right_tokens = token_set(right)
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def merge_value(old: Any, new: Any) -> Any:
    if new in (None, "", [], {}):
        return old
    if old in (None, "", [], {}):
        return new
    if old == new:
        return old
    values = old if isinstance(old, list) else [old]
    for item in new if isinstance(new, list) else [new]:
        if item not in values:
            values.append(item)
    return values


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


@dataclass
class GraphNode:
    id: str
    type: str
    canonical_name: str
    aliases: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    context: str = ""
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    source_ids: list[str] = field(default_factory=list)
    status: str = "active"


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    type: str
    attributes: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    source_ids: list[str] = field(default_factory=list)


@dataclass
class ReviewItem:
    id: str
    source: str
    target: str
    relation: str
    confidence: float
    reason: str
    status: str = "pending"
    created_at: str = field(default_factory=utc_now)


@dataclass
class UpsertResult:
    node: GraphNode
    action: str
    matched_id: str | None = None
    confidence: float = 0.0


class GraphStore:
    """Small JSON graph store with conservative entity resolution.

    The store is intentionally boring: it works without Neo4j, Chroma, or an LLM,
    but keeps node/edge/review records shaped so a Neo4j adapter can be added later.
    """

    def __init__(self, path: Path | str = Path("data/graph/medflow_graph.json")) -> None:
        self.path = Path(path)
        self.nodes: dict[str, GraphNode] = {}
        self.edges: dict[str, GraphEdge] = {}
        self.reviews: dict[str, ReviewItem] = {}

    @classmethod
    def load(cls, path: Path | str = Path("data/graph/medflow_graph.json")) -> "GraphStore":
        store = cls(path)
        if not store.path.exists():
            return store
        payload = json.loads(store.path.read_text(encoding="utf-8"))
        store.nodes = {
            node_id: GraphNode(**node)
            for node_id, node in payload.get("nodes", {}).items()
        }
        store.edges = {
            edge_id: GraphEdge(**edge)
            for edge_id, edge in payload.get("edges", {}).items()
        }
        store.reviews = {
            review_id: ReviewItem(**review)
            for review_id, review in payload.get("reviews", {}).items()
        }
        return store

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": 1,
            "updated_at": utc_now(),
            "nodes": {node_id: asdict(node) for node_id, node in sorted(self.nodes.items())},
            "edges": {edge_id: asdict(edge) for edge_id, edge in sorted(self.edges.items())},
            "reviews": {review_id: asdict(review) for review_id, review in sorted(self.reviews.items())},
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def summary(self) -> dict[str, int]:
        by_type: dict[str, int] = {}
        active_nodes = 0
        tombstoned_nodes = 0
        for node in self.nodes.values():
            if node.status == "active":
                active_nodes += 1
            elif node.status == "tombstoned":
                tombstoned_nodes += 1
            by_type[node.type] = by_type.get(node.type, 0) + 1
        return {
            "nodes": len(self.nodes),
            "active_nodes": active_nodes,
            "tombstoned_nodes": tombstoned_nodes,
            "edges": len(self.edges),
            "pending_reviews": sum(1 for review in self.reviews.values() if review.status == "pending"),
            **{f"nodes_{key.lower()}": value for key, value in sorted(by_type.items())},
        }

    def upsert_node(
        self,
        node_type: str,
        name: str,
        *,
        attributes: dict[str, Any] | None = None,
        context: str = "",
        source_id: str | None = None,
        stable_key: str | None = None,
    ) -> UpsertResult:
        attributes = attributes or {}
        canonical_name = canonicalize(node_type, name)
        node_context = context or f"{node_type} {canonical_name} {stable_json(attributes)}"

        if stable_key:
            node_id = self.node_id(node_type, stable_key)
            if node_id in self.nodes:
                node = self.merge_node(self.nodes[node_id], canonical_name, attributes, node_context, source_id)
                return UpsertResult(node=node, action="merged", matched_id=node_id, confidence=1.0)
            node = GraphNode(
                id=node_id,
                type=node_type,
                canonical_name=canonical_name,
                aliases=[name] if name and name != canonical_name else [],
                attributes=attributes,
                context=node_context,
                source_ids=[source_id] if source_id else [],
            )
            self.nodes[node.id] = node
            return UpsertResult(node=node, action="created", confidence=1.0)

        candidate = GraphNode(
            id=self.node_id(node_type, f"{canonical_name}:{sha1_short(node_context, 8)}"),
            type=node_type,
            canonical_name=canonical_name,
            aliases=[name] if name and name != canonical_name else [],
            attributes=attributes,
            context=node_context,
            source_ids=[source_id] if source_id else [],
        )
        best_node, best_score = self.best_identity_match(candidate)
        if best_node and best_score >= MERGE_THRESHOLD:
            node = self.merge_node(best_node, canonical_name, attributes, node_context, source_id)
            return UpsertResult(node=node, action="merged", matched_id=best_node.id, confidence=best_score)
        if candidate.id not in self.nodes:
            self.nodes[candidate.id] = candidate
        if best_node and best_score >= REVIEW_THRESHOLD:
            self.add_review(candidate.id, best_node.id, best_score, "Possible duplicate after type-gated full-context comparison.")
            return UpsertResult(node=candidate, action="review", matched_id=best_node.id, confidence=best_score)
        return UpsertResult(node=candidate, action="created", confidence=best_score)

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        *,
        attributes: dict[str, Any] | None = None,
        source_id: str | None = None,
    ) -> GraphEdge:
        edge_id = self.edge_id(source, target, edge_type)
        if edge_id in self.edges:
            edge = self.edges[edge_id]
            for key, value in (attributes or {}).items():
                edge.attributes[key] = merge_value(edge.attributes.get(key), value)
            if source_id and source_id not in edge.source_ids:
                edge.source_ids.append(source_id)
            return edge
        edge = GraphEdge(
            id=edge_id,
            source=source,
            target=target,
            type=edge_type,
            attributes=attributes or {},
            source_ids=[source_id] if source_id else [],
        )
        self.edges[edge.id] = edge
        return edge

    def dream_dedup(self) -> dict[str, int]:
        """Nightly-style cleanup pass across same-type nodes."""
        merged = 0
        reviews = 0
        nodes = list(self.nodes.values())
        for index, left in enumerate(nodes):
            if left.status != "active" or left.id not in self.nodes:
                continue
            for right in nodes[index + 1:]:
                if right.status != "active" or right.id not in self.nodes or left.type != right.type:
                    continue
                score = self.identity_score(left, right)
                if score >= MERGE_THRESHOLD and self.has_stable_identity_overlap(left, right):
                    self.merge_existing_nodes(left.id, right.id)
                    merged += 1
                elif score >= REVIEW_THRESHOLD:
                    before = len(self.reviews)
                    self.add_review(left.id, right.id, score, "Dream dedup found a possible same-as relationship.")
                    reviews += int(len(self.reviews) > before)
        return {"merged": merged, "reviews_added": reviews}

    def to_cypher(self) -> str:
        lines = ["// Generated by MedFlow graph memory. Review before importing."]
        for node in self.nodes.values():
            props = {
                "id": node.id,
                "type": node.type,
                "canonical_name": node.canonical_name,
                "aliases": node.aliases,
                "status": node.status,
                "source_ids": node.source_ids,
                "created_at": node.created_at,
                "updated_at": node.updated_at,
                **node.attributes,
            }
            lines.append(f"MERGE (n:MedFlowEntity {{id: {json.dumps(node.id)}}}) SET n += {json.dumps(props, sort_keys=True)};")
        for edge in self.edges.values():
            relation = re.sub(r"[^A-Z0-9_]", "_", edge.type.upper())
            props = {"id": edge.id, **edge.attributes}
            lines.append(
                "MATCH (a:MedFlowEntity {id: "
                + json.dumps(edge.source)
                + "}), (b:MedFlowEntity {id: "
                + json.dumps(edge.target)
                + f"}}) MERGE (a)-[r:{relation} {{id: {json.dumps(edge.id)}}}]->(b) SET r += {json.dumps(props, sort_keys=True)};"
            )
        for review in self.reviews.values():
            props = asdict(review)
            lines.append(
                "MATCH (a:MedFlowEntity {id: "
                + json.dumps(review.source)
                + "}), (b:MedFlowEntity {id: "
                + json.dumps(review.target)
                + "}) MERGE (a)-[r:PENDING_SAME_AS {id: "
                + json.dumps(review.id)
                + f"}}]->(b) SET r += {json.dumps(props, sort_keys=True)};"
            )
        return "\n".join(lines) + "\n"

    def node_id(self, node_type: str, stable_key: str) -> str:
        return f"{node_type.lower()}:{sha1_short(node_type + ':' + stable_key)}"

    def edge_id(self, source: str, target: str, edge_type: str) -> str:
        return f"edge:{sha1_short(source + '|' + edge_type + '|' + target)}"

    def merge_node(
        self,
        node: GraphNode,
        canonical_name: str,
        attributes: dict[str, Any],
        context: str,
        source_id: str | None,
    ) -> GraphNode:
        if canonical_name != node.canonical_name and canonical_name not in node.aliases:
            node.aliases.append(canonical_name)
        for key, value in attributes.items():
            node.attributes[key] = merge_value(node.attributes.get(key), value)
        node.context = merge_context(node.context, context)
        node.updated_at = utc_now()
        if source_id and source_id not in node.source_ids:
            node.source_ids.append(source_id)
        return node

    def best_identity_match(self, candidate: GraphNode) -> tuple[GraphNode | None, float]:
        best_node: GraphNode | None = None
        best_score = 0.0
        for node in self.nodes.values():
            if node.status != "active" or node.type != candidate.type:
                continue
            score = self.identity_score(candidate, node)
            if score > best_score:
                best_node = node
                best_score = score
        return best_node, best_score

    def identity_score(self, left: GraphNode, right: GraphNode) -> float:
        if left.type != right.type:
            return 0.0
        if self.has_stable_identity_overlap(left, right):
            return 1.0
        name_score = text_similarity(left.canonical_name, right.canonical_name)
        context_score = jaccard_similarity(left.context, right.context)
        return round((name_score * 0.35) + (context_score * 0.65), 3)

    def has_stable_identity_overlap(self, left: GraphNode, right: GraphNode) -> bool:
        keys = ["ip", "url", "route_url", "service_key", "capability_id", "campaign_id", "role", "mitre_id"]
        return any(left.attributes.get(key) and left.attributes.get(key) == right.attributes.get(key) for key in keys)

    def add_review(self, source: str, target: str, confidence: float, reason: str) -> None:
        review_id = f"review:{sha1_short(source + '|SAME_AS|' + target)}"
        if review_id in self.reviews:
            return
        self.reviews[review_id] = ReviewItem(
            id=review_id,
            source=source,
            target=target,
            relation="SAME_AS",
            confidence=confidence,
            reason=reason,
        )

    def merge_existing_nodes(self, keep_id: str, remove_id: str) -> None:
        if keep_id == remove_id or keep_id not in self.nodes or remove_id not in self.nodes:
            return
        keep = self.nodes[keep_id]
        remove = self.nodes[remove_id]
        self.merge_node(keep, remove.canonical_name, remove.attributes, remove.context, None)
        for source_id in remove.source_ids:
            if source_id not in keep.source_ids:
                keep.source_ids.append(source_id)
        keep.aliases.extend(alias for alias in remove.aliases if alias not in keep.aliases)

        for edge in list(self.edges.values()):
            changed = False
            if edge.source == remove_id:
                edge.source = keep_id
                changed = True
            if edge.target == remove_id:
                edge.target = keep_id
                changed = True
            if changed:
                del self.edges[edge.id]
                edge.id = self.edge_id(edge.source, edge.target, edge.type)
                self.edges[edge.id] = edge
        remove.status = "tombstoned"
        remove.updated_at = utc_now()


def merge_context(old: str, new: str, limit: int = 3000) -> str:
    if not old:
        return new[:limit]
    if not new or new in old:
        return old[:limit]
    return f"{old}\n{new}"[:limit]


def ingest_campaign_report(store: GraphStore, report_path: Path | str) -> dict[str, int]:
    path = Path(report_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    source_id = str(path)
    stats = {"created": 0, "merged": 0, "review": 0, "edges": 0}

    def track(result: UpsertResult) -> GraphNode:
        stats[result.action] = stats.get(result.action, 0) + 1
        return result.node

    campaign_id = payload.get("saved_at") or path.stem
    campaign = track(
        store.upsert_node(
            "Campaign",
            payload.get("goal") or path.stem,
            attributes={
                "campaign_id": campaign_id,
                "goal": payload.get("goal"),
                "provider": payload.get("provider"),
                "elapsed_seconds": payload.get("elapsed_seconds"),
                "report_path": source_id,
            },
            context=campaign_context(payload),
            source_id=source_id,
            stable_key=str(campaign_id),
        )
    )

    target_node = None
    target = payload.get("target")
    if target:
        target_node = track(
            store.upsert_node(
                "Target",
                str(target),
                attributes={"ip": str(target)},
                context=f"Target {target} observed in campaign {campaign_id}",
                source_id=source_id,
                stable_key=str(target),
            )
        )
        store.add_edge(campaign.id, target_node.id, "ASSESSED_TARGET", source_id=source_id)
        stats["edges"] += 1

    services_by_port: dict[str, GraphNode] = {}
    for service in payload.get("services") or []:
        port = str(service.get("port") or "")
        proto = str(service.get("protocol") or "tcp")
        label = f"{target or 'unknown'} {port}/{proto} {service.get('service') or 'unknown'}"
        service_key = f"{target}:{port}/{proto}"
        service_node = track(
            store.upsert_node(
                "Service",
                label,
                attributes={
                    "service_key": service_key,
                    "target": target,
                    "port": port,
                    "protocol": proto,
                    "service": service.get("service"),
                    "version": service.get("version"),
                },
                context=f"Service {label} {service.get('version') or ''}",
                source_id=source_id,
                stable_key=service_key,
            )
        )
        services_by_port[port] = service_node
        store.add_edge(campaign.id, service_node.id, "OBSERVED_SERVICE", source_id=source_id)
        stats["edges"] += 1
        if target_node:
            store.add_edge(target_node.id, service_node.id, "HAS_SERVICE", source_id=source_id)
            stats["edges"] += 1

    for route in ((payload.get("web_routes") or {}).get("web_routes") or []):
        url = str(route.get("url") or "")
        if not url or not route.get("status"):
            continue
        route_node = track(
            store.upsert_node(
                "Route",
                url,
                attributes={
                    "url": normalize_url(url),
                    "route_url": normalize_url(url),
                    "status": route.get("status"),
                    "title": route.get("title"),
                    "content_type": route.get("content_type"),
                    "content_length": route.get("content_length"),
                    "artifact_signal": route.get("artifact_signal"),
                },
                context=f"Web route {url} status {route.get('status')} signal {route.get('artifact_signal') or ''}",
                source_id=source_id,
                stable_key=normalize_url(url),
            )
        )
        store.add_edge(campaign.id, route_node.id, "OBSERVED_ROUTE", source_id=source_id)
        stats["edges"] += 1
        if target_node:
            store.add_edge(target_node.id, route_node.id, "HAS_ROUTE", source_id=source_id)
            stats["edges"] += 1
        if route.get("artifact_signal"):
            artifact = track(
                store.upsert_node(
                    "Artifact",
                    url,
                    attributes={"url": normalize_url(url), "signal": route.get("artifact_signal")},
                    context=f"Potential exposed artifact at {url}: {route.get('artifact_signal')}",
                    source_id=source_id,
                    stable_key=f"{normalize_url(url)}:{route.get('artifact_signal')}",
                )
            )
            finding = track(
                store.upsert_node(
                    "Finding",
                    str(route.get("artifact_signal")),
                    attributes={"name": route.get("artifact_signal"), "severity": "needs-review", "source_url": normalize_url(url)},
                    context=f"Finding from route discovery: {route.get('artifact_signal')} at {url}",
                    source_id=source_id,
                    stable_key=f"{normalize_url(url)}:{route.get('artifact_signal')}",
                )
            )
            store.add_edge(route_node.id, artifact.id, "EXPOSES_ARTIFACT", source_id=source_id)
            store.add_edge(artifact.id, finding.id, "SUPPORTS_FINDING", source_id=source_id)
            stats["edges"] += 2

    validation = payload.get("capability_validation") or {}
    for result in validation.get("results") or []:
        capability_id = str(result.get("selected_exploit_id") or result.get("capability_id") or "unknown")
        capability = track(
            store.upsert_node(
                "Capability",
                capability_id,
                attributes={
                    "capability_id": capability_id,
                    "provider": result.get("provider"),
                    "runner": result.get("runner"),
                    "verified": bool(result.get("verified")),
                },
                context=f"Capability {capability_id} verified={bool(result.get('verified'))} reason={result.get('reason') or ''}",
                source_id=source_id,
                stable_key=capability_id,
            )
        )
        store.add_edge(campaign.id, capability.id, "RAN_CAPABILITY", attributes={"verified": bool(result.get("verified"))}, source_id=source_id)
        stats["edges"] += 1
        port = str(result.get("port") or "")
        if port and port in services_by_port:
            store.add_edge(capability.id, services_by_port[port].id, "VALIDATED_SERVICE", source_id=source_id)
            stats["edges"] += 1
        evidence_text = result.get("proof_output") or result.get("reason") or ""
        if evidence_text:
            evidence = track(
                store.upsert_node(
                    "Evidence",
                    f"{capability_id} evidence",
                    attributes={
                        "capability_id": capability_id,
                        "verified": bool(result.get("verified")),
                        "preview": str(evidence_text)[:600],
                    },
                    context=str(evidence_text)[:1200],
                    source_id=source_id,
                    stable_key=f"{campaign_id}:{capability_id}:{bool(result.get('verified'))}",
                )
            )
            store.add_edge(capability.id, evidence.id, "PRODUCED_EVIDENCE", source_id=source_id)
            stats["edges"] += 1

    for agent in payload.get("agents") or []:
        role = str(agent.get("role") or "Unknown Agent")
        agent_node = track(
            store.upsert_node(
                "AgentRole",
                role,
                attributes={"role": role, "tools": agent.get("tools") or []},
                context=f"{role} objective={agent.get('objective')} handoff={agent.get('handoff')}",
                source_id=source_id,
                stable_key=role,
            )
        )
        store.add_edge(campaign.id, agent_node.id, "USED_AGENT", source_id=source_id)
        stats["edges"] += 1

    for hit in payload.get("sources") or []:
        metadata = hit.get("metadata") or {}
        source_name = metadata.get("mitre_id") or metadata.get("name") or hit.get("id") or "retrieved source"
        source = track(
            store.upsert_node(
                "KnowledgeSource",
                str(source_name),
                attributes={
                    "collection": hit.get("collection"),
                    "source_id": hit.get("id"),
                    "score": hit.get("score"),
                    "mitre_id": metadata.get("mitre_id"),
                    "name": metadata.get("name"),
                },
                context=str(hit.get("document") or "")[:1200],
                source_id=source_id,
                stable_key=f"{hit.get('collection')}:{hit.get('id')}",
            )
        )
        store.add_edge(campaign.id, source.id, "RETRIEVED_SOURCE", source_id=source_id)
        stats["edges"] += 1

    return stats


def campaign_context(payload: dict[str, Any]) -> str:
    parts = [
        f"Goal: {payload.get('goal')}",
        f"Target: {payload.get('target')}",
        f"Provider: {payload.get('provider')}",
        f"Services: {stable_json(payload.get('services') or [])[:1000]}",
        f"Safety review: {payload.get('safety_review') or ''}",
    ]
    return "\n".join(parts)
