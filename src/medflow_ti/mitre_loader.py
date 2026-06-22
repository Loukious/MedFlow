from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict
from typing import Any, Iterable


MITRE_TYPES = {
    "attack-pattern",
    "intrusion-set",
    "malware",
    "tool",
    "campaign",
    "course-of-action",
    "x-mitre-analytic",
    "x-mitre-detection-strategy",
    "x-mitre-data-source",
    "x-mitre-data-component",
}


@dataclass(frozen=True)
class Document:
    collection: str
    doc_id: str
    text: str
    metadata: dict[str, str | int | float | bool]


def load_objects(base_dir: Path) -> dict[str, dict[str, Any]]:
    objects: dict[str, dict[str, Any]] = {}
    for path in base_dir.glob("*/*.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        for obj in data.get("objects", []):
            if obj.get("type") in MITRE_TYPES or obj.get("type") == "relationship":
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue
                obj["_path"] = str(path)
                objects[obj["id"]] = obj
    return objects


def external_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return ""


def url(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return ""


def clean(text: Any) -> str:
    text = "" if text is None else str(text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\(Citation:[^)]+\)", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def names(values: Iterable[str], objects: dict[str, dict[str, Any]]) -> list[str]:
    out = []
    for value in values:
        obj = objects.get(value)
        if obj:
            label = external_id(obj)
            out.append(f"{obj.get('name', value)} {f'({label})' if label else ''}".strip())
    return out


def relationship_index(objects: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    rels: dict[str, list[dict[str, Any]]] = {}
    for obj in objects.values():
        if obj.get("type") != "relationship":
            continue
        rels.setdefault(obj.get("source_ref", ""), []).append(obj)
        rels.setdefault(obj.get("target_ref", ""), []).append(obj)
    return rels


def relation_lines(obj_id: str, objects: dict[str, dict[str, Any]], rels: dict[str, list[dict[str, Any]]]) -> list[str]:
    lines = []
    for rel in rels.get(obj_id, []):
        source = objects.get(rel.get("source_ref", ""))
        target = objects.get(rel.get("target_ref", ""))
        if not source or not target:
            continue
        desc = clean(rel.get("description", ""))
        line = (
            f"{source.get('name')} {rel.get('relationship_type')} "
            f"{target.get('name')}: {desc}"
        )
        lines.append(line)
    return lines[:30]


def base_metadata(obj: dict[str, Any]) -> dict[str, str | int | float | bool]:
    return {
        "stix_id": obj.get("id", ""),
        "type": obj.get("type", ""),
        "name": obj.get("name", ""),
        "mitre_id": external_id(obj),
        "url": url(obj),
        "path": obj.get("_path", ""),
    }


def tactic_text(obj: dict[str, Any]) -> str:
    phases = obj.get("kill_chain_phases", [])
    return ", ".join(p.get("phase_name", "") for p in phases if p.get("phase_name"))


def object_text(obj: dict[str, Any], objects: dict[str, dict[str, Any]], rels: dict[str, list[dict[str, Any]]]) -> str:
    parts = [
        f"Name: {obj.get('name', '')}",
        f"MITRE ID: {external_id(obj)}",
        f"Type: {obj.get('type', '')}",
        f"Tactics: {tactic_text(obj)}",
        f"Platforms: {', '.join(obj.get('x_mitre_platforms', []) or [])}",
        f"Description: {clean(obj.get('description', ''))}",
        f"Detection: {clean(obj.get('x_mitre_detection', ''))}",
        f"Mitigation: {clean(obj.get('x_mitre_old_attack_id', ''))}",
    ]
    rel_text = relation_lines(obj["id"], objects, rels)
    if rel_text:
        parts.append("Relationships: " + " | ".join(rel_text))
    return "\n".join(p for p in parts if p and not p.endswith(": "))


def _balanced_limit(docs: list[Document], limit: int | None) -> list[Document]:
    if not limit or len(docs) <= limit:
        return docs
    grouped: dict[str, list[Document]] = defaultdict(list)
    for doc in docs:
        grouped[doc.collection].append(doc)

    selected: list[Document] = []
    names = sorted(grouped)
    cursor = 0
    while len(selected) < limit and any(grouped.values()):
        name = names[cursor % len(names)]
        if grouped[name]:
            selected.append(grouped[name].pop(0))
        cursor += 1
    return selected


def iter_documents(base_dir: Path, limit: int | None = None) -> list[Document]:
    objects = load_objects(base_dir)
    rels = relationship_index(objects)
    docs: list[Document] = []

    for obj in objects.values():
        if obj.get("type") == "relationship":
            continue

        text = object_text(obj, objects, rels)
        meta = base_metadata(obj)
        obj_type = obj.get("type")
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))

        if obj_type == "attack-pattern":
            meta["is_subtechnique"] = is_sub
            meta["tactics"] = tactic_text(obj)
            docs.append(Document("attack_db", obj["id"], text, meta))
            if is_sub or rels.get(obj["id"]):
                docs.append(Document("redteam_db", f"redteam::{obj['id']}", text, meta))

        if obj_type in {"intrusion-set", "malware", "tool", "campaign"}:
            docs.append(Document("actor_db", obj["id"], text, meta))
            docs.append(Document("redteam_db", f"tooling::{obj['id']}", text, meta))

        if obj_type in {
            "course-of-action",
            "x-mitre-analytic",
            "x-mitre-detection-strategy",
            "x-mitre-data-source",
            "x-mitre-data-component",
        }:
            docs.append(Document("detection_db", obj["id"], text, meta))

    return _balanced_limit(docs, limit)
