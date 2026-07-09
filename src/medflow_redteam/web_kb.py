from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from medflow_ti.config import ROOT
from medflow_ti.mitre_loader import Document
from medflow_ti.vector_store import add_documents, query


WEB_COLLECTIONS = ("web_methodology_db", "web_payload_db")
SEED_PATH = ROOT / "data" / "web_appsec_seed" / "web_appsec_seed.json"
SOURCE_ROOT = ROOT / "data" / "web_appsec_sources"


def load_seed_documents(path: Path = SEED_PATH) -> list[Document]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    docs: list[Document] = []
    for item in payload.get("documents", []):
        docs.append(
            Document(
                collection=str(item.get("collection") or "web_methodology_db"),
                doc_id=str(item["id"]),
                text=web_doc_text(item),
                metadata=web_doc_metadata(item, path),
            )
        )
    return docs


def web_doc_text(item: dict[str, Any]) -> str:
    parts = [
        f"Title: {item.get('title', '')}",
        f"Category: {item.get('category', '')}",
        f"CWE: {', '.join(item.get('cwe', []) or [])}",
        f"OWASP: {', '.join(item.get('owasp', []) or [])}",
        f"Probe class: {item.get('probe_class', '')}",
        f"Text: {clean_text(item.get('text', ''))}",
    ]
    return "\n".join(part for part in parts if not part.endswith(": "))


def web_doc_metadata(item: dict[str, Any], path: Path) -> dict[str, str | int | float | bool]:
    return {
        "type": "web-appsec",
        "name": str(item.get("title", "")),
        "category": str(item.get("category", "")),
        "source": str(item.get("source", "")),
        "probe_class": str(item.get("probe_class", "")),
        "cwe": ", ".join(item.get("cwe", []) or []),
        "owasp": ", ".join(item.get("owasp", []) or []),
        "path": str(path),
        "url": str(item.get("url", "")),
        "mitre_id": "",
        "stix_id": "",
    }


def iter_markdown_documents(root: Path = SOURCE_ROOT, limit: int | None = None) -> list[Document]:
    docs: list[Document] = []
    if not root.exists():
        return docs
    for path in sorted([*root.rglob("*.md"), *root.rglob("*.txt")]):
        text = clean_text(path.read_text(encoding="utf-8", errors="replace"))
        if not text:
            continue
        category = category_from_path(path)
        collection = "web_payload_db" if "payload" in category else "web_methodology_db"
        for index, chunk in enumerate(chunk_text(text)):
            doc_id = f"websrc::{path.relative_to(root)}::{index}"
            docs.append(
                Document(
                    collection=collection,
                    doc_id=doc_id,
                    text=f"Source file: {path.name}\nCategory: {category}\n{chunk}",
                    metadata={
                        "type": "web-appsec-source",
                        "name": path.stem,
                        "category": category,
                        "source": path.parts[-3] if len(path.parts) >= 3 else path.parent.name,
                        "probe_class": "",
                        "cwe": "",
                        "owasp": "",
                        "path": str(path),
                        "url": "",
                        "mitre_id": "",
                        "stix_id": "",
                    },
                )
            )
            if limit and len(docs) >= limit:
                return docs
    return docs


def ingest_web_appsec_kb(chroma_path: Path, model_name: str, source_root: Path = SOURCE_ROOT, limit: int | None = None) -> dict[str, int]:
    docs = [*load_seed_documents(), *iter_markdown_documents(source_root, limit=limit)]
    if not docs:
        return {}
    return add_documents(chroma_path, docs, model_name)


def query_web_appsec(chroma_path: Path, question: str, model_name: str, n_results: int = 6) -> list[dict[str, Any]]:
    return query(chroma_path, list(WEB_COLLECTIONS), question, model_name, n_results=n_results)


def clean_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def chunk_text(text: str, chunk_size: int = 1800, overlap: int = 250) -> list[str]:
    if len(text) <= chunk_size:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        chunk = text[start : start + chunk_size].strip()
        if chunk:
            chunks.append(chunk)
        start += max(1, chunk_size - overlap)
    return chunks


def category_from_path(path: Path) -> str:
    text = " ".join(part.lower() for part in path.parts)
    for category, needles in {
        "sql_injection": ["sql", "sqli", "injection"],
        "xss": ["xss", "cross_site_scripting"],
        "idor": ["idor", "authorization", "access-control", "access_control"],
        "path_traversal": ["traversal", "file", "lfi"],
        "ssti": ["ssti", "template"],
        "api": ["api"],
        "payload": ["payload"],
    }.items():
        if any(needle in text for needle in needles):
            return category
    return "web_appsec"
