from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Any

import chromadb
from chromadb.config import Settings as ChromaSettings

from .embeddings import embed_texts
from .mitre_loader import Document, iter_documents


COLLECTIONS = ("attack_db", "redteam_db", "actor_db", "detection_db")

STOPWORDS = {
    "about",
    "against",
    "attack",
    "attacks",
    "detect",
    "does",
    "from",
    "help",
    "helps",
    "hospital",
    "hospitals",
    "healthcare",
    "medical",
    "portal",
    "portals",
    "rule",
    "rules",
    "that",
    "what",
    "which",
    "with",
}

SECURITY_PHRASES = {
    "mfa": ("mfa", "multi factor", "multifactor", "2fa", "two factor"),
    "siem": ("siem", "detection rule", "analytic", "analytics", "log source", "syslog"),
    "fatigue": ("fatigue", "push bombing", "push spam", "prompt bombing", "prompt spam"),
    "authentication": ("authentication", "authenticator", "login", "logon", "sign-in", "signin"),
}


def client(path: Path) -> chromadb.PersistentClient:
    path.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(
        path=str(path),
        settings=ChromaSettings(anonymized_telemetry=False),
    )


def reset_collections(chroma_path: Path) -> None:
    db = client(chroma_path)
    for name in COLLECTIONS:
        try:
            db.delete_collection(name)
        except Exception:
            pass


def add_documents(chroma_path: Path, docs: list[Document], model_name: str) -> dict[str, int]:
    db = client(chroma_path)
    grouped: dict[str, list[Document]] = defaultdict(list)
    for doc in docs:
        grouped[doc.collection].append(doc)

    counts: dict[str, int] = {}
    for collection_name, items in grouped.items():
        collection = db.get_or_create_collection(collection_name)
        counts[collection_name] = len(items)
        for start in range(0, len(items), 256):
            batch = items[start : start + 256]
            texts = [item.text for item in batch]
            collection.upsert(
                ids=[item.doc_id for item in batch],
                documents=texts,
                metadatas=[item.metadata for item in batch],
                embeddings=embed_texts(texts, model_name),
            )
    return counts


def build_from_mitre(mitre_dir: Path, chroma_path: Path, model_name: str, limit: int | None = None) -> dict[str, int]:
    docs = iter_documents(mitre_dir, limit=limit)
    reset_collections(chroma_path)
    return add_documents(chroma_path, docs, model_name)


def _tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9][a-z0-9_-]{1,}", text.lower()) if token not in STOPWORDS}


def _phrase_hits(text: str, question_terms: set[str]) -> int:
    text = text.lower()
    score = 0
    for term, phrases in SECURITY_PHRASES.items():
        if term in question_terms and any(phrase in text for phrase in phrases):
            score += 1
    return score


def _rerank_score(question: str, hit: dict) -> tuple[float, float, float]:
    distance = hit.get("distance")
    semantic_score = 0.0 if distance is None else 1 / (1 + float(distance))
    metadata = hit.get("metadata") or {}
    searchable = " ".join(
        str(value)
        for value in [
            hit.get("document", ""),
            metadata.get("mitre_id", ""),
            metadata.get("name", ""),
            metadata.get("type", ""),
            metadata.get("dataset", ""),
            metadata.get("source_file", ""),
        ]
        if value
    )

    query_terms = _tokens(question)
    doc_terms = _tokens(searchable)
    overlap = query_terms & doc_terms
    overlap_score = len(overlap) / max(len(query_terms), 1)
    phrase_score = _phrase_hits(searchable, query_terms)
    lexical_score = min(1.0, overlap_score + (phrase_score * 0.28))

    score = (semantic_score * 0.62) + (lexical_score * 0.38)
    detection_intent = bool(query_terms & {"siem", "detection", "analytic", "analytics"})
    if query_terms and not overlap:
        score -= 0.18
    if metadata.get("type") == "healthcare-dataset-row" and query_terms and not (overlap - {"cve", "hospital"}):
        score -= 0.12
    if metadata.get("type") in {"attack-technique", "attack-mitigation", "attack-detection"} and lexical_score:
        score += 0.04
    if detection_intent and metadata.get("type") == "x-mitre-analytic" and lexical_score:
        score += 0.18
    if detection_intent and metadata.get("type") == "course-of-action":
        score -= 0.06
    return score, semantic_score, lexical_score


def _lexical_candidates(collection: Any, collection_name: str, question: str, limit: int) -> list[dict]:
    query_terms = _tokens(question)
    if not query_terms:
        return []

    candidates: list[dict] = []
    count = collection.count()
    batch_size = 1000
    for offset in range(0, count, batch_size):
        batch = collection.get(
            limit=min(batch_size, count - offset),
            offset=offset,
            include=["documents", "metadatas"],
        )
        for doc_id, document, metadata in zip(
            batch.get("ids", []),
            batch.get("documents", []),
            batch.get("metadatas", []),
            strict=False,
        ):
            hit = {
                "collection": collection_name,
                "id": doc_id,
                "document": document,
                "metadata": metadata,
                "distance": None,
            }
            score, semantic_score, lexical_score = _rerank_score(question, hit)
            if lexical_score >= 0.32:
                hit["score"] = score
                hit["semantic_score"] = semantic_score
                hit["lexical_score"] = lexical_score
                candidates.append(hit)

    return sorted(candidates, key=lambda x: x.get("score", 0), reverse=True)[:limit]


def query(chroma_path: Path, collection_names: list[str], question: str, model_name: str, n_results: int = 8) -> list[dict]:
    db = client(chroma_path)
    q_emb = embed_texts([question], model_name)[0]
    hits_by_id: dict[tuple[str, str], dict] = {}
    candidate_count = max(n_results * 6, 30)
    for name in collection_names:
        collection = db.get_or_create_collection(name)
        count = collection.count()
        if count == 0:
            continue
        result = collection.query(query_embeddings=[q_emb], n_results=min(candidate_count, count))
        for idx, doc_id in enumerate(result.get("ids", [[]])[0]):
            hit = {
                "collection": name,
                "id": doc_id,
                "document": result.get("documents", [[]])[0][idx],
                "metadata": result.get("metadatas", [[]])[0][idx],
                "distance": result.get("distances", [[]])[0][idx],
            }
            score, semantic_score, lexical_score = _rerank_score(question, hit)
            hit["score"] = score
            hit["semantic_score"] = semantic_score
            hit["lexical_score"] = lexical_score
            hits_by_id[(name, doc_id)] = hit

        for hit in _lexical_candidates(collection, name, question, limit=n_results * 3):
            key = (name, hit["id"])
            existing = hits_by_id.get(key)
            if existing is None or hit.get("score", 0) > existing.get("score", 0):
                hits_by_id[key] = hit
    hits = list(hits_by_id.values())
    return sorted(hits, key=lambda x: x.get("score", 0), reverse=True)[:n_results]
