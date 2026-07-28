from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml

from medflow_ti.config import ROOT
from medflow_ti.embeddings import embedding_max_sequence_length, embedding_tokenizer
from medflow_ti.mitre_loader import Document
from medflow_ti.vector_store import (
    add_documents,
    client,
    query,
    reset_named_collections,
)


WEB_COLLECTIONS = ("web_methodology_db", "web_payload_db")
SEED_PATH = ROOT / "data" / "web_appsec_seed" / "web_appsec_seed.json"
SOURCE_ROOT = ROOT / "data" / "web_appsec_sources"
SOURCE_CONFIG = ROOT / "config" / "web_appsec_sources.json"
SYNC_MANIFEST = SOURCE_ROOT / "sync_manifest.json"
DEFAULT_TOKEN_OVERLAP = 64
MAX_SOURCE_FILE_BYTES = 2_000_000


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


def load_source_config(path: Path = SOURCE_CONFIG) -> dict[str, Any]:
    if not path.exists():
        return {"sources": []}
    return json.loads(path.read_text(encoding="utf-8"))


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
        "type": "web-appsec-seed",
        "name": str(item.get("title", "")),
        "category": str(item.get("category", "")),
        "source": str(item.get("source", "")),
        "source_type": "curated-seed",
        "source_path": str(path.name),
        "source_revision": "",
        "probe_class": str(item.get("probe_class", "")),
        "cwe": ", ".join(item.get("cwe", []) or []),
        "owasp": ", ".join(item.get("owasp", []) or []),
        "path": str(path),
        "url": str(item.get("url", "")),
        "mitre_id": "",
        "stix_id": "",
    }


def iter_markdown_documents(
    root: Path = SOURCE_ROOT,
    limit: int | None = None,
    *,
    model_name: str = "BAAI/bge-base-en-v1.5",
    config_path: Path = SOURCE_CONFIG,
    tokenizer: Any | None = None,
    max_tokens: int | None = None,
) -> list[Document]:
    """Load configured web sources using source-specific, content-safe policies."""
    if not root.exists():
        return []

    active_tokenizer = tokenizer or embedding_tokenizer(model_name)
    token_limit = max_tokens or embedding_max_sequence_length(model_name)
    docs: list[Document] = []
    seen_content: set[str] = set()

    for source in load_source_config(config_path).get("sources", []):
        ingestion = source.get("ingestion")
        if not isinstance(ingestion, dict):
            continue
        source_id = str(source.get("id", "")).strip()
        source_dir = root / source_id
        if not source_id or not source_dir.is_dir():
            continue

        revision = repository_revision(source_dir)
        for path in selected_source_paths(source_dir, ingestion):
            if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
                continue
            mode = str(ingestion.get("mode", "markdown"))
            if mode == "nuclei_metadata":
                parsed = nuclei_metadata_text(path, source_dir)
                if parsed is None:
                    continue
                title, category, body, extra_metadata = parsed
            else:
                raw = path.read_text(encoding="utf-8", errors="replace")
                title = markdown_title(raw) or path.stem.replace("_", " ")
                category = category_from_path(path, source_dir)
                body = markdown_to_prose(
                    raw,
                    strip_code_blocks=bool(ingestion.get("strip_code_blocks", False)),
                    taxonomy_only=mode == "markdown_taxonomy",
                )
                extra_metadata = {}
            if not body:
                continue

            relative_path = path.relative_to(source_dir)
            source_url = source_file_url(str(source.get("url", "")), relative_path, revision)
            prefix = "\n".join(
                [
                    f"Title: {title}",
                    f"Category: {category}",
                    f"Source: {source.get('name', source_id)}",
                    f"Source type: {source.get('type', '')}",
                    f"Source path: {relative_path.as_posix()}",
                ]
            )
            chunks = chunk_text_tokens(
                body,
                active_tokenizer,
                max_tokens=token_limit,
                overlap_tokens=DEFAULT_TOKEN_OVERLAP,
                prefix=prefix,
            )
            for index, text in enumerate(chunks):
                content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
                if content_hash in seen_content:
                    continue
                seen_content.add(content_hash)
                metadata: dict[str, str | int | float | bool] = {
                    "type": (
                        "nuclei-template-metadata"
                        if mode == "nuclei_metadata"
                        else "web-payload-taxonomy"
                        if mode == "markdown_taxonomy"
                        else "web-appsec-methodology"
                    ),
                    "name": title,
                    "category": category,
                    "source": source_id,
                    "source_type": str(source.get("type", "")),
                    "source_path": relative_path.as_posix(),
                    "source_revision": revision,
                    "probe_class": "",
                    "cwe": "",
                    "owasp": "",
                    "path": str(path),
                    "url": source_url,
                    "mitre_id": "",
                    "stix_id": "",
                    **extra_metadata,
                }
                docs.append(
                    Document(
                        collection=str(ingestion.get("collection", "web_methodology_db")),
                        doc_id=f"websrc::{source_id}::{relative_path.as_posix()}::{index}",
                        text=text,
                        metadata=metadata,
                    )
                )
                if limit is not None and len(docs) >= limit:
                    return docs
    return docs


def ingest_web_appsec_kb(
    chroma_path: Path,
    model_name: str,
    source_root: Path = SOURCE_ROOT,
    limit: int | None = None,
    *,
    reset: bool = True,
) -> dict[str, int]:
    tokenizer = embedding_tokenizer(model_name)
    max_tokens = embedding_max_sequence_length(model_name)
    docs = [
        *load_seed_documents(),
        *iter_markdown_documents(
            source_root,
            limit=limit,
            model_name=model_name,
            tokenizer=tokenizer,
            max_tokens=max_tokens,
        ),
    ]
    docs = enforce_token_budget(docs, tokenizer, max_tokens)
    if not docs:
        return {}
    if reset:
        reset_named_collections(chroma_path, list(WEB_COLLECTIONS))
    return add_documents(chroma_path, docs, model_name)


def query_web_appsec(
    chroma_path: Path,
    question: str,
    model_name: str,
    n_results: int = 6,
) -> list[dict[str, Any]]:
    return query(
        chroma_path,
        list(WEB_COLLECTIONS),
        question,
        model_name,
        n_results=n_results,
    )


def audit_web_appsec_kb(
    chroma_path: Path,
    model_name: str,
    *,
    source_root: Path = SOURCE_ROOT,
    manifest_path: Path = SYNC_MANIFEST,
) -> dict[str, Any]:
    tokenizer = embedding_tokenizer(model_name)
    sequence_limit = embedding_max_sequence_length(model_name)
    special_tokens = tokenizer_special_tokens(tokenizer)
    database = client(chroma_path)
    collections: dict[str, dict[str, Any]] = {}
    source_totals: dict[str, dict[str, int]] = {}

    for name in WEB_COLLECTIONS:
        try:
            collection = database.get_collection(name)
        except Exception:
            collections[name] = {
                "documents": 0,
                "input_tokens": 0,
                "max_tokens": 0,
                "p50_tokens": 0,
                "p95_tokens": 0,
                "over_limit": 0,
            }
            continue
        lengths: list[int] = []
        for offset in range(0, collection.count(), 500):
            batch = collection.get(
                limit=min(500, collection.count() - offset),
                offset=offset,
                include=["documents", "metadatas"],
            )
            for document, metadata in zip(
                batch.get("documents", []),
                batch.get("metadatas", []),
                strict=False,
            ):
                length = token_count(tokenizer, document) + special_tokens
                lengths.append(length)
                source = str((metadata or {}).get("source") or "unknown")
                source_total = source_totals.setdefault(
                    source,
                    {"documents": 0, "input_tokens": 0},
                )
                source_total["documents"] += 1
                source_total["input_tokens"] += length
        lengths.sort()
        collections[name] = {
            "documents": len(lengths),
            "input_tokens": sum(lengths),
            "max_tokens": max(lengths, default=0),
            "p50_tokens": percentile(lengths, 0.50),
            "p95_tokens": percentile(lengths, 0.95),
            "over_limit": sum(length > sequence_limit for length in lengths),
        }

    selected_files: dict[str, int] = {}
    for source in load_source_config().get("sources", []):
        ingestion = source.get("ingestion")
        source_id = str(source.get("id", ""))
        source_dir = source_root / source_id
        if isinstance(ingestion, dict) and source_dir.is_dir():
            selected_files[source_id] = len(
                selected_source_paths(source_dir, ingestion)
            )

    manifest: dict[str, Any] = {}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return {
        "embedding_model": model_name,
        "sequence_limit": sequence_limit,
        "collections": collections,
        "sources": dict(sorted(source_totals.items())),
        "selected_source_files": selected_files,
        "sync_manifest": manifest,
    }


def selected_source_paths(source_dir: Path, ingestion: dict[str, Any]) -> list[Path]:
    includes = [str(item) for item in ingestion.get("include", [])]
    excludes = [str(item) for item in ingestion.get("exclude", [])]
    selected: set[Path] = set()
    for pattern in includes:
        selected.update(path for path in source_dir.glob(pattern) if path.is_file())
    return sorted(
        path
        for path in selected
        if not path_matches_any(path.relative_to(source_dir), excludes)
    )


def path_matches_any(path: Path, patterns: list[str]) -> bool:
    value = path.as_posix()
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def markdown_title(text: str) -> str:
    match = re.search(r"(?m)^#\s+(.+?)\s*$", text)
    return clean_text(match.group(1)) if match else ""


def markdown_to_prose(
    value: str,
    *,
    strip_code_blocks: bool,
    taxonomy_only: bool = False,
) -> str:
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\A---\n.*?\n---\n", "", text, flags=re.DOTALL)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    if strip_code_blocks:
        text = re.sub(r"```.*?```", "\n", text, flags=re.DOTALL)
        text = re.sub(r"~~~.*?~~~", "\n", text, flags=re.DOTALL)
    else:
        text = re.sub(r"(?m)^\s*(```|~~~)[^\n]*$", "", text)
    text = re.sub(r"!\[[^\]]*]\([^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)]\([^)]*\)", r"\1", text)
    text = re.sub(r"<https?://[^>]+>", "", text)

    lines: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if re.fullmatch(r"\|?[\s:|-]+\|?", line):
            continue
        if taxonomy_only:
            line = re.sub(r"`[^`\n]+`", "", line)
            if line.startswith("|"):
                continue
            visible = re.sub(r"[^A-Za-z]+", "", line)
            if line and not visible:
                continue
        line = re.sub(r"^#{1,6}\s*", "", line)
        line = re.sub(r"^\s*>\s?", "", line)
        line = re.sub(r"^\s*[-*+]\s+", "", line)
        line = re.sub(r"^\s*\d+\.\s+", "", line)
        line = re.sub(r"[*_]{1,3}([^*_]+)[*_]{1,3}", r"\1", line)
        line = re.sub(r"\s+", " ", line).strip()
        if line:
            lines.append(line)
        elif lines and lines[-1] != "":
            lines.append("")
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def nuclei_metadata_text(
    path: Path,
    source_dir: Path,
) -> tuple[str, str, str, dict[str, str | int | float | bool]] | None:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except yaml.YAMLError:
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("info"), dict):
        return None

    info = payload["info"]
    classification = info.get("classification")
    classification = classification if isinstance(classification, dict) else {}
    template_metadata = info.get("metadata")
    template_metadata = template_metadata if isinstance(template_metadata, dict) else {}
    template_id = scalar_text(payload.get("id"))
    title = scalar_text(info.get("name")) or template_id or path.stem
    severity = scalar_text(info.get("severity"))
    tags = scalar_text(info.get("tags"))
    cve = scalar_text(classification.get("cve-id"))
    cwe = scalar_text(classification.get("cwe-id"))
    relative = path.relative_to(source_dir)
    category_part = relative.parts[1] if len(relative.parts) > 1 else "http"
    category = f"nuclei_{slug(category_part)}"
    body_parts = [
        f"Nuclei template ID: {template_id}",
        f"Name: {title}",
        f"Template class: {category_part.replace('-', ' ')}",
        f"Severity: {severity}",
        f"Tags: {tags}",
        f"CVE: {cve}",
        f"CWE: {cwe}",
        f"Vendor: {scalar_text(template_metadata.get('vendor'))}",
        f"Product: {scalar_text(template_metadata.get('product'))}",
        f"Description: {clean_text(info.get('description'))}",
        f"Impact: {clean_text(info.get('impact'))}",
        f"Remediation: {clean_text(info.get('remediation'))}",
    ]
    body = "\n".join(part for part in body_parts if not part.endswith(": "))
    if not body:
        return None
    metadata: dict[str, str | int | float | bool] = {
        "template_id": template_id,
        "severity": severity,
        "tags": tags[:4000],
        "cwe": cwe,
        "cve": cve,
        "vendor": scalar_text(template_metadata.get("vendor")),
        "product": scalar_text(template_metadata.get("product")),
    }
    return title, category, body, metadata


def scalar_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        items = [scalar_text(item) for item in value]
        return ", ".join(item for item in items if item)
    if isinstance(value, dict):
        items = [(key, scalar_text(item)) for key, item in value.items()]
        return ", ".join(
            f"{key}={item}"
            for key, item in items
            if item
        )
    return clean_text(value)


def chunk_text_tokens(
    text: str,
    tokenizer: Any,
    *,
    max_tokens: int,
    overlap_tokens: int = DEFAULT_TOKEN_OVERLAP,
    prefix: str = "",
) -> list[str]:
    clean_prefix = prefix.strip()
    special_tokens = tokenizer_special_tokens(tokenizer)
    prefix_cost = token_count(tokenizer, f"{clean_prefix}\n") if clean_prefix else 0
    content_budget = max_tokens - special_tokens - prefix_cost
    if content_budget < 8:
        raise ValueError(
            f"Document prefix uses too much of the {max_tokens}-token embedding budget."
        )

    content_ids = encode_tokens(tokenizer, text)
    if not content_ids:
        return [clean_prefix] if clean_prefix else []
    overlap = min(max(0, overlap_tokens), content_budget - 1)
    chunks: list[str] = []
    start = 0
    while start < len(content_ids):
        candidate_ids = list(content_ids[start : start + content_budget])
        candidate = tokenizer.decode(
            candidate_ids,
            skip_special_tokens=True,
            clean_up_tokenization_spaces=True,
        ).strip()
        full_text = f"{clean_prefix}\n{candidate}".strip() if clean_prefix else candidate
        while candidate_ids and token_count(tokenizer, full_text) + special_tokens > max_tokens:
            candidate_ids.pop()
            candidate = tokenizer.decode(
                candidate_ids,
                skip_special_tokens=True,
                clean_up_tokenization_spaces=True,
            ).strip()
            full_text = (
                f"{clean_prefix}\n{candidate}".strip() if clean_prefix else candidate
            )
        if not candidate_ids:
            raise ValueError("Unable to fit source text into the embedding token budget.")
        chunks.append(full_text)
        consumed = len(candidate_ids)
        if start + consumed >= len(content_ids):
            break
        start += max(1, consumed - overlap)
    return chunks


def enforce_token_budget(
    docs: list[Document],
    tokenizer: Any,
    max_tokens: int,
) -> list[Document]:
    bounded: list[Document] = []
    special_tokens = tokenizer_special_tokens(tokenizer)
    for doc in docs:
        if token_count(tokenizer, doc.text) + special_tokens <= max_tokens:
            bounded.append(doc)
            continue
        chunks = chunk_text_tokens(
            doc.text,
            tokenizer,
            max_tokens=max_tokens,
            overlap_tokens=DEFAULT_TOKEN_OVERLAP,
        )
        for index, chunk in enumerate(chunks):
            bounded.append(
                Document(
                    collection=doc.collection,
                    doc_id=f"{doc.doc_id}::token::{index}",
                    text=chunk,
                    metadata=doc.metadata,
                )
            )
    return bounded


def token_count(tokenizer: Any, text: str) -> int:
    return len(encode_tokens(tokenizer, text))


def encode_tokens(tokenizer: Any, text: str) -> list[Any]:
    try:
        return list(
            tokenizer.encode(
                text,
                add_special_tokens=False,
                verbose=False,
            )
        )
    except TypeError:
        return list(tokenizer.encode(text, add_special_tokens=False))


def tokenizer_special_tokens(tokenizer: Any) -> int:
    counter = getattr(tokenizer, "num_special_tokens_to_add", None)
    return int(counter(pair=False)) if callable(counter) else 2


def percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    index = min(len(values) - 1, max(0, int(len(values) * fraction)))
    return values[index]


def repository_revision(repository: Path) -> str:
    git_dir = repository / ".git"
    head = git_dir / "HEAD"
    if not head.is_file():
        return ""
    value = head.read_text(encoding="utf-8").strip()
    if not value.startswith("ref: "):
        return value[:40]
    reference = value.removeprefix("ref: ").strip()
    ref_file = git_dir / reference
    if ref_file.is_file():
        return ref_file.read_text(encoding="utf-8").strip()[:40]
    packed_refs = git_dir / "packed-refs"
    if packed_refs.is_file():
        suffix = f" {reference}"
        for line in packed_refs.read_text(encoding="utf-8").splitlines():
            if line.endswith(suffix):
                return line.split(" ", 1)[0][:40]
    return ""


def source_file_url(base_url: str, relative_path: Path, revision: str) -> str:
    if not base_url:
        return ""
    ref = revision or "HEAD"
    encoded_path = quote(relative_path.as_posix(), safe="/")
    return f"{base_url.rstrip('/')}/blob/{ref}/{encoded_path}"


def clean_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def category_from_path(path: Path, source_dir: Path | None = None) -> str:
    try:
        relative = path.relative_to(source_dir) if source_dir else path
    except ValueError:
        relative = path
    normalized = " ".join(relative.parts).lower()
    normalized = re.sub(r"[_/\\-]+", " ", normalized)
    categories = {
        "nosql_injection": ("nosql injection",),
        "sql_injection": ("sql injection", "sqli"),
        "command_injection": ("command injection", "os command"),
        "xss": ("cross site scripting", "xss"),
        "idor": ("insecure direct object", "idor", "authorization", "access control"),
        "path_traversal": ("path traversal", "directory traversal", "file inclusion", "lfi"),
        "ssti": ("server side template", "ssti"),
        "ssrf": ("server side request forgery", "ssrf"),
        "csrf": ("cross site request forgery", "csrf"),
        "xxe": ("xml external entit", "xxe"),
        "deserialization": ("deserialization",),
        "request_smuggling": ("request smuggling",),
        "authentication": ("authentication", "credential", "brute force"),
        "api": (" api ", "graphql"),
    }
    padded = f" {normalized} "
    for category, needles in categories.items():
        if any(needle in padded for needle in needles):
            return category
    return "web_appsec"


def slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "web"
