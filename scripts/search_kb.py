from __future__ import annotations

import argparse
import json
from textwrap import shorten

from rich.console import Console
from rich.table import Table

from medflow_ti.config import load_settings
from medflow_ti.embeddings import embedding_device
from medflow_ti.vector_store import COLLECTIONS, query


COLLECTION_GROUPS = {
    "all": list(COLLECTIONS),
    "redteam": ["redteam_db", "attack_db", "actor_db"],
    "threat_intel": ["attack_db", "actor_db", "detection_db", "redteam_db"],
}


def resolve_collections(values: list[str]) -> list[str]:
    selected: list[str] = []
    for value in values:
        if value in COLLECTION_GROUPS:
            selected.extend(COLLECTION_GROUPS[value])
        elif value in COLLECTIONS:
            selected.append(value)
        else:
            choices = sorted([*COLLECTION_GROUPS, *COLLECTIONS])
            raise SystemExit(f"Unknown collection/group '{value}'. Choose from: {', '.join(choices)}")
    return list(dict.fromkeys(selected))


def print_table(console: Console, hits: list[dict], show_text: bool) -> None:
    table = Table("Rank", "Score", "Collection", "MITRE ID", "Name", "URL")
    for rank, hit in enumerate(hits, 1):
        meta = hit.get("metadata") or {}
        distance = hit.get("distance")
        score_value = hit.get("score")
        if score_value is None and distance is not None:
            score_value = 1 / (1 + float(distance))
        score = "" if score_value is None else f"{float(score_value):.3f}"
        table.add_row(
            str(rank),
            score,
            hit["collection"],
            meta.get("mitre_id", ""),
            meta.get("name", ""),
            meta.get("url", ""),
        )
    console.print(table)

    if show_text:
        for rank, hit in enumerate(hits, 1):
            meta = hit.get("metadata") or {}
            title = " ".join(x for x in [meta.get("mitre_id", ""), meta.get("name", "")] if x).strip()
            console.rule(f"{rank}. {hit['collection']} {title}")
            console.print(hit["document"])


def print_text(console: Console, hits: list[dict], max_chars: int) -> None:
    for rank, hit in enumerate(hits, 1):
        meta = hit.get("metadata") or {}
        distance = hit.get("distance")
        score_value = hit.get("score")
        if score_value is None and distance is not None:
            score_value = 1 / (1 + float(distance))
        score = "" if score_value is None else f"{float(score_value):.3f}"
        title = " ".join(x for x in [meta.get("mitre_id", ""), meta.get("name", "")] if x).strip()
        console.print(f"\n[{rank}] score={score} collection={hit['collection']} {title}")
        if meta.get("url"):
            console.print(meta["url"])
        console.print(shorten(hit["document"], width=max_chars, placeholder=" ..."))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Similarity search the MedFlow Chroma knowledge bases without using an LLM."
    )
    parser.add_argument("query", nargs="*", help="Search query. Omit for interactive mode.")
    parser.add_argument(
        "--collection",
        "-c",
        action="append",
        default=None,
        help=(
            "Collection or group to search. May be repeated. "
            "Choices: all, redteam, threat_intel, attack_db, redteam_db, actor_db, detection_db."
        ),
    )
    parser.add_argument("--results", "-k", type=int, default=8, help="Number of ranked hits to return.")
    parser.add_argument("--format", choices=["table", "text", "json"], default="table")
    parser.add_argument("--show-text", action="store_true", help="With table output, print full document text below.")
    parser.add_argument("--max-chars", type=int, default=1200, help="Max characters per hit in text output.")
    args = parser.parse_args()

    question = " ".join(args.query).strip()
    if not question:
        question = input("Knowledge-base search query: ").strip()
    if not question:
        raise SystemExit("No query provided.")

    settings = load_settings()
    collections = resolve_collections(args.collection or ["all"])
    hits = query(settings.chroma_dir, collections, question, settings.embedding_model, n_results=args.results)

    if args.format == "json":
        print(json.dumps(hits, indent=2))
        return

    console = Console()
    console.print(f"Embedding device: [bold]{embedding_device()}[/bold]")
    console.print(f"Searched: {', '.join(collections)}")
    if args.format == "text":
        print_text(console, hits, args.max_chars)
    else:
        print_table(console, hits, args.show_text)


if __name__ == "__main__":
    main()
