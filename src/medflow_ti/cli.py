from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .agents import AGENTS, answer_question
from .config import load_settings
from .embeddings import embedding_device
from .healthcare import ingest_healthcare_csv
from .vector_store import build_from_mitre, client


console = Console()


def cmd_build(args: argparse.Namespace) -> None:
    settings = load_settings()
    console.print(f"Embedding device: [bold]{embedding_device()}[/bold]")
    counts = build_from_mitre(settings.mitre_dir, settings.chroma_dir, settings.embedding_model, limit=args.limit)
    table = Table("Collection", "Documents")
    for name, count in sorted(counts.items()):
        table.add_row(name, str(count))
    console.print(table)


def cmd_status(_: argparse.Namespace) -> None:
    settings = load_settings()
    db = client(settings.chroma_dir)
    table = Table("Collection", "Count")
    for collection in db.list_collections():
        table.add_row(collection.name, str(collection.count()))
    console.print(f"Embedding device: [bold]{embedding_device()}[/bold]")
    console.print(table)


def cmd_ask(args: argparse.Namespace) -> None:
    settings = load_settings()
    result = answer_question(settings, args.agent, args.question, n_results=args.results, provider=args.provider)
    console.print(result.answer)
    if args.sources:
        table = Table("Collection", "MITRE ID", "Name", "URL")
        for hit in result.sources:
            meta = hit.get("metadata") or {}
            table.add_row(hit["collection"], meta.get("mitre_id", ""), meta.get("name", ""), meta.get("url", ""))
        console.print(table)


def cmd_ingest_healthcare(args: argparse.Namespace) -> None:
    settings = load_settings()
    counts = ingest_healthcare_csv(Path(args.path), settings.chroma_dir, settings.embedding_model)
    console.print(counts or "No CSV files found.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MedFlow AI threat intelligence and red-team RAG platform")
    sub = parser.add_subparsers(required=True)

    build = sub.add_parser("build", help="Build the four Chroma vector databases from MITRE CTI")
    build.add_argument("--limit", type=int, default=None, help="Optional document limit for smoke tests")
    build.set_defaults(func=cmd_build)

    status = sub.add_parser("status", help="Show vector collection counts")
    status.set_defaults(func=cmd_status)

    ask = sub.add_parser("ask", help="Ask one of the agents")
    ask.add_argument("agent", choices=sorted(AGENTS))
    ask.add_argument("question")
    ask.add_argument("--provider", choices=["llama", "qwen"], default="llama")
    ask.add_argument("--results", type=int, default=8)
    ask.add_argument("--sources", action="store_true")
    ask.set_defaults(func=cmd_ask)

    ingest = sub.add_parser("ingest-healthcare-csv", help="Ingest optional healthcare CSV data into detection_db")
    ingest.add_argument("path")
    ingest.set_defaults(func=cmd_ingest_healthcare)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
