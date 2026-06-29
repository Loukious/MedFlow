from __future__ import annotations

import argparse
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from medflow_graph.memory import GraphStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Search the MedFlow graph-memory store without using an LLM.")
    parser.add_argument("query", help="Search text, for example: packet capture exposure on web routes")
    parser.add_argument("--graph", type=Path, default=Path("data/graph/medflow_graph.json"), help="Graph JSON store path.")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--types", default="", help="Optional comma-separated node types, for example Route,Finding,Capability.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of a table.")
    args = parser.parse_args()

    store = GraphStore.load(args.graph)
    node_types = {item.strip() for item in args.types.split(",") if item.strip()} or None
    hits = store.search(args.query, limit=args.limit, node_types=node_types)

    if args.json:
        print(json.dumps(hits, indent=2, default=str))
        return

    console = Console()
    table = Table("Rank", "Score", "Type", "Name", "Source")
    for rank, hit in enumerate(hits, 1):
        table.add_row(
            str(rank),
            f"{hit['score']:.3f}",
            hit["type"],
            hit["name"][:90],
            ", ".join(hit.get("source_ids") or [])[:90],
        )
    console.print(table)
    for rank, hit in enumerate(hits, 1):
        console.print(f"\n[bold]{rank}. {hit['type']} · {hit['name']}[/bold]")
        if hit.get("attributes"):
            console.print_json(json.dumps(hit["attributes"], default=str))
        if hit.get("context"):
            console.print(hit["context"][:1200])


if __name__ == "__main__":
    main()
