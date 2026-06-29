from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table

from medflow_graph.memory import GraphStore, ingest_campaign_report


def print_summary(console: Console, store: GraphStore) -> None:
    summary = store.summary()
    table = Table("Metric", "Value")
    for key, value in summary.items():
        table.add_row(key, str(value))
    console.print(table)


def print_reviews(console: Console, store: GraphStore, limit: int) -> None:
    pending = [review for review in store.reviews.values() if review.status == "pending"]
    if not pending:
        console.print("No pending review items.")
        return
    table = Table("Confidence", "Source", "Target", "Reason")
    for review in sorted(pending, key=lambda item: item.confidence, reverse=True)[:limit]:
        source = store.nodes.get(review.source)
        target = store.nodes.get(review.target)
        table.add_row(
            f"{review.confidence:.3f}",
            f"{source.type if source else '?'}: {source.canonical_name if source else review.source}"[:80],
            f"{target.type if target else '?'}: {target.canonical_name if target else review.target}"[:80],
            review.reason,
        )
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest MedFlow campaign JSON reports into a clean graph-memory store.")
    parser.add_argument("reports", nargs="*", type=Path, help="Campaign JSON report(s) to ingest.")
    parser.add_argument("--graph", type=Path, default=Path("data/graph/medflow_graph.json"), help="Graph JSON store path.")
    parser.add_argument("--dream", action="store_true", help="Run a same-type dedup cleanup pass after ingest.")
    parser.add_argument("--reviews", action="store_true", help="Print pending duplicate-review records.")
    parser.add_argument("--review-limit", type=int, default=20, help="Maximum pending reviews to print.")
    parser.add_argument("--cypher", type=Path, default=None, help="Optional Neo4j Cypher export path.")
    args = parser.parse_args()

    console = Console()
    store = GraphStore.load(args.graph)

    totals = {"created": 0, "merged": 0, "review": 0, "edges": 0}
    for report in args.reports:
        stats = ingest_campaign_report(store, report)
        for key, value in stats.items():
            totals[key] = totals.get(key, 0) + value
        console.print(f"Ingested [bold]{report}[/bold]: {stats}")

    if args.dream:
        result = store.dream_dedup()
        console.print(f"Dream dedup: {result}")

    store.save()
    console.print(f"Saved graph: [bold]{store.path}[/bold]")
    console.print(f"Ingest totals: {totals}")
    print_summary(console, store)

    if args.cypher:
        args.cypher.parent.mkdir(parents=True, exist_ok=True)
        args.cypher.write_text(store.to_cypher(), encoding="utf-8")
        console.print(f"Saved Cypher export: [bold]{args.cypher}[/bold]")

    if args.reviews:
        print_reviews(console, store, args.review_limit)


if __name__ == "__main__":
    main()
