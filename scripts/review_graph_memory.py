from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table

from medflow_graph.memory import GraphStore


def print_reviews(store: GraphStore, limit: int) -> None:
    console = Console()
    table = Table("Review ID", "Confidence", "Source", "Target", "Reason")
    for review in store.pending_reviews()[:limit]:
        source = store.nodes.get(review.source)
        target = store.nodes.get(review.target)
        table.add_row(
            review.id,
            f"{review.confidence:.3f}",
            f"{source.type if source else '?'}: {source.canonical_name if source else review.source}"[:90],
            f"{target.type if target else '?'}: {target.canonical_name if target else review.target}"[:90],
            review.reason,
        )
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="Review and apply MedFlow graph-memory duplicate decisions.")
    parser.add_argument("--graph", type=Path, default=Path("data/graph/medflow_graph.json"))
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--confirm", default="", help="Review id to confirm and merge.")
    parser.add_argument("--reject", default="", help="Review id to reject.")
    args = parser.parse_args()

    store = GraphStore.load(args.graph)
    if args.confirm and args.reject:
        raise SystemExit("Use either --confirm or --reject, not both.")
    if args.confirm:
        review = store.apply_review(args.confirm, "confirm")
        store.save()
        print(f"Confirmed {review.id}")
    elif args.reject:
        review = store.apply_review(args.reject, "reject")
        store.save()
        print(f"Rejected {review.id}")
    print_reviews(store, args.limit)


if __name__ == "__main__":
    main()
