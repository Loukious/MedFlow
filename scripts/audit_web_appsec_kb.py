from __future__ import annotations

import argparse
import json

from rich.console import Console
from rich.table import Table

from medflow_redteam.web_kb import audit_web_appsec_kb
from medflow_ti.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit web AppSec vector collections, sources, and token limits."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the complete machine-readable audit result.",
    )
    args = parser.parse_args()
    settings = load_settings()
    audit = audit_web_appsec_kb(
        settings.chroma_dir,
        settings.embedding_model,
    )
    if args.json:
        print(json.dumps(audit, indent=2))
        return

    console = Console()
    collection_table = Table(
        "Collection",
        "Documents",
        "Input tokens",
        "Max",
        "P50",
        "P95",
        "Over limit",
    )
    for name, metrics in audit["collections"].items():
        collection_table.add_row(
            name,
            f"{metrics['documents']:,}",
            f"{metrics['input_tokens']:,}",
            str(metrics["max_tokens"]),
            str(metrics["p50_tokens"]),
            str(metrics["p95_tokens"]),
            str(metrics["over_limit"]),
        )
    console.print(collection_table)

    source_table = Table("Source", "Selected files", "Documents", "Input tokens")
    source_ids = set(audit["selected_source_files"]) | set(audit["sources"])
    for source in sorted(source_ids):
        metrics = audit["sources"].get(source, {})
        source_table.add_row(
            source,
            f"{audit['selected_source_files'].get(source, 0):,}",
            f"{metrics.get('documents', 0):,}",
            f"{metrics.get('input_tokens', 0):,}",
        )
    console.print(source_table)
    console.print(
        f"Embedding model: [bold]{audit['embedding_model']}[/bold] "
        f"(limit {audit['sequence_limit']} tokens)"
    )


if __name__ == "__main__":
    main()
