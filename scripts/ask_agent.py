from __future__ import annotations

import argparse

from rich.console import Console
from rich.table import Table

from medflow_ti.agents import AGENTS, answer_question
from medflow_ti.config import load_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Send your own prompt to a MedFlow agent.")
    parser.add_argument("agent", choices=sorted(AGENTS), help="Agent to ask.")
    parser.add_argument("prompt", nargs="*", help="Prompt text. Omit for interactive mode.")
    parser.add_argument("--provider", choices=["llama", "qwen"], default="llama", help="LLM provider/model to use.")
    parser.add_argument("--results", type=int, default=8, help="Number of retrieved sources.")
    parser.add_argument("--sources", action="store_true", help="Show retrieved source rows.")
    args = parser.parse_args()

    question = " ".join(args.prompt).strip()
    if not question:
        question = input(f"Prompt for {args.agent}: ").strip()
    if not question:
        raise SystemExit("No prompt provided.")

    console = Console()
    result = answer_question(load_settings(), args.agent, question, n_results=args.results, provider=args.provider)
    console.print(result.answer)

    if args.sources:
        table = Table("Collection", "MITRE ID", "Name", "URL")
        for hit in result.sources:
            meta = hit.get("metadata") or {}
            table.add_row(hit["collection"], meta.get("mitre_id", ""), meta.get("name", ""), meta.get("url", ""))
        console.print(table)


if __name__ == "__main__":
    main()
