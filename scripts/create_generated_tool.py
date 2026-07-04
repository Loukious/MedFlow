from __future__ import annotations

import argparse
import json
from pathlib import Path

from medflow_redteam.toolsmith import ToolsmithAgent


def main() -> None:
    parser = argparse.ArgumentParser(description="Toolsmith agent for on-demand generated Python tools.")
    parser.add_argument("--lookup", default="", help="Search graph/data cache for a reusable generated tool.")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--id", default="", help="Short tool id without the generated: prefix.")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--template", choices=["tcp_banner"], default=None)
    parser.add_argument("--service", default="")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--prompt", default="", help="LLM generation prompt for a generated tool.")
    parser.add_argument("--provider", choices=["llama", "qwen"], default="llama")
    parser.add_argument("--graph", type=Path, default=Path("data/graph/medflow_graph.json"))
    args = parser.parse_args()

    agent = ToolsmithAgent(graph_path=args.graph, provider=args.provider)

    if args.lookup:
        print(json.dumps(agent.lookup(args.lookup, limit=args.limit), indent=2))
        return

    if not args.id:
        raise SystemExit("--id is required when creating a tool.")

    if args.template == "tcp_banner":
        if not args.service or not args.port:
            raise SystemExit("--template tcp_banner requires --service and --port.")
        result = agent.create_from_template(
            tool_id=args.id,
            template=args.template,
            service=args.service,
            port=args.port,
            overwrite=args.overwrite,
        )
    elif args.prompt:
        result = agent.create_from_prompt(tool_id=args.id, prompt=args.prompt, overwrite=args.overwrite)
    else:
        raise SystemExit("Provide --lookup, --template, or --prompt.")

    print(
        json.dumps(
            {
                "action": result.action,
                "tool_id": (result.spec or {}).get("id"),
                "paths": {key: str(value) for key, value in (result.paths or {}).items()},
                "graph_node_id": result.graph_node_id,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
