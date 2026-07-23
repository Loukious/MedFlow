from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from medflow_redteam.web_app import WebAuthContext
from medflow_redteam.web_stateful import run_stateful_api_assessment


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the bounded MedFlow stateful differential API agent.")
    parser.add_argument("target", help="Allowlisted lab target hostname or IP address.")
    parser.add_argument("--ports", default="80,443,5000,8080", help="Comma-separated API ports.")
    parser.add_argument("--auth-contexts", default=None, help="Optional JSON file with two pre-authenticated contexts.")
    parser.add_argument("--execution-mode", choices=["safe", "aggressive_lab"], default="safe")
    parser.add_argument("--max-requests", type=int, default=40)
    parser.add_argument("--max-workflows", type=int, default=8)
    parser.add_argument("--output", default=None, help="Optional JSON output path.")
    args = parser.parse_args()

    result = run_stateful_api_assessment(
        args.target,
        parse_ports(args.ports),
        auth_contexts=load_auth_contexts(args.auth_contexts),
        execution_mode=args.execution_mode,
        max_requests=args.max_requests,
        max_workflows=args.max_workflows,
    )
    rendered = json.dumps(result, indent=2)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered)


def parse_ports(value: str) -> list[int]:
    ports = sorted({int(item.strip()) for item in value.split(",") if item.strip()})
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise SystemExit("Provide one or more valid ports.")
    return ports


def load_auth_contexts(path: str | None) -> list[WebAuthContext]:
    if not path:
        return []
    payload: Any = json.loads(Path(path).read_text(encoding="utf-8"))
    items = payload.get("contexts", []) if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        raise SystemExit("Auth context JSON must be a list or an object containing contexts.")
    return [
        WebAuthContext(
            name=str(item.get("name") or f"principal-{index + 1}"),
            headers={str(key): str(value) for key, value in (item.get("headers") or {}).items()},
            cookies={str(key): str(value) for key, value in (item.get("cookies") or {}).items()},
            owned_object_ids=[str(value) for value in item.get("owned_object_ids") or []],
        )
        for index, item in enumerate(items[:4])
        if isinstance(item, dict)
    ]


if __name__ == "__main__":
    main()
