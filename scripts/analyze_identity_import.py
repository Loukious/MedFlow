from __future__ import annotations

import argparse
import json
from pathlib import Path

from medflow_redteam.identity import analyze_bloodhound_export, analyze_identity_logs


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze exported identity data without live authentication attempts.")
    parser.add_argument("path", type=Path)
    parser.add_argument("--type", choices=["logs", "bloodhound"], default="logs")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    result = analyze_bloodhound_export(args.path) if args.type == "bloodhound" else analyze_identity_logs(args.path)
    payload = json.dumps(result, indent=2, default=str)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload)


if __name__ == "__main__":
    main()
