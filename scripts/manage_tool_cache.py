from __future__ import annotations

import argparse
import json

from medflow_redteam.tool_quality import (
    QUALITY_STATES,
    list_quality_entries,
    record_quality_outcome,
    set_quality_state,
)


OUTCOMES = ["completed", "confirmed", "contradicted", "fixture_passed", "inconclusive", "tool_error"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Review generated-tool cache quality and reliability history.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List cached tool versions and quality scores.")
    list_parser.add_argument("--state", choices=sorted(QUALITY_STATES), default=None)

    inspect_parser = subparsers.add_parser("inspect", help="Inspect one tool ID or artifact hash.")
    inspect_parser.add_argument("reference")

    state_parser = subparsers.add_parser("set-state", help="Perform an explicit lifecycle transition.")
    state_parser.add_argument("reference")
    state_parser.add_argument("state", choices=sorted(QUALITY_STATES))
    state_parser.add_argument("--reason", required=True)
    state_parser.add_argument("--force", action="store_true")

    record_parser = subparsers.add_parser("record", help="Record fixture or independently reviewed ground truth.")
    record_parser.add_argument("reference")
    record_parser.add_argument("outcome", choices=OUTCOMES)
    record_parser.add_argument("--reason", default="")
    record_parser.add_argument(
        "--evidence-id",
        default="",
        help="Unique benchmark, report, or review ID; required for confirmed and contradicted outcomes.",
    )

    args = parser.parse_args()
    entries = list_quality_entries()
    if args.command == "list":
        if args.state:
            entries = [entry for entry in entries if entry.get("state") == args.state]
        print(json.dumps(entries, indent=2))
        return
    if args.command == "inspect":
        matches = [
            entry
            for entry in entries
            if entry.get("tool_id") == args.reference
            or entry.get("artifact_hash") == args.reference
            or str(entry.get("artifact_hash") or "").startswith(args.reference)
        ]
        if not matches:
            raise SystemExit(f"No cached tool found for {args.reference}")
        print(json.dumps(matches, indent=2))
        return
    if args.command == "set-state":
        result = set_quality_state(args.reference, args.state, reason=args.reason, force=args.force)
    else:
        if args.outcome in {"confirmed", "contradicted"} and not args.evidence_id:
            raise SystemExit("--evidence-id is required for confirmed and contradicted outcomes.")
        result = record_quality_outcome(
            args.reference,
            args.outcome,
            reason=args.reason,
            evidence_id=args.evidence_id,
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
