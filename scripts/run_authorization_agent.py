from __future__ import annotations

import argparse
import json
from pathlib import Path

from medflow_redteam.authorization_agent import (
    DEFAULT_OUTPUT_ROOT,
    resume_authorization_assignment,
    run_authorization_assignment,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a generic prompt-driven HTTP authorization assessment agent."
    )
    parser.add_argument(
        "prompt",
        type=Path,
        help="PDF or text file containing the complete authorized assessment scenario.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=DEFAULT_OUTPUT_ROOT,
        help="Ignored directory for reports, raw evidence, and execution logs.",
    )
    parser.add_argument(
        "--request-budget",
        type=int,
        default=30,
        help="Maximum HTTP requests the model may execute (1-50).",
    )
    parser.add_argument(
        "--max-tool-rounds",
        type=int,
        default=3,
        help="Maximum plan/coverage cycles (1-5).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a compact machine-readable result after the run.",
    )
    parser.add_argument(
        "--resume-run",
        type=Path,
        help=(
            "Resume model analysis from a prior run's captured evidence without sending HTTP "
            "requests again."
        ),
    )
    parser.add_argument(
        "--prompt-addendum",
        type=Path,
        action="append",
        default=[],
        help=(
            "Append a hash-tracked PDF/text instruction document to the primary prompt. "
            "Repeat for multiple addenda."
        ),
    )
    parser.add_argument(
        "--provider",
        choices=["gpt_oss", "qwen"],
        default="gpt_oss",
        help="Groq-hosted reasoning model profile (default: assignment-required GPT-OSS).",
    )
    args = parser.parse_args()

    if args.resume_run:
        run = resume_authorization_assignment(
            prompt_path=args.prompt,
            run_dir=args.resume_run,
            prompt_addenda=tuple(args.prompt_addendum),
            provider=args.provider,
        )
    else:
        run = run_authorization_assignment(
            prompt_path=args.prompt,
            prompt_addenda=tuple(args.prompt_addendum),
            output_root=args.output_root,
            request_budget=args.request_budget,
            max_tool_rounds=args.max_tool_rounds,
            provider=args.provider,
        )
    summary = {
        "run_id": run.run_id,
        "overall_security_posture": run.assessment["overall_security_posture"],
        "tests": [
            {
                "test_id": item["test_id"],
                "name": item["name"],
                "result": item["result"],
            }
            for item in run.assessment["tests"]
        ],
        "http_requests": len(run.observations),
        "artifacts": {
            "raw_report": str(run.report_path),
            "assessment": str(run.assessment_path),
            "raw_http_evidence": str(run.evidence_path),
            "execution_log": str(run.execution_log_path),
            "console_log": str(run.console_log_path),
            "submission_note": str(run.submission_note_path),
        },
    }
    if args.json:
        print(json.dumps(summary, indent=2))
        return

    print("\nAssessment artifacts:")
    for label, path in summary["artifacts"].items():
        print(f"- {label}: {path}")


if __name__ == "__main__":
    main()
