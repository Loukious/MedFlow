from __future__ import annotations

import argparse
from pathlib import Path

from medflow_redteam.debug import export_campaign_debug


def latest_campaign_report(directory: Path) -> Path:
    reports = sorted(directory.glob("redteam_campaign_*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not reports:
        raise SystemExit(f"No campaign JSON reports found in {directory}")
    return reports[0]


def main() -> None:
    parser = argparse.ArgumentParser(description="Export full debug artifacts from a MedFlow campaign JSON report.")
    parser.add_argument("report", nargs="?", help="Campaign JSON report. Defaults to latest report in --report-dir.")
    parser.add_argument("--report-dir", default="reports/redteam_campaign")
    parser.add_argument("--output-dir", default=None, help="Debug output directory. Defaults to reports/debug/<report-stem>.")
    args = parser.parse_args()

    report = Path(args.report) if args.report else latest_campaign_report(Path(args.report_dir))
    paths = export_campaign_debug(report, args.output_dir)
    print(f"Debug export for: {report}")
    for label, path in paths.items():
        print(f"{label}: {path}")


if __name__ == "__main__":
    main()
