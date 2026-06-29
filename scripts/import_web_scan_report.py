from __future__ import annotations

import argparse
import json
from pathlib import Path

from medflow_redteam.tools import parse_burp_xml_report, parse_zap_json_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize Burp XML or ZAP JSON findings for MedFlow reporting.")
    parser.add_argument("report", type=Path)
    parser.add_argument("--format", choices=["burp", "zap"], required=True)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    if args.format == "burp":
        normalized = parse_burp_xml_report(args.report)
    else:
        normalized = parse_zap_json_report(args.report)

    payload = json.dumps(normalized, indent=2, default=str)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload)


if __name__ == "__main__":
    main()
