from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import kagglehub


KAGGLE_DATASETS = {
    "health-care-cyber-security": "hussainsheikh03/health-care-cyber-security",
    "healthcare-ransomware": "rivalytics/healthcare-ransomware-dataset",
    "medsec-25-iomt": "abdullah001234/medsec-25-iomt-cybersecurity-dataset",
    "iot-healthcare-security": "faisalmalik/iot-healthcare-security-dataset",
    "healthcare-vulnerabilities": "chuneeb/healthcare-cybersecurity-vulnerabilities-dataset",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Download an optional healthcare cybersecurity Kaggle dataset.")
    parser.add_argument(
        "--dataset",
        default="hussainsheikh03/health-care-cyber-security",
        help="Kaggle dataset slug or short name. Use --list to see short names.",
    )
    parser.add_argument("--out", default="data/kaggle")
    parser.add_argument("--list", action="store_true", help="List known healthcare cybersecurity Kaggle datasets.")
    parser.add_argument("--all", action="store_true", help="Download all known Kaggle datasets.")
    args = parser.parse_args()

    if args.list:
        print("Known Kaggle healthcare/security datasets:")
        for name, slug in KAGGLE_DATASETS.items():
            print(f"- {name}: {slug}")
        return

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    datasets = KAGGLE_DATASETS.items() if args.all else [(args.dataset, KAGGLE_DATASETS.get(args.dataset, args.dataset))]
    for name, dataset in datasets:
        downloaded = Path(kagglehub.dataset_download(dataset))
        target = out / safe_name(name if name in KAGGLE_DATASETS else dataset)
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(downloaded, target)
        print(f"Downloaded {dataset}")
        print(f"  Kaggle cache: {downloaded}")
        print(f"  Project copy: {target}")

    print(f"Run ingestion with: python -m medflow_ti.cli ingest-healthcare-csv {out}")


def safe_name(value: str) -> str:
    return value.replace("/", "__").replace(" ", "_")


if __name__ == "__main__":
    main()
