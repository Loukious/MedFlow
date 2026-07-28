from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from medflow_redteam.config_loader import ROOT


REPOSITORY = "https://github.com/danielmiessler/SecLists.git"
DEFAULT_DESTINATION = ROOT / "data" / "wordlists" / "SecLists"
SPARSE_PATHS = [
    "Usernames/top-usernames-shortlist.txt",
    "Passwords/Common-Credentials/xato-net-10-million-passwords-1000.txt",
    "Passwords/Common-Credentials/top-20-common-SSH-passwords.txt",
    "Passwords/Common-Credentials/10k-most-common.txt",
]


def run(command: list[str], *, cwd: Path | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=600,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def acquire(destination: Path, update: bool) -> dict[str, object]:
    if (destination / ".git").is_dir():
        if update:
            run(["git", "pull", "--ff-only"], cwd=destination)
    elif destination.exists():
        raise RuntimeError(
            f"{destination} exists but is not a Git checkout; move or remove it first."
        )
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--no-checkout",
                REPOSITORY,
                str(destination),
            ]
        )
    run(["git", "sparse-checkout", "init", "--no-cone"], cwd=destination)
    sparse_file = destination / ".git" / "info" / "sparse-checkout"
    sparse_file.write_text(
        "\n".join(f"/{path}" for path in SPARSE_PATHS) + "\n",
        encoding="utf-8",
    )
    run(["git", "checkout"], cwd=destination)
    missing = [path for path in SPARSE_PATHS if not (destination / path).is_file()]
    if missing:
        raise RuntimeError(f"SecLists checkout is missing: {', '.join(missing)}")
    return {
        "repository": REPOSITORY,
        "destination": str(destination),
        "commit": run(["git", "rev-parse", "HEAD"], cwd=destination),
        "files": SPARSE_PATHS,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Acquire the bounded SecLists subset used by MedFlow lab agents."
    )
    parser.add_argument(
        "--destination",
        type=Path,
        default=DEFAULT_DESTINATION,
    )
    parser.add_argument("--update", action="store_true")
    args = parser.parse_args()
    print(json.dumps(acquire(args.destination.resolve(), args.update), indent=2))


if __name__ == "__main__":
    main()
