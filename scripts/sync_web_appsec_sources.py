from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from medflow_ti.config import ROOT


CONFIG = ROOT / "config" / "web_appsec_sources.json"
DEST = ROOT / "data" / "web_appsec_sources"


REPO_SOURCES = {
    "owasp_wstg",
    "owasp_cheat_sheets",
    "payloadsallthethings_curated",
    "nuclei_templates_metadata",
}
DEFAULT_SOURCES = REPO_SOURCES


def load_config(path: Path = CONFIG) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def run(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False, timeout=1800)


def revision(dest: Path) -> str:
    result = run(["git", "rev-parse", "HEAD"], cwd=dest)
    return result.stdout.strip() if result.returncode == 0 else ""


def result_with_revision(result: dict[str, Any], dest: Path) -> dict[str, Any]:
    if dest.is_dir() and (dest / ".git").exists():
        result["revision"] = revision(dest)
    return result


def sync_source(source: dict[str, Any], dest_root: Path, refresh: bool) -> dict[str, Any]:
    source_id = str(source["id"])
    url = str(source["url"])
    dest = dest_root / source_id
    if source_id not in REPO_SOURCES:
        return {"id": source_id, "status": "metadata_only", "url": url}
    if dest.exists() and (dest / ".git").exists():
        if refresh:
            result = run(["git", "pull", "--ff-only"], cwd=dest)
            return result_with_revision(
                {
                    "id": source_id,
                    "status": "updated" if result.returncode == 0 else "update_failed",
                    "path": str(dest),
                    "url": url,
                    "stderr": result.stderr[-1000:],
                },
                dest,
            )
        return result_with_revision(
            {"id": source_id, "status": "exists", "path": str(dest), "url": url},
            dest,
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    result = run(["git", "clone", "--depth", "1", "--filter=blob:none", url, str(dest)])
    return result_with_revision(
        {
            "id": source_id,
            "status": "cloned" if result.returncode == 0 else "clone_failed",
            "path": str(dest),
            "url": url,
            "stderr": result.stderr[-1000:],
        },
        dest,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync optional web appsec source repositories for KB ingestion.")
    parser.add_argument("--refresh", action="store_true", help="Pull existing repositories.")
    parser.add_argument("--dest", type=Path, default=DEST)
    parser.add_argument("--sources", nargs="*", default=None, help="Source IDs to sync. Defaults to all cloneable sources.")
    args = parser.parse_args()
    config = load_config()
    requested = set(args.sources or DEFAULT_SOURCES)
    known = {str(source["id"]) for source in config.get("sources", [])}
    unknown = sorted(requested - known)
    if unknown:
        raise SystemExit(f"Unknown source IDs: {', '.join(unknown)}")
    results = [
        sync_source(source, args.dest, args.refresh)
        for source in config.get("sources", [])
        if str(source["id"]) in requested
    ]
    manifest = {
        "schema_version": 1,
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "destination": str(args.dest),
        "results": results,
    }
    args.dest.mkdir(parents=True, exist_ok=True)
    (args.dest / "sync_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
