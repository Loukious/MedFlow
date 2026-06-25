from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "config"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_lab_config() -> dict[str, Any]:
    return _read_json(CONFIG_DIR / "redteam_lab.json")


@lru_cache(maxsize=1)
def load_internal_capabilities_config() -> dict[str, Any]:
    return _read_json(CONFIG_DIR / "internal_capabilities.json")
