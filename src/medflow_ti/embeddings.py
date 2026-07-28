from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from sentence_transformers import SentenceTransformer


def _device() -> str:
    try:
        import torch

        return "cuda" if torch.cuda.is_available() else "cpu"
    except Exception:
        return "cpu"


@lru_cache(maxsize=1)
def model(name: str = "BAAI/bge-base-en-v1.5") -> SentenceTransformer:
    cache_folder = _cache_folder()
    local_path = _local_model_path(name, cache_folder)
    if local_path:
        return SentenceTransformer(
            str(local_path),
            device=_device(),
            local_files_only=True,
        )
    return SentenceTransformer(
        name,
        device=_device(),
        cache_folder=str(cache_folder) if cache_folder else None,
    )


def _cache_folder() -> Path | None:
    candidates = [
        os.getenv("SENTENCE_TRANSFORMERS_HOME"),
        os.getenv("HF_HOME"),
        "/home/Loukious/.cache/huggingface",
        str(Path.home() / ".cache" / "huggingface"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return Path(candidate)
    return None


def _local_model_path(name: str, cache_folder: Path | None) -> Path | None:
    direct = Path(name).expanduser()
    if direct.is_dir():
        return direct
    if cache_folder is None:
        return None
    repository = f"models--{name.replace('/', '--')}"
    for root in (cache_folder, cache_folder / "hub"):
        model_root = root / repository
        reference = model_root / "refs" / "main"
        snapshots = model_root / "snapshots"
        candidates: list[Path] = []
        if reference.is_file():
            revision = reference.read_text(encoding="utf-8").strip()
            if revision:
                candidates.append(snapshots / revision)
        if snapshots.is_dir():
            candidates.extend(
                path
                for path in sorted(
                    snapshots.iterdir(),
                    key=lambda item: item.stat().st_mtime,
                    reverse=True,
                )
                if path.is_dir()
            )
        for candidate in candidates:
            has_model = (
                (candidate / "model.safetensors").exists()
                or (candidate / "pytorch_model.bin").exists()
            )
            has_tokenizer = (
                (candidate / "tokenizer.json").exists()
                or (candidate / "vocab.txt").exists()
            )
            if (
                (candidate / "modules.json").is_file()
                and (candidate / "config.json").is_file()
                and has_model
                and has_tokenizer
            ):
                return candidate
    return None


def embed_texts(texts: Iterable[str], model_name: str = "BAAI/bge-base-en-v1.5") -> list[list[float]]:
    docs = list(texts)
    if not docs:
        return []
    vectors = model(model_name).encode(
        docs,
        batch_size=32,
        normalize_embeddings=True,
        show_progress_bar=True,
    )
    return vectors.tolist()


def embedding_device() -> str:
    return _device()
