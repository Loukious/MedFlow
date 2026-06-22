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
    try:
        return SentenceTransformer(
            name,
            device=_device(),
            cache_folder=str(cache_folder) if cache_folder else None,
            local_files_only=True,
        )
    except Exception:
        os.environ.pop("HF_HUB_OFFLINE", None)
        os.environ.pop("TRANSFORMERS_OFFLINE", None)
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
