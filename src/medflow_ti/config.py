from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    root: Path = ROOT
    mitre_dir: Path = ROOT / "data" / "mitre-cti" / "enterprise-attack"
    chroma_dir: Path = ROOT / "data" / "chroma"
    healthcare_dir: Path = ROOT / "data" / "kaggle"
    embedding_model: str = "BAAI/bge-base-en-v1.5"
    llama_model: str = "llama-3.1-8b-instant"
    qwen_model: str = "qwen/qwen3-32b"
    groq_api_key: str | None = None


def load_settings() -> Settings:
    load_dotenv(ROOT / ".env")
    groq_key = (
        os.getenv("GROQ_API_KEY")
        or os.getenv("GroqAPIKey")
        or os.getenv("GROQAPIKEY")
    )
    return Settings(groq_api_key=groq_key)
