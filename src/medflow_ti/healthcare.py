from __future__ import annotations

from pathlib import Path

import pandas as pd

from .mitre_loader import Document
from .vector_store import add_documents


def csv_documents(path: Path) -> list[Document]:
    docs: list[Document] = []
    for csv_path in path.rglob("*.csv"):
        frame = pd.read_csv(csv_path, dtype=str, nrows=5000, on_bad_lines="skip")
        relative_path = csv_path.relative_to(path)
        dataset_name = relative_path.parts[0] if len(relative_path.parts) > 1 else csv_path.stem
        for idx, row in frame.iterrows():
            values = [f"{col}: {row[col]}" for col in frame.columns if pd.notna(row[col])]
            text = "Healthcare security dataset row\n" + "\n".join(values)
            docs.append(
                Document(
                    collection="detection_db",
                    doc_id=f"healthcare::{relative_path}::{idx}",
                    text=text,
                    metadata={
                        "type": "healthcare-dataset-row",
                        "name": csv_path.name,
                        "dataset": dataset_name,
                        "path": str(csv_path),
                        "mitre_id": "",
                        "url": "",
                        "stix_id": "",
                    },
                )
            )
    return docs


def ingest_healthcare_csv(path: Path, chroma_path: Path, model_name: str) -> dict[str, int]:
    docs = csv_documents(path)
    if not docs:
        return {}
    return add_documents(chroma_path, docs, model_name)
