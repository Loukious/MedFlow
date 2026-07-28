from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from medflow_redteam.web_kb import (
    category_from_path,
    iter_markdown_documents,
    token_count,
    tokenizer_special_tokens,
)
from medflow_ti.vector_store import _rerank_score


class FakeTokenizer:
    def encode(self, text: str, add_special_tokens: bool = False) -> list[str]:
        return text.split()

    def decode(
        self,
        tokens: list[str],
        skip_special_tokens: bool = True,
        clean_up_tokenization_spaces: bool = True,
    ) -> str:
        return " ".join(tokens)

    def num_special_tokens_to_add(self, pair: bool = False) -> int:
        return 2


class WebKnowledgeBaseTests(unittest.TestCase):
    def test_nosql_category_is_not_collapsed_into_sql(self) -> None:
        root = Path("/sources")
        self.assertEqual(
            category_from_path(
                root / "NoSQL Injection" / "README.md",
                root,
            ),
            "nosql_injection",
        )

    def test_exact_cve_metadata_is_preferred(self) -> None:
        exact = {
            "document": "Apache logging remote code execution.",
            "metadata": {
                "type": "nuclei-template-metadata",
                "cve": "CVE-2021-44228",
            },
            "distance": 0.6,
        }
        generic = {
            "document": "General Java web application testing guidance.",
            "metadata": {"type": "web-appsec-methodology"},
            "distance": 0.4,
        }
        question = "What metadata is available for CVE-2021-44228?"
        self.assertGreater(
            _rerank_score(question, exact)[0],
            _rerank_score(question, generic)[0],
        )

    def test_source_policies_and_token_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source_root = base / "sources"

            methodology = source_root / "methodology"
            (methodology / "docs").mkdir(parents=True)
            (methodology / "README.md").write_text(
                "# Repository setup\nGeneric contribution instructions.",
                encoding="utf-8",
            )
            (methodology / "docs" / "sqli.md").write_text(
                "# SQL Injection Testing\n"
                + " ".join(f"methodology-{index}" for index in range(100)),
                encoding="utf-8",
            )

            payloads = source_root / "payloads" / "SQL Injection"
            payloads.mkdir(parents=True)
            (payloads / "README.md").write_text(
                "# SQL Injection\n"
                "Use response differentials and database error evidence.\n"
                "```sql\nDANGEROUS_PAYLOAD\n```\n",
                encoding="utf-8",
            )

            nuclei = source_root / "nuclei" / "http" / "cves" / "2026"
            nuclei.mkdir(parents=True)
            (nuclei / "CVE-2026-0001.yaml").write_text(
                """
id: CVE-2026-0001
info:
  name: Example Web Injection
  severity: high
  description: A web parameter is not safely handled.
  remediation: Validate and parameterize input.
  classification:
    cve-id: CVE-2026-0001
    cwe-id: CWE-89
  metadata:
    vendor: example
    product: portal
  tags: cve,sqli,web
http:
  - raw:
      - |
        GET /dangerous-request HTTP/1.1
        Host: {{Hostname}}
""".strip(),
                encoding="utf-8",
            )

            config = {
                "sources": [
                    {
                        "id": "methodology",
                        "name": "Methodology",
                        "type": "methodology",
                        "url": "https://example.test/methodology",
                        "ingestion": {
                            "mode": "markdown",
                            "collection": "web_methodology_db",
                            "include": ["**/*.md"],
                            "exclude": ["README.md"],
                            "strip_code_blocks": False,
                        },
                    },
                    {
                        "id": "payloads",
                        "name": "Payload Taxonomy",
                        "type": "payload-taxonomy",
                        "url": "https://example.test/payloads",
                        "ingestion": {
                            "mode": "markdown_taxonomy",
                            "collection": "web_payload_db",
                            "include": ["**/*.md"],
                            "exclude": [],
                            "strip_code_blocks": True,
                        },
                    },
                    {
                        "id": "nuclei",
                        "name": "Nuclei Metadata",
                        "type": "scanner-template-metadata",
                        "url": "https://example.test/nuclei",
                        "ingestion": {
                            "mode": "nuclei_metadata",
                            "collection": "web_payload_db",
                            "include": ["http/**/*.yaml"],
                            "exclude": [],
                        },
                    },
                ]
            }
            config_path = base / "sources.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")

            tokenizer = FakeTokenizer()
            docs = iter_markdown_documents(
                source_root,
                tokenizer=tokenizer,
                max_tokens=50,
                config_path=config_path,
            )

            self.assertGreater(len(docs), 3)
            self.assertFalse(
                any(doc.metadata["source_path"] == "README.md" for doc in docs)
            )
            self.assertTrue(
                any(doc.metadata["type"] == "web-payload-taxonomy" for doc in docs)
            )
            nuclei_docs = [
                doc
                for doc in docs
                if doc.metadata["type"] == "nuclei-template-metadata"
            ]
            self.assertGreaterEqual(len(nuclei_docs), 1)
            self.assertTrue(
                all(doc.metadata["cve"] == "CVE-2026-0001" for doc in nuclei_docs)
            )
            self.assertNotIn("DANGEROUS_PAYLOAD", "\n".join(doc.text for doc in docs))
            self.assertNotIn(
                "/dangerous-request",
                "\n".join(doc.text for doc in nuclei_docs),
            )
            for doc in docs:
                self.assertLessEqual(
                    token_count(tokenizer, doc.text)
                    + tokenizer_special_tokens(tokenizer),
                    50,
                )


if __name__ == "__main__":
    unittest.main()
