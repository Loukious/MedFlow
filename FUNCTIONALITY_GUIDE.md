# MedFlow Functionality Guide

This file explains the main functionality added to the MedFlow AI Threat Intelligence and Red Team Platform, how each feature works, and where the code lives.

## 1. MITRE CTI Data Ingestion

The project uses the official MITRE CTI repository at:

```text
data/mitre-cti
```

The loader reads Enterprise ATT&CK STIX JSON bundles from:

```text
data/mitre-cti/enterprise-attack
```

Code:

```text
src/medflow_ti/mitre_loader.py
```

What it does:

- Reads ATT&CK STIX objects such as techniques, sub-techniques, tools, malware, campaigns, intrusion sets, analytics, detection strategies, mitigations, and data sources.
- Skips revoked or deprecated objects.
- Extracts useful fields such as name, MITRE ID, description, tactic, platform, detection text, URL, and relationship text.
- Converts each object into a document that can be embedded and stored in Chroma.

## 2. The Four Vector Knowledge Bases

The platform builds four Chroma collections:

```text
attack_db
redteam_db
actor_db
detection_db
```

Code:

```text
src/medflow_ti/vector_store.py
```

Purpose of each collection:

- `attack_db`: ATT&CK techniques and sub-techniques.
- `redteam_db`: red-team procedures, sub-techniques, tools, and relationship examples.
- `actor_db`: intrusion sets, malware, tools, and campaigns.
- `detection_db`: analytics, detection strategies, mitigations, data sources, and healthcare CSV rows if ingested.

Build command:

```bash
python -m medflow_ti.cli build
```

Smoke-test build:

```bash
python -m medflow_ti.cli build --limit 500
```

Status command:

```bash
python -m medflow_ti.cli status
```

The full build stores the persistent Chroma database in:

```text
data/chroma
```

## 3. Embeddings And GPU Support

The project uses:

```text
BAAI/bge-base-en-v1.5
```

Code:

```text
src/medflow_ti/embeddings.py
scripts/check_gpu.py
```

How it works:

- Text is converted into normalized embedding vectors using `sentence-transformers`.
- If PyTorch can see CUDA, the embedding model uses the GPU.
- If CUDA is unavailable, it automatically falls back to CPU.
- The embedding loader checks the local Hugging Face cache first and can fall back to online download when needed.

Check GPU:

```bash
python scripts/check_gpu.py
```

Expected GPU output when WSL CUDA is working:

```text
Embedding device: cuda
cuda available: True
gpu: NVIDIA GeForce RTX 3050 Laptop GPU
```

## 4. LLM Provider Integration

Groq-hosted Llama 3.1 8B and Qwen 3 32B are used only for the agent answer generation layer.

Code:

```text
src/medflow_ti/llm.py
src/medflow_ti/agents.py
```

Configuration:

```text
.env
```

Supported API key names:

```text
GroqAPIKey
GROQ_API_KEY
GROQAPIKEY
```

How it works:

- The system retrieves relevant documents from Chroma first.
- Retrieved evidence is inserted into a prompt.
- The selected model writes the final answer using only that retrieved context.
- Llama defaults to Llama 3.1 8B using model ID `llama-3.1-8b-instant`.
- Qwen defaults to Qwen 3 32B using model ID `qwen/qwen3-32b`.
- Qwen uses a smaller context budget to stay friendlier to free-tier token limits.
- If the selected LLM is quota-limited or unavailable, the app returns retrieved MITRE evidence instead of crashing.

## 5. The Two Agents

The UI and scripts expose two PDF-facing agents:

```text
redteam
threat_intel
```

Code:

```text
src/medflow_ti/agents.py
scripts/ask_agent.py
```

### Red Team Agent

Collection search scope:

```text
redteam_db
attack_db
actor_db
```

Use it for:

- High-level adversary simulation.
- ATT&CK-based kill-chain overviews.
- Tool-to-technique mapping.
- Procedure examples.
- Defensive validation planning.

Safety behavior:

- Supports authorized defensive red-team planning.
- Avoids exploit code, credential theft instructions, destructive commands, stealth persistence recipes, and operational compromise steps.

Example:

```bash
python scripts/ask_agent.py redteam "Give me a safe kill-chain overview for a Ryuk-style hospital ransomware intrusion."
```

### Threat Intelligence Agent

Collection search scope:

```text
attack_db
actor_db
detection_db
redteam_db
```

Use it for:

- Technique lookup.
- Attribution-style questions.
- Detection engineering.
- Mitigation and response guidance.
- Healthcare-specific threat framing.

Example:

```bash
python scripts/ask_agent.py threat_intel "What SIEM rules detect MFA fatigue attacks against hospital portals?" --sources
```

## 6. Direct Knowledge Base Search Without An LLM

This feature performs similarity search directly against Chroma and does not call Llama, Qwen, Groq, or any other LLM.

Code:

```text
scripts/search_kb.py
src/medflow_ti/vector_store.py
```

Use it when:

- You want raw retrieved MITRE evidence.
- You want to debug what the vector database returns.
- You do not want LLM summarization.
- LLM quota is unavailable.

Examples:

```bash
python scripts/search_kb.py "MFA fatigue hospital portal SIEM" --collection threat_intel --results 8 --show-text
python scripts/search_kb.py "Ryuk hospital ransomware kill chain" --collection redteam --format text
python scripts/search_kb.py "T1053.005" --collection attack_db --format json
```

Supported groups and collections:

```text
all
redteam
threat_intel
attack_db
redteam_db
actor_db
detection_db
```

Output formats:

- `table`: ranked table with score, collection, MITRE ID, name, and URL.
- `text`: readable text snippets.
- `json`: raw structured hits for programmatic use.

## 7. Streamlit Web UI

The web app is:

```text
app.py
```

Run it with:

```bash
streamlit run app.py
```

Open:

```text
http://localhost:8501
```

The sidebar has two modes.

### Ask Agent Mode

This mode uses retrieval plus the selected LLM provider.

Workflow:

1. Select `Ask Agent`.
2. Choose `Red Team Agent` or `Threat Intelligence Agent`.
3. Enter a question.
4. Click `Ask`.
5. The app retrieves relevant Chroma documents, sends them to the selected provider, and displays the final answer plus sources.

### Search Knowledge Base Mode

This mode uses direct knowledge-base search, with no LLM. It first retrieves semantic candidates from Chroma, then reranks them with keyword and security-phrase matching so specific terms like `MFA`, `SIEM`, and `fatigue` are prioritized over broad healthcare-only matches.

Workflow:

1. Select `Search Knowledge Base`.
2. Choose a knowledge base group such as `Threat Intelligence Knowledge` or `Detection & Mitigation`.
3. Enter a search query.
4. Click `Search`.
5. The app displays ranked Chroma results with scores and expandable source text.

Knowledge base options:

- `All Knowledge Bases`
- `Red Team Knowledge`
- `Threat Intelligence Knowledge`
- `ATT&CK Techniques`
- `Red Team Procedures`
- `Actors, Malware, Tools`
- `Detection & Mitigation`

## 8. Optional Kaggle Healthcare Data

The project includes a helper for downloading public healthcare/security datasets from Kaggle.

Code:

```text
scripts/download_kaggle_healthcare.py
src/medflow_ti/healthcare.py
HEALTHCARE_DATA_SOURCES.md
```

The expanded source catalog includes IoMT datasets, HHS breach resources, HC3 bulletins, VCDB, CISA KEV, CTI report repositories, TRAM, FDA MAUDE/MDR sources, and Kaggle healthcare cybersecurity datasets.

Download example:

```bash
python scripts/download_kaggle_healthcare.py --list
python scripts/download_kaggle_healthcare.py --all
python scripts/download_kaggle_healthcare.py --dataset hussainsheikh03/health-care-cyber-security
```

Ingest CSV files:

```bash
python -m medflow_ti.cli ingest-healthcare-csv data/kaggle
```

How ingestion works:

- Reads CSV rows from the provided directory.
- Converts rows into text documents.
- Adds them to `detection_db`.
- This lets healthcare-specific dataset rows appear in detection and threat-intel search results.

Current ingested Kaggle rows:

```text
health-care-cyber-security: 1,423 rows
healthcare-ransomware: 5,000 rows
healthcare-vulnerabilities: 1,515 rows
iot-healthcare-security: 15,000 rows
medsec-25-iomt: 5,000 rows
total healthcare rows: 27,938
```

After ingestion, `detection_db` contains 30,543 documents total: the original MITRE detection/mitigation documents plus the healthcare dataset rows.

## 9. Command-Line Interface

Main CLI:

```text
src/medflow_ti/cli.py
```

Commands:

```bash
python -m medflow_ti.cli build
python -m medflow_ti.cli status
python -m medflow_ti.cli ask redteam "question"
python -m medflow_ti.cli ask threat_intel "question"
python -m medflow_ti.cli ingest-healthcare-csv data/kaggle
```

Installed console command:

```bash
medflow-ti status
```

The console command is defined in:

```text
pyproject.toml
```

## 10. Supporting Scripts

### `scripts/check_gpu.py`

Checks PyTorch and CUDA availability.

```bash
python scripts/check_gpu.py
```

### `scripts/ask_agent.py`

Sends a prompt to one of the two agents.

```bash
python scripts/ask_agent.py threat_intel "What is T9999?" --sources
```

### `scripts/search_kb.py`

Performs direct similarity search without an LLM.

```bash
python scripts/search_kb.py "MFA fatigue" --collection threat_intel --show-text
```

### `scripts/download_kaggle_healthcare.py`

Downloads an optional Kaggle healthcare/security dataset.

```bash
python scripts/download_kaggle_healthcare.py
```

### `scripts/build_index.py`

Small wrapper that invokes the main CLI entry point.

```bash
python scripts/build_index.py build
```

## 11. Streamlit Configuration

Streamlit config:

```text
.streamlit/config.toml
```

Purpose:

- Disables Streamlit file watching.
- Prevents Streamlit from scanning optional `transformers` vision modules that require `torchvision`.
- Disables telemetry.

Current config:

```toml
[server]
fileWatcherType = "none"

[browser]
gatherUsageStats = false
```

## 12. Safety And Hallucination Controls

The agents are prompted to:

- Use retrieved context when naming MITRE techniques, actors, tools, analytics, mitigations, or URLs.
- Separate evidence from inference.
- Admit when a MITRE ID is not found.
- Avoid unsafe offensive instructions.

Example hallucination test:

```bash
python scripts/ask_agent.py threat_intel "What is T9999?" --sources
```

Expected behavior:

- The agent should not invent a fake technique.
- It should explain that no exact matching MITRE ID was found in the retrieved context.

## 13. High-Level Data Flow

Build-time flow:

```text
MITRE CTI JSON -> STIX loader -> normalized documents -> BGE embeddings -> Chroma collections
```

Agent question flow:

```text
User question -> BGE query embedding -> Chroma search -> retrieved context -> selected LLM -> final answer
```

Direct search flow:

```text
User query -> BGE query embedding -> Chroma search -> ranked evidence only
```

## 14. Common Troubleshooting

### Hugging Face model cache errors

The embedding loader checks local cache paths first. If the model is missing, run a command with internet access once:

```bash
python scripts/search_kb.py "test" --results 1
```

### LLM quota errors

The app will still return retrieved evidence when Groq is unavailable, but full narrative answers require valid API quota for the selected model.

### GPU not detected

Run:

```bash
python scripts/check_gpu.py
```

If it says `cuda available: False`, check WSL/NVIDIA driver support on the Windows host.

### Streamlit optional `torchvision` errors

The app disables Streamlit file watching in `.streamlit/config.toml`, which avoids watcher errors from optional `transformers` vision modules.
