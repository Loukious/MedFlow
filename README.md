# MedFlow AI Threat Intelligence & Red Team Platform

This project follows `Presentation 1.pdf`: it builds four Chroma vector databases over MITRE ATT&CK CTI, then exposes two LLM-powered agents: a red-team agent and a threat-intelligence agent. The threat-intelligence agent internally covers CTI lookup, attribution, detection guidance, and healthcare framing.

For a detailed explanation of every feature, see `FUNCTIONALITY_GUIDE.md`.
For the expanded healthcare cybersecurity source catalog, see `HEALTHCARE_DATA_SOURCES.md`.
For the Milestone 2 red-team framework comparison, see `REDTEAM_FRAMEWORK_COMPARISON.md`.

## What Is Included

- `attack_db`: ATT&CK technique and sub-technique lookup.
- `redteam_db`: technique procedures, tool mappings, and relationship examples.
- `actor_db`: intrusion sets, malware, tools, campaigns, and their mapped TTPs.
- `detection_db`: MITRE analytics, detection strategies, data sources, mitigations, and healthcare notes.
- Groq-hosted Llama 3.1 8B and Qwen 3 32B clients using the `.env` key `GroqAPIKey`.
- Optional Kaggle healthcare cybersecurity dataset download and ingestion.
- CLI and Streamlit UI.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The MITRE CTI repository is expected at `data/mitre-cti`. If it is missing:

```bash
git clone --depth 1 https://github.com/mitre/cti data/mitre-cti
```

## Build The Vector DBs

For a quick smoke build:

```bash
python -m medflow_ti.cli build --limit 500
```

For the full assignment build:

```bash
python -m medflow_ti.cli build
```

The first run downloads the embedding model `BAAI/bge-base-en-v1.5`. If PyTorch can see a CUDA device under WSL, embeddings run on GPU automatically; otherwise they run on CPU.

Check GPU detection:

```bash
python scripts/check_gpu.py
```

## Ask Questions

```bash
python -m medflow_ti.cli ask redteam "Give me a safe kill-chain overview for a Ryuk-style hospital ransomware intrusion."
python -m medflow_ti.cli ask threat_intel "What is T1053.005 and which tactics does it support?"
python -m medflow_ti.cli ask threat_intel "Which actors are associated with hospital ransomware behavior?"
python -m medflow_ti.cli ask threat_intel "What SIEM logic helps detect MFA fatigue against hospital portals?"
python -m medflow_ti.cli ask threat_intel "What is T9999?"
python -m medflow_ti.cli ask threat_intel "What is T9999?" --provider qwen
```

Or use the small prompt script:

```bash
python scripts/ask_agent.py threat_intel "What SIEM logic helps detect MFA fatigue against hospital portals?" --sources
python scripts/ask_agent.py threat_intel "What is T9999?" --provider qwen --sources
python scripts/ask_agent.py redteam
```

## Search Knowledge Bases Without An LLM

Use `scripts/search_kb.py` when you only want direct knowledge-base results from Chroma. It retrieves semantic candidates, then reranks them with keyword and security-phrase matching so specific terms like `MFA`, `SIEM`, and `fatigue` are not buried by generic healthcare matches:

```bash
python scripts/search_kb.py "MFA fatigue hospital portal SIEM" --collection threat_intel --results 8 --show-text
python scripts/search_kb.py "Ryuk hospital ransomware kill chain" --collection redteam --format text
python scripts/search_kb.py "T1053.005" --collection attack_db --format json
```

## Streamlit UI

```bash
streamlit run app.py
```

## Optional Kaggle Data

The helper uses `kagglehub`. It can download public Kaggle datasets without hard-coding credentials when Kaggle access is configured.

Recommended healthcare/security candidates found during setup:

- `hussainsheikh03/health-care-cyber-security`
- `rivalytics/healthcare-ransomware-dataset`
- `abdullah001234/medsec-25-iomt-cybersecurity-dataset`
- `faisalmalik/iot-healthcare-security-dataset`
- `chuneeb/healthcare-cybersecurity-vulnerabilities-dataset`

Download one:

```bash
python scripts/download_kaggle_healthcare.py --list
python scripts/download_kaggle_healthcare.py --all
python scripts/download_kaggle_healthcare.py --dataset hussainsheikh03/health-care-cyber-security
python -m medflow_ti.cli ingest-healthcare-csv data/kaggle
```

Current ingestion status:

- Downloaded all five configured Kaggle healthcare/security datasets into `data/kaggle`.
- Ingested 27,938 healthcare rows into `detection_db`.
- `detection_db` now contains 30,543 documents total.

## Safety Boundary

The red-team agent is designed for authorized security work and healthcare defense. It can explain ATT&CK concepts, defensive validation paths, and high-level kill chains, but it is prompted not to provide exploit code, credential theft steps, persistence recipes, or instructions that enable real compromise.
