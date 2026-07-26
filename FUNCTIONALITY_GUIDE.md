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

Groq-hosted GPT-OSS 120B, Llama 3.1 8B, and Qwen 3 32B are used only for the agent answer generation layer. GPT-OSS 120B is the default.

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
- GPT-OSS defaults to GPT-OSS 120B using model ID `openai/gpt-oss-120b`, medium reasoning effort, and hidden reasoning output.
- Llama defaults to Llama 3.1 8B using model ID `llama-3.1-8b-instant`.
- Qwen defaults to Qwen 3.6 27B using model ID `qwen/qwen3.6-27b`.
- Model IDs can be overridden with `GPT_OSS_MODEL`, `LLAMA_MODEL`, and `QWEN_MODEL`.
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

## 15. Agent-Led Web Validation

The red-team web assessment keeps collection and safety controls deterministic, while the selected
LLM chooses active validation work. The collector discovers routes, JSON field names, rendered DOM
controls, and same-origin browser requests. The Web Test Planner selects up to three bounded SQLi
or DOM-XSS proof probes from that evidence. The executor permits only observed same-origin routes,
GET or POST, small payloads, no redirects, and a small request budget. DOM-XSS confirmation uses
local Chromium/Playwright and accepts only a harmless `document.title` sentinel; it blocks payloads
that access cookies/storage, redirect, open windows, or use network APIs. The Web Evidence Analyst
then classifies the redacted responses and browser proof. Planner choices and execution results are
included in campaign traces as `llm_web_planner` and `bounded_web_executor`.

## 16. Generated Tool Cache Quality

Generated tools are versioned and reviewed by artifact hash so a broken cached implementation does
not silently affect every later campaign. The registry lives at:

```text
data/generated_tools/quality_registry.json
```

Code:

```text
src/medflow_redteam/tool_quality.py
src/medflow_redteam/generated_tools.py
scripts/manage_tool_cache.py
```

Each code and specification pair has an immutable SHA-256 identity and one lifecycle state:

- `candidate`: newly generated by an LLM; blocked from execution.
- `fixture_passed`: a fixture result was recorded; still blocked.
- `shadow`: eligible to run, but its positive result cannot create a finding.
- `trusted`: eligible to run and contribute a finding when its proof satisfies the result contract.
- `degraded`: removed from automatic ranking and available only for direct diagnostics.
- `quarantined`: blocked.

A shadow artifact becomes trusted after three confirmations with distinct independent evidence IDs.
The first contradiction degrades a shadow or trusted artifact, the second quarantines it, and three
consecutive execution errors also quarantine it. A contradiction against an unproven candidate
quarantines it immediately. Editing code or behavior-relevant specification fields creates a new
hash and a new quality history, so trust does not transfer to the modified version.

Generated tools run in a child process with a bounded timeout. Results must be JSON-serializable,
boolean status fields must really be booleans, `exploited=true` requires `verified=true`, and
positive results require `proof_output` or `evidence`. These checks catch malformed output and
runtime failures. Semantic correctness still requires a known fixture, an independent scanner, or
manual review; a tool cannot establish its own trust merely by reporting success.

Review the cache:

```bash
.venv/bin/python scripts/manage_tool_cache.py list
.venv/bin/python scripts/manage_tool_cache.py inspect generated:custom_observer
```

Promote a reviewed candidate into shadow evaluation:

```bash
.venv/bin/python scripts/manage_tool_cache.py record generated:custom_observer fixture_passed \
  --reason "Known positive and negative fixtures behaved correctly"
.venv/bin/python scripts/manage_tool_cache.py set-state generated:custom_observer shadow \
  --reason "Fixture output reviewed"
```

Record independent agreement or disagreement:

```bash
.venv/bin/python scripts/manage_tool_cache.py record generated:custom_observer confirmed \
  --evidence-id benchmark-2026-07-23-a --reason "Independent benchmark agreed"
.venv/bin/python scripts/manage_tool_cache.py record generated:custom_observer contradicted \
  --evidence-id manual-review-2026-07-23-b --reason "Ground truth disagreed"
```

The REST API exposes the same controls:

```text
GET  /toolsmith/cache
GET  /toolsmith/cache/{tool-id-or-hash}
POST /toolsmith/cache/{tool-id-or-hash}/state
POST /toolsmith/cache/{tool-id-or-hash}/outcomes
```

## 17. Stateful Differential API Agent

The stateful API agent detects authorization failures that a one-request scanner cannot prove. It
discovers an OpenAPI document, loads it through Schemathesis, converts its operations into a
producer/consumer resource graph, and executes bounded workflows against an allowlisted target.

The primary workflow is:

```text
discover schema -> model operations -> establish two principals -> create resource as A
-> read as A -> replay as B twice -> replay anonymously twice -> clean up when DELETE exists
```

The deterministic evidence oracle only reports a confirmed BOLA finding when the owner can read the
resource, another principal can retrieve materially equivalent data twice, and the operation policy
or returned fields indicate owner-scoped or sensitive data. An OpenAPI-protected operation that
returns equivalent data anonymously twice is reported as ignored API authentication. HTTP bodies,
passwords, tokens, cookies, and authorization values are not persisted in traces; traces retain
status, response shape, field names, size, hash, timing, and redacted references.

Run it directly:

```bash
.venv/bin/python scripts/run_stateful_api_agent.py 172.19.0.2 \
  --ports 5000 \
  --execution-mode aggressive_lab \
  --max-requests 50 \
  --max-workflows 10
```

Run it through the LangGraph campaign:

```bash
.venv/bin/python scripts/run_redteam_campaign.py \
  "Assess the authorized API lab for stateful authorization flaws" \
  --target 172.19.0.2 \
  --ports 5000 \
  --execute-recon \
  --stateful-api \
  --execution-mode aggressive_lab \
  --stateful-max-requests 50 \
  --stateful-max-workflows 10 \
  --no-llm
```

The REST API accepts the same controls on `POST /campaigns`:

```json
{
  "goal": "Assess the authorized API lab for stateful authorization flaws",
  "target": "172.19.0.2",
  "ports": [5000],
  "execute_recon": true,
  "stateful_api": true,
  "execution_mode": "aggressive_lab",
  "stateful_max_requests": 50,
  "stateful_max_workflows": 10,
  "use_llm": false
}
```

`safe` mode performs read-only comparisons and needs supplied authentication contexts for meaningful
cross-principal checks. `aggressive_lab` may use documented registration and login operations to
create two random test identities, then create and delete test resources when the schema exposes the
required operations. It must only be used on an authorized disposable lab. The feature is opt-in;
without `stateful_api`, existing campaign behavior is unchanged.

The observation graph stores `ApiSchema`, `ApiOperation`, and `ApiResource` nodes plus operation
producer/consumer edges. Current discovery supports OpenAPI 2.x and 3.x. GraphQL and schema-less
traffic inference are not yet statefully exercised.

## 18. Autonomous URL Campaign Routing

For a web target, the regular LangGraph campaign accepts only the high-level objective and the
explicitly authorized URL. The Campaign Orchestrator asks the selected LLM which internal
specialists are relevant. When it selects authorization testing, the Web/API Agent launches a
bounded same-origin subworkflow; callers do not select or invoke that agent directly.

```bash
.venv/bin/python scripts/run_redteam_campaign.py \
  "Run an authorized black-box web/API assessment and autonomously validate applicable access-control boundaries" \
  --url https://authorized-lab.example \
  --report
```

The subworkflow discovers routes from target evidence, creates applicable authorization
hypotheses, executes a bounded request matrix, reviews coverage, independently audits each verdict,
and returns normalized findings to the campaign report. It cannot follow redirects or leave the
explicit URL origin. It cannot invent credentials, identity headers, role values, sessions,
accounts, or object identifiers. Safe mode permits read-only discovery; `aggressive_lab` also makes
mutating methods available, but every write must contain a synthetic test marker.
When the target exposes only an authentication barrier and the prompt supplies no valid context,
the overall posture is `inconclusive`; a `401` proves that narrow anonymous boundary, not the
security of hidden authenticated functionality.

The REST API uses the same interface:

```json
{
  "goal": "Run an authorized black-box web/API assessment",
  "target_url": "https://authorized-lab.example",
  "provider": "qwen",
  "use_llm": true
}
```

Campaign JSON and debug exports include `campaign_routing` and `authorization_assessment`. Detailed
request and response evidence is stored under the campaign output directory's `authorization`
subdirectory.
