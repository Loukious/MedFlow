# MedFlow REST API Design

MedFlow now exposes the red-team campaign runner, graph memory, and Toolsmith through a small FastAPI service.

## Framework Choice

The API uses FastAPI with Uvicorn because it gives us:

- High-throughput async HTTP handling.
- Built-in OpenAPI docs at `/docs`.
- Pydantic request validation.
- Simple background job orchestration for long-running scans and campaign runs.
- Clean separation from the Streamlit frontend and CLI scripts.

The API is intentionally local-first. `scripts/run_api.py` binds to `127.0.0.1` by default. If it is exposed to a network later, add authentication, request logging, and deployment-level access controls.

## Main Components

- `src/medflow_api/app.py`: FastAPI routes and orchestration glue.
- `src/medflow_api/schemas.py`: request and response models.
- `src/medflow_api/jobs.py`: in-memory background job manager.
- `scripts/run_api.py`: development server entry point.

The AI/red-team logic remains outside the API package:

- `src/medflow_redteam/campaign.py`: campaign orchestration.
- `src/medflow_redteam/toolsmith.py`: dynamic tool creation and lookup.
- `src/medflow_graph/`: graph memory, ingestion, and deduplication.

## Endpoints

### Health

```http
GET /health
```

Returns a basic service status.

### Campaigns

```http
POST /campaigns
GET /jobs
GET /jobs/{job_id}
```

`POST /campaigns` starts a background campaign job and immediately returns a job record.
Use `/jobs/{job_id}` to poll for the result.

Important campaign flags:

- `target`: authorized lab target IP or hostname.
- `ports`: optional narrowed port list.
- `execute_validation`: enables validation behavior.
- `execution_mode`: `safe` or `aggressive_lab`.
- `metasploit_action`: `plan`, `check`, or `exploit`.
- `use_llm`: enables LLM planning.
- `provider`: `llama` or `qwen`.
- `loop`: enables iterative campaign rounds.
- `update_graph`: ingests the finished campaign report into graph memory.

Live exploitation is still gated by the red-team safety controls in the underlying campaign code, including lab allowlists and execution mode checks.

Example:

```bash
curl -s -X POST http://127.0.0.1:8000/campaigns \
  -H 'Content-Type: application/json' \
  -d '{
    "goal": "Assess an unknown authorized lab target and identify viable validation paths",
    "target": "172.29.10.10",
    "ports": [21, 22, 6667],
    "execute_validation": true,
    "execution_mode": "aggressive_lab",
    "metasploit_action": "check",
    "use_llm": false,
    "update_graph": true
  }'
```

### Graph Memory

```http
GET /graph/summary
POST /graph/search
```

Use graph search to retrieve remembered campaigns, vulnerabilities, services, reports, and generated tool metadata.

Example:

```bash
curl -s -X POST http://127.0.0.1:8000/graph/search \
  -H 'Content-Type: application/json' \
  -d '{"query":"redis unauthenticated access", "limit": 5}'
```

### Toolsmith

```http
POST /toolsmith/lookup
POST /toolsmith/tools
```

`/toolsmith/lookup` searches the generated-tool memory.
`/toolsmith/tools` creates or reuses a generated tool and registers it in graph memory.

Example:

```bash
curl -s -X POST http://127.0.0.1:8000/toolsmith/tools \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "redis_banner_probe",
    "template": "tcp_banner",
    "service": "redis",
    "port": 6379
  }'
```

### Debug Review

```http
GET /jobs/{job_id}/debug
GET /debug/campaign-report?path=reports/redteam_campaign/redteam_campaign_YYYYMMDD-HHMMSS.json
```

These endpoints return the full debug structure used for manual review: summary counters, tool timeline, tool traces, validation results, raw recon output, selected capability scores, graph hits, sources, phases, and agent handoffs.

## Running

```bash
.venv/bin/python scripts/run_api.py --host 127.0.0.1 --port 8000
```

OpenAPI documentation:

```text
http://127.0.0.1:8000/docs
```
