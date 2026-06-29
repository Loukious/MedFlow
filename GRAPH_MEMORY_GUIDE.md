# MedFlow Graph Memory

MedFlow graph memory is an optional, file-backed intelligence layer for campaign outputs. It keeps the red-team runner modular: campaigns still run through `src/medflow_redteam`, while graph memory lives in `src/medflow_graph` and can be reused by another frontend or service.

## What It Stores

The graph ingests JSON reports from `scripts/run_redteam_campaign.py` and converts them into typed entities:

- `Campaign`: the campaign goal, provider, elapsed time, and report path.
- `Target`: allowlisted target identifiers such as lab IP addresses.
- `Service`: observed port/protocol/service/version records.
- `Route`: discovered HTTP routes and status metadata.
- `Artifact`: exposed downloadable or sensitive web artifacts flagged by route discovery.
- `Finding`: review-worthy findings derived from evidence, such as possible packet capture exposure.
- `Capability`: validation modules selected from internal checks, Nmap NSE, Nuclei, or Metasploit metadata.
- `Evidence`: proof or failure text produced by capability validation.
- `AgentRole`: the LangGraph role outputs used during the campaign.
- `KnowledgeSource`: retrieved ATT&CK / MedFlow context items used by the campaign.

Edges connect the entities, for example:

- `Campaign -> ASSESSED_TARGET -> Target`
- `Target -> HAS_SERVICE -> Service`
- `Target -> HAS_ROUTE -> Route`
- `Route -> EXPOSES_ARTIFACT -> Artifact`
- `Capability -> PRODUCED_EVIDENCE -> Evidence`
- `Campaign -> USED_AGENT -> AgentRole`

## Clean-Graph Behavior

The implementation follows a conservative clean-graph flow:

1. Normalize names into canonical forms.
2. Type-gate deduplication, so services compare only with services, routes only with routes, and so on.
3. Prefer stable identities for automatic merges, such as exact target IP, route URL, service key, capability ID, campaign ID, or agent role.
4. Use full-context fuzzy comparison for non-stable entities.
5. Automatically merge only high-confidence matches.
6. Add medium-confidence matches to a pending review queue instead of merging them.
7. Keep tombstoned nodes when dedup merges two existing nodes so old references remain auditable.

Thresholds live in [src/medflow_graph/memory.py](/home/Loukious/Stage/src/medflow_graph/memory.py):

- `MERGE_THRESHOLD = 0.95`
- `REVIEW_THRESHOLD = 0.85`

## Ingest Campaign Reports

Run a campaign first:

```bash
.venv/bin/python scripts/run_redteam_campaign.py "Assess an unknown authorized lab target and identify viable validation paths" --target 10.129.32.115 --ports 1-1000 --execute-validation --max-capabilities 8 --execution-mode aggressive_lab --no-llm
```

Then ingest one or more saved campaign JSON reports:

```bash
.venv/bin/python scripts/ingest_campaign_graph.py reports/redteam_campaign/redteam_campaign_*.json --dream --reviews
```

The generated graph is saved to:

```text
data/graph/medflow_graph.json
```

`data/graph/` is ignored by Git because it is generated local state.

## Neo4j Export

You can export a Cypher file without requiring a Neo4j server locally:

```bash
.venv/bin/python scripts/ingest_campaign_graph.py reports/redteam_campaign/redteam_campaign_*.json --cypher data/graph/medflow_graph.cypher
```

Review the generated Cypher before importing it into Neo4j.

## Search Graph Memory

Search the graph directly without an LLM:

```bash
.venv/bin/python scripts/query_graph_memory.py "packet capture exposure web route" --limit 8
```

Filter by node type when you only want specific entities:

```bash
.venv/bin/python scripts/query_graph_memory.py "http header validation" --types Capability,Evidence
```

The Streamlit UI also has a `Graph Memory` mode for:

- graph summary,
- direct search,
- report ingestion,
- pending-memory inspection through search results.

## Campaign Integration

Campaign runs now load graph memory after reconnaissance:

```bash
.venv/bin/python scripts/run_redteam_campaign.py "Assess an unknown authorized lab target and identify viable validation paths" --target 10.129.32.115 --ports 1-1000 --execute-validation --max-capabilities 8 --execution-mode aggressive_lab --no-llm --graph-memory data/graph/medflow_graph.json
```

The campaign uses graph memory as prior evidence, not as hardcoded target knowledge. It can influence capability scoring when prior campaigns show matching successful or failed validation outcomes.

Saved campaign JSON and Markdown now include:

- `phases`: explicit campaign phase states.
- `tool_timeline`: tool calls and evidence previews.
- `graph_memory`: matched prior graph evidence.
- `web_fingerprint`: lightweight web stack/header signals.

## Validation Statuses

Capability validation results now use clearer statuses:

- `confirmed_vulnerability`: controlled validation produced vulnerability evidence.
- `confirmed_exposure`: non-exploit exposure validation produced positive evidence.
- `ran_no_finding`: tool ran but did not produce positive evidence.
- `blocked_by_safety_policy`: capability was not allowed by the execution policy.
- `tool_error`: local tool execution failed.
- `not_applicable`: the capability was not runnable for the observed context.

The older `verified` boolean is still present for compatibility, but new reports should use `status` for human interpretation.

## Web Scan Imports

MedFlow can normalize exported web scanner reports without launching a scanner:

```bash
.venv/bin/python scripts/import_web_scan_report.py zap-report.json --format zap
.venv/bin/python scripts/import_web_scan_report.py burp-report.xml --format burp --output reports/imported/burp-normalized.json
```

These adapters are intentionally import-focused so the campaign can consume authorized evidence without turning the agent into an uncontrolled web scanner.

## Why This Helps

This gives the agents memory without hardcoding target-specific facts into prompts. Over repeated authorized campaigns, MedFlow can build a clean record of:

- which services were observed,
- which routes exposed useful artifacts,
- which validation capabilities matched,
- which checks verified real evidence,
- which findings were seen across multiple targets,
- which duplicate entities need human review.

That memory can later feed retrieval, reporting, attack-path scoring, or a Neo4j-backed graph UI without coupling those pieces to the current Streamlit frontend.
