# Red-Team Agent Framework Comparison

This is a small Milestone 2 comparison harness for testing LangGraph and LlamaIndex Agents side by side without rebuilding the full MedFlow app.

The focus is red-team validation, not the existing Streamlit frontend.

## Goal

Compare two agent frameworks on the same safe MedFlow red-team planning task:

```text
Authorized hospital portal tabletop/purple-team validation using synthetic telemetry.
```

The scenario covers:

- Password spraying signals
- MFA fatigue signals
- Session abuse signals
- Device registration abuse signals
- SIEM/detection and response validation

The implementation is intentionally synthetic-only. It does not run offensive tools, attempt real logins, send real MFA prompts, or touch live systems.

## What Was Added

```text
data/sample_alerts/redteam_hospital_portal.json
src/medflow_compare/
scripts/compare_redteam_frameworks.py
```

The comparison package imports the existing modular MedFlow AI code:

- `medflow_ti.vector_store.query`
- `medflow_ti.embeddings`
- `medflow_ti.llm`
- `medflow_ti.config`

No Streamlit/frontend code is required.

## Shared Tools

Both frameworks use the same shared logic from:

```text
src/medflow_compare/shared_tools.py
```

Shared capabilities:

- Load the red-team scenario
- Build retrieval queries
- Search the MedFlow Chroma knowledge bases
- Compact retrieved ATT&CK evidence
- Check outputs against a safe tabletop boundary
- Call the configured Groq model

## LangGraph Version

File:

```text
src/medflow_compare/langgraph_workflow.py
```

Workflow:

```text
prepare_queries
  -> retrieve_context
  -> draft_campaign_plan
  -> safety_gate
  -> final_report
```

This version is best for comparing explicit stateful orchestration, predictable steps, and future human-in-the-loop gates.

## LlamaIndex Version

File:

```text
src/medflow_compare/llamaindex_workflow.py
```

Agent type:

```text
FunctionAgent
```

Tools:

```text
search_medflow_redteam_knowledge
review_redteam_safety
```

This version is best for comparing framework-native tool calling and faster agent prototyping.

## Run The Comparison

Run both:

```bash
python scripts/compare_redteam_frameworks.py --framework both --provider llama --results 3 --sources --traces
```

Run only LangGraph:

```bash
python scripts/compare_redteam_frameworks.py --framework langgraph --provider llama --results 3 --sources
```

Run only LlamaIndex:

```bash
python scripts/compare_redteam_frameworks.py --framework llamaindex --provider llama --results 3 --sources --traces
```

JSON output:

```bash
python scripts/compare_redteam_frameworks.py --framework both --json
```

## Early Comparison Notes

Initial successful run:

```text
LangGraph:  explicit multi-step workflow, 4 traced actions, richer evidence set
LlamaIndex: FunctionAgent tool workflow, 2 captured tool calls, simpler setup
```

LangGraph is better when we care about:

- Explicit state
- Auditable workflow stages
- Deterministic control flow
- Human approval gates
- Long-running red-team campaign orchestration

LlamaIndex is better when we care about:

- Fast tool-agent prototyping
- Less orchestration code
- Simple RAG/tool use
- Quick experiments with agent behavior

## Current Recommendation

For MedFlow's final red-team platform, LangGraph is the stronger architecture candidate because the milestone points toward stateful security workflows, tool coordination, approval gates, and multi-step campaign reasoning.

For quick experiments and retrieval/tool-agent demos, LlamaIndex is very useful and easier to iterate.
