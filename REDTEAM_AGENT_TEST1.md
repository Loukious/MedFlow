# Red-Team Agent Test 1

The normal entry point is the LangGraph campaign. The caller supplies a high-level prompt and one
explicitly authorized URL; the Campaign Orchestrator decides whether authorization testing belongs
in the campaign and routes it internally to the Web/API Agent. No agent name, PDF, route list, test
matrix, or expected finding is selected by the caller.

```bash
.venv/bin/python scripts/run_redteam_campaign.py \
  "Run an authorized black-box web/API assessment. Discover applicable authorization boundaries and validate them with bounded, non-destructive evidence." \
  --url https://authorized-lab.example \
  --report
```

Use `--provider qwen` only when comparing Qwen with the default provider. Agent routing remains
automatic.

## Architecture

```text
campaign prompt + authorized URL
  -> Campaign Orchestrator specialist router
  -> selected Web/API Agent subworkflow
  -> provider test planner
  -> generic bounded HTTP batch tool
  -> provider coverage reviewer and optional follow-up plan
  -> provider evidence judges and independent verdict critic
  -> campaign Reporting Agent
  -> campaign report, raw HTTP evidence, and execution logs
```

The router and planner decide:

- Whether the authorization specialist is relevant to the goal and target type.
- Which same-origin routes and authorization boundaries to discover.
- Which prompt- or evidence-supplied headers form the baseline identity and may be varied.
- Which applicable tests and request matrix provide enough evidence.
- Whether follow-up requests are needed after an independent coverage review.

The agent cannot infer a credential, hidden route, account, or role that neither the prompt nor the
target reveals. In that situation it reports the observable anonymous boundary and marks the broad
posture inconclusive instead of claiming the application is secure.

The host executor knows nothing about MedFlow application behavior. It only applies reusable
boundaries: prompt-derived same-origin scope, supplied-header validation, bounded request and
response sizes, no redirects, a request budget, and harmless marker data for write requests.
The selected provider separately interprets every response and produces PASS, FAIL, or INCONCLUSIVE results,
root causes, classifications, and remediation.

The campaign JSON records the routing decision and a compact authorization result. Detailed HTTP
evidence is checkpointed under `reports/redteam_campaign/authorization/`.

## Reproduction Utility

`scripts/run_authorization_agent.py` remains available to reproduce a document-defined assignment
or resume a captured run. It is not the normal campaign interface. If a provider error interrupts
only its model analysis, resume without replaying requests:

```bash
.venv/bin/python scripts/run_authorization_agent.py redteam_agent_test1.pdf \
  --prompt-addendum prompts/redteam_agent_test1_authorization_semantics.md \
  --resume-run reports/authorization_agent/run_YYYYMMDD-HHMMSS
```

The addendum is prompt content, not executor logic. It resolves the assignment's ambiguity between
a genuinely authenticated elevated user and the supplied patient merely changing a role header.
Both prompt files and their combined SHA-256 are recorded in every run.

Set `GROQ_API_KEY` (or `GroqAPIKey`) in `.env`. A document-defined assignment that explicitly
requires GPT-OSS should still use `openai/gpt-oss-120b`.

```bash
.venv/bin/python scripts/run_authorization_agent.py redteam_agent_test1.pdf \
  --prompt-addendum prompts/redteam_agent_test1_authorization_semantics.md
```

Compact terminal output:

```bash
.venv/bin/python scripts/run_authorization_agent.py redteam_agent_test1.pdf \
  --prompt-addendum prompts/redteam_agent_test1_authorization_semantics.md \
  --json
```

Qwen can re-analyze an existing run without replaying HTTP:

```bash
.venv/bin/python scripts/run_authorization_agent.py redteam_agent_test1.pdf \
  --prompt-addendum prompts/redteam_agent_test1_authorization_semantics.md \
  --resume-run reports/authorization_agent/run_YYYYMMDD-HHMMSS \
  --provider qwen \
  --json
```

This is useful as a comparison or diagnostic result. The assignment deliverable still requires
GPT-OSS 120B.

## Deliverables

Each routed campaign creates its normal JSON and Markdown report plus an ignored authorization
subdirectory containing:

- `raw_report.md`: generated findings plus bounded raw request/response evidence.
- `assessment.json`: structured model judgments.
- `raw_http_evidence.json`: exact tool observations.
- `execution_log.jsonl`: timestamped planning, tool, review, and reporting events.
- `console_output.log`: screenshot-friendly unattended progress.
- `SUBMISSION_NOTE.md`: provider, endpoint, prompt design, and architecture.
- `run_metadata.json`: timing, model, prompt hash, selected scope, and request counts.

Generated reports are ignored by Git because they can contain data returned by the assessment
target.
