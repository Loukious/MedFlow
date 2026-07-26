# Red-Team Agent Test 1

The assignment is run through the generic prompt-driven authorization agent. The implementation
does not contain the assignment hostname, routes, accounts, roles, test matrix, or expected
findings. GPT-OSS 120B reads those details directly from `redteam_agent_test1.pdf`.
Authorization semantics that are ambiguous in the PDF are supplied through a separate tracked
prompt addendum rather than application code.

## Architecture

```text
PDF/text prompt
  -> GPT-OSS test planner
  -> generic bounded HTTP batch tool
  -> GPT-OSS coverage reviewer
  -> optional GPT-OSS follow-up plan
  -> GPT-OSS baseline and per-test evidence judges
  -> independent GPT-OSS verdict critic
  -> GPT-OSS report synthesizer
  -> report, raw evidence, and execution log
```

The planner decides:

- Which prompt-supplied origin to assess.
- Which supplied headers form the baseline identity and which may be varied.
- Which routes and methods to use.
- Which tests are required and which request matrix provides enough evidence.
- Whether follow-up requests are needed after an independent coverage review.

The host executor knows nothing about MedFlow application behavior. It only applies reusable
boundaries: prompt-derived same-origin scope, supplied-header validation, bounded request and
response sizes, no redirects, a request budget, and harmless marker data for write requests.
GPT-OSS separately interprets every response and produces PASS, FAIL, or INCONCLUSIVE results,
root causes, classifications, and remediation.

Evidence is checkpointed after every HTTP response. If a provider error interrupts only the model
analysis, resume it without replaying requests:

```bash
.venv/bin/python scripts/run_authorization_agent.py redteam_agent_test1.pdf \
  --prompt-addendum prompts/redteam_agent_test1_authorization_semantics.md \
  --resume-run reports/authorization_agent/run_YYYYMMDD-HHMMSS
```

The addendum is prompt content, not executor logic. It resolves the assignment's ambiguity between
a genuinely authenticated elevated user and the supplied patient merely changing a role header.
Both prompt files and their combined SHA-256 are recorded in every run.

## Run

Set `GROQ_API_KEY` (or `GroqAPIKey`) in `.env`. The configured model must be
`openai/gpt-oss-120b`.

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

The same runner accepts a different authorized HTTP assessment prompt without code changes:

```bash
.venv/bin/python scripts/run_authorization_agent.py path/to/another_assignment.pdf
```

## Deliverables

Each unattended run creates an ignored directory under
`reports/authorization_agent/run_YYYYMMDD-HHMMSS/` containing:

- `raw_report.md`: generated findings plus bounded raw request/response evidence.
- `assessment.json`: structured GPT-OSS judgments.
- `raw_http_evidence.json`: exact tool observations.
- `execution_log.jsonl`: timestamped planning, tool, review, and reporting events.
- `console_output.log`: screenshot-friendly unattended progress.
- `SUBMISSION_NOTE.md`: provider, endpoint, prompt design, and architecture.
- `run_metadata.json`: timing, model, prompt hash, selected scope, and request counts.

Generated reports are ignored by Git because they can contain data returned by the assessment
target.
