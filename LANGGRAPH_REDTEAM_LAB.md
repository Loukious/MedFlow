# LangGraph Red-Team Lab

This milestone implementation keeps the red-team code separate from the Streamlit UI and the older threat-intelligence agents. It uses LangGraph to run a small, safe validation workflow against a local Metasploitable3 Docker target.

## What It Builds

- `config/redteam_lab.json` defines lab target safety, scan ports, and Docker lab settings.
- `config/generated_tools/tool_specs.json` is intentionally empty; no generated Python tools are committed as baseline capabilities.
- `data/generated_tools/` stores on-demand generated tools created during experimentation.
- `scripts/build_capability_inventory.py` builds a provider-backed capability inventory from Metasploit metadata, Nuclei templates, and local NSE metadata.
- `data/capabilities/capability_inventory.json` stores the generated capability inventory.
- `src/medflow_redteam/docker_lab.py` manages the Docker lab.
- `src/medflow_redteam/tools.py` keeps target safety checks, runtime recon helpers, parsers, and provider-backed execution dispatch.
- `src/medflow_redteam/langgraph_lab.py` defines the LangGraph workflow.
- `src/medflow_redteam/campaign.py` defines the role-separated multi-agent campaign workflow.
- `scripts/run_langgraph_redteam_lab.py` is the CLI entry point.
- `scripts/run_redteam_campaign.py` is the CLI entry point for high-level campaign orchestration.
- `reports/redteam_lab/` stores JSON and Markdown run outputs.
- `reports/redteam_campaign/` stores JSON and Markdown campaign outputs.

## Lab Isolation

The setup command creates the Docker bridge network defined in `config/redteam_lab.json` with `--internal`, so the Metasploitable3 container does not get internet access through that network.

The current configured target container is:

- Image: `kirscht/metasploitable3-ub1404`
- Container name: `medflow-metasploitable3`
- Internal IP: `172.29.10.10`
- Internal subnet: `172.29.10.0/24`

The launcher also requests localhost port bindings for convenience, but in this WSL setup the reliable scan target is the configured internal container IP.

## Agent Flow

The LangGraph lab workflow runs these nodes in order:

1. `recon_connectivity`: runs the runtime TCP connectivity check.
2. `recon_nmap`: runs LLM-planned, validator-gated service discovery command generation.
3. `probe_http`: runs runtime HTTP probing for ports selected by the reconnaissance strategy.
4. `select_exploit_tool`: uses observed service evidence to build a candidate pool.
5. `controlled_exploitation`: optionally executes LLM-selected validation candidates.
6. `retrieve_attack_context`: searches the MedFlow/ATT&CK vector knowledge bases.
7. `safety_gate`: checks the planned content against the project safety boundary.
8. `report`: asks the selected LLM to produce a concise validation report.

The workflow is intentionally validation-focused. It does not run exploit modules, credential theft, persistence, evasion, destructive actions, or attacks against non-lab systems.

## Multi-Agent Campaign Flow

The campaign workflow converts a high-level red-team goal into a role-separated campaign plan. It is separate from the lab exploitation workflow so campaign planning can remain useful even when no live target is supplied.

The campaign graph runs these cooperating agents:

1. `Campaign Orchestrator Agent`: defines the campaign charter, phases, role tasking, constraints, and success criteria.
2. `Reconnaissance Agent`: collects or plans attack-surface evidence. With `--execute-recon`, it runs active TCP checks, asks the LLM which observed ports deserve deeper inspection, then executes validator-gated service discovery and HTTP probes against an allowlisted target.
3. `Identity Attack Agent`: models safe identity validation paths using BloodHound, SharpHound, Impacket, Kerbrute, IdP telemetry, and SIEM evidence as tool families.
4. `Web/API Attack Agent`: designs healthcare portal and API validation using Burp Suite, OWASP ZAP, Postman, and HTTP evidence as tool families.
5. `Blockchain Security Agent`: decides whether blockchain is in scope, and if so plans smart-contract and wallet/event-log validation using Slither, Mythril, and Hardhat as tool families.
6. `Reporting Agent`: merges the role handoffs into executive and technical campaign reporting with safety constraints, evidence, limitations, and next work.

Each role produces a structured JSON handoff with:

- `role`
- `objective`
- `tools`
- `decisions`
- `outputs`
- `handoff`

The role agents share retrieved ATT&CK/MedFlow context and prior agent outputs. This gives the project the “AI agents decide, security tools execute” shape requested in the milestone while keeping tool execution gated by allowlists and safety policy.

The exploitation phase is opt-in. The graph first chooses from the generated capability inventory using tool output. The current inventory sources are:

- On-demand generated Python tools from `data/generated_tools/`, when explicitly created.
- Metasploit module metadata from `data/capability_sources/metasploit-framework`.
- Nuclei template metadata from `data/capability_sources/nuclei-templates`.
- Local NSE script metadata from `/usr/share/nmap/scripts`.

There are no current seed generated tools. That means the action is not selected by a hidden hardcoded `if` in the execution step. LangGraph runs a selection node, records the matching reasons, and then passes selected provider capabilities to the execution node.

In the CLI output, `verified` means the selected provider path did more than connect to the service. For Metasploit exploit mode, `exploited` means the runner collected session or command-execution proof from an allowlisted isolated lab target.

The current kill chain is intentionally small:

- Reconnaissance: discover open services.
- Target selection: choose the highest-scoring matching capabilities from the generated inventory.
- Exploitation: trigger the controlled lab-only command execution proof.
- Command execution proof: verify the output of `id`.
- Cleanup: remove the temporary proof file.

It does not perform persistence, privilege escalation, lateral movement, credential theft, or destructive actions.

## What Is Config-Driven

These values are now outside the agent logic:

- Default target and allowed CIDRs.
- Docker image, network, subnet, container name, container IP, hostname, published ports, and startup commands.
- Default scan ports and HTTP probe ports.
- Locally generated Python tool capability entries from `data/generated_tools/`, when explicitly created.
- Capability match rules: service, ports, and product/version keywords.
- Provider-backed capability metadata from Metasploit, Nuclei, and NSE.

The code still intentionally enforces:

- Target validation against configured localhost names and CIDR allowlist.
- Execution dispatch: Metasploit can run through the gated lab adapter; Nuclei and NSE provider entries are metadata-only for now.
- Cleanup verification after exploitation.
- Safety/reporting boundaries.

## Generated Python Tools

Generated Python tools are intended to be created on demand by a Toolsmith-style workflow, then reused later when their metadata matches observed evidence. They are normal records with `runner: generated_python_tool` plus a Python file that exposes `run(context)`.

The committed config registry is intentionally empty:

```text
config/generated_tools/tool_specs.json
```

Locally generated tools live in:

```text
data/generated_tools/
```

`data/generated_tools/` is ignored by Git so experimental tools do not get committed by accident.

Create a deterministic TCP banner tool:

```bash
.venv/bin/python scripts/create_generated_tool.py --id redis_banner --template tcp_banner --service redis --port 6379
```

Search for a reusable generated tool in graph/data cache:

```bash
.venv/bin/python scripts/create_generated_tool.py --lookup "redis banner port 6379"
```

Create a tool from an LLM prompt:

```bash
.venv/bin/python scripts/create_generated_tool.py --provider llama --prompt "Create a safe observation tool for Redis INFO exposure on port 6379"
```

Before an on-demand generated tool is stored, the project validates that the Python file defines `run(context)`, only imports from the small allowed import set, and avoids blocked dynamic execution primitives. Each implementation is stored under an immutable content hash and receives an independent quality history. LLM-generated tools begin as blocked `candidate` artifacts; reviewed tools can run in `shadow` mode, where their output is visible but cannot create findings. Only `trusted` artifacts can contribute findings. Runtime contract failures, timeouts, contradictions, and repeated errors degrade or quarantine the exact artifact version.

Review and update quality state with:

```bash
.venv/bin/python scripts/manage_tool_cache.py list
.venv/bin/python scripts/manage_tool_cache.py inspect generated:redis_banner
```

See `FUNCTIONALITY_GUIDE.md` for lifecycle transitions and independent evidence commands. The child-process timeout and static checks are reliability boundaries, not a complete OS sandbox; production deployment should still execute generated code in an isolated container or worker.

## Vulhub Lab Set

Vulhub labs are managed through:

```bash
sudo .venv/bin/python scripts/manage_vulhub_labs.py status
sudo .venv/bin/python scripts/manage_vulhub_labs.py up --pull
sudo .venv/bin/python scripts/manage_vulhub_labs.py test
sudo .venv/bin/python scripts/manage_vulhub_labs.py down
```

Configured labs live in:

```text
config/vulhub_labs.json
```

The manager starts each selected Vulhub scenario on its own internal Docker network with container restart set to `unless-stopped` and host port publishing disabled. Metasploitable3 is managed separately and is also kept at `restart=unless-stopped`.

The current always-light seeded validation set is:

- `flask_ssti`: validates benign Jinja2 arithmetic rendering.
- `mini_httpd_file_read`: validates the empty-Host file-read condition with a short `/etc/passwd` proof.
- `appweb_auth_bypass`: validates the incomplete Digest Authorization bypass signal.

Additional Vulhub scenarios are configured for broader Metasploit-selection testing:

- `metabase_cve_2023_38646`
- `couchdb_cve_2017_12636`
- `couchdb_cve_2022_24706`
- `struts2_s2_061`
- `struts2_s2_032`
- `struts2_s2_045`
- `struts2_s2_057`
- `shiro_cve_2016_4437`
- `rocketmq_cve_2023_33246`
- `solr_cve_2019_17558`
- `drupal_cve_2018_7600`

The currently practical multi-lab bring-up command is:

```bash
sudo .venv/bin/python scripts/manage_vulhub_labs.py up \
  metabase_cve_2023_38646 \
  couchdb_cve_2017_12636 \
  struts2_s2_045 \
  shiro_cve_2016_4437 \
  solr_cve_2019_17558 \
  drupal_cve_2018_7600 \
  --pull
```

Those six plus the three light validators give nine running Vulhub targets. The remaining configured labs can be started by name when needed, but some are heavier or have more moving parts.

## Metasploit Selection Benchmark

The Metasploit selection benchmark is in:

```text
config/benchmarks/vulhub_metasploit_selection.json
scripts/benchmark_metasploit_selection.py
scripts/benchmark_live_vulhub_metasploit.py
```

The benchmark labels expected Metasploit modules and acceptable payloads for scoring only. The selector does not receive the expected module as an instruction; it ranks modules from observed service evidence, optional CVE intelligence, web titles/routes, graph memory, and provider inventory metadata. Payload planning is handled separately by `src/medflow_redteam/metasploit_planner.py`, which chooses module options and payload candidates from module metadata, platform/architecture hints, default payloads, and observed service data.

Run the benchmark:

```bash
python scripts/benchmark_metasploit_selection.py --mode both --top-k 10 --save-report
```

Run live exploit-proof validation against currently running Vulhub containers:

```bash
python scripts/benchmark_live_vulhub_metasploit.py --labs all --max-capabilities 4 --loop --max-rounds 3 --max-tools 8 --save-report
```

The live benchmark does not pass expected CVEs or modules into the campaign. Expected modules are scoring labels only. Each run starts from observed services and web fingerprints, then records whether the selected Metasploit path produced `exploited=True` proof.

Modes:

- `service`: uses only service/product evidence, similar to what active recon can observe.
- `cve`: adds known CVEs to the observed service record, modeling what an NVD/version-enrichment step should provide later.
- `both`: runs both modes.

Current verified benchmark result:

- Static benchmark: 28 service/CVE rows across 14 lab definitions.
- Expected module was top 1 for 24/28 rows and top 5 for 27/28 rows.
- Expected payload was top 3 for all 28 rows.
- The remaining static miss is `thinkphp_5_rce` in service-only mode; the live benchmark solves it after the web fingerprint tool observes the ThinkPHP page.

The benchmark output now reports:

- module rank
- selected payload and payload rank
- expected modules
- top module candidates
- misses and payload misses in the JSON summary
- live selected modules, payload/option attempts, and proof lines in `live_vulhub_metasploit_*.json`

This is the baseline for a SkillOpt-style improvement loop: run scored lab rollouts, inspect misses and weak rankings, update the ranking/skill policy, and keep changes only when held-out benchmark performance improves.

## Tool Boundary

The deployable LangGraph agent does not depend on Docker. Docker is only used by the local lab setup CLI.

The current deployable agent tools are:

- TCP connectivity checks.
- LLM-planned, validator-gated service discovery.
- HTTP probing.
- Capability candidate lookup from the generated inventory.
- LLM-assisted validation target selection.
- Metasploit module option, payload, and resource planning.
- Gated Metasploit `plan`, `check`, and lab-only `exploit` execution for allowlisted lab targets.
- On-demand generated Python tool support through `data/generated_tools/`.
- Provider metadata ranking for NSE, Nuclei, and Metasploit sources.
- MedFlow/ATT&CK retrieval.
- Safety review.
- LLM narrative reporting.

MITRE ATT&CK is used for technique context and reporting, not exploit code. ATT&CK can keep the agent current on tactics, techniques, mitigations, and detection context, but execution requires an on-demand generated tool or an integration with a maintained exploit framework.

## Capability Inventory

Build or refresh the inventory:

```bash
python scripts/build_capability_inventory.py --refresh
```

Rebuild from already cloned local sources:

```bash
python scripts/build_capability_inventory.py --skip-network
```

The inventory builder currently produced about 19k provider capabilities:

- Metasploit metadata: module paths, CVEs extracted from Ruby module references, service hints, ports, product keywords, platform/architecture hints, default payloads, and safety metadata.
- Nuclei templates: template IDs, tags, CVEs, severity, and HTTP/service hints.
- NSE metadata: categories, service/port hints, and runtime safety classification.

The selector can recommend provider metadata. Metasploit modules are handled by a separate gated runner:

- `safe` mode returns a Metasploit plan only.
- `aggressive_lab` mode with `--metasploit-action check` runs `msfconsole check` against allowlisted lab targets.
- `aggressive_lab` mode with `--metasploit-action exploit` can run the selected Metasploit module, prefer command/reverse/fetch payloads when available, infer `LHOST` and fetch-server addresses from the route to the target, collect session/command proof, and attempt session cleanup.

Nuclei and NSE provider items are metadata-only until an on-demand generated tool or dedicated adapter is created for that behavior.

Execution policy:

- In `safe` mode, generated tools are not auto-executed by the main campaign unless explicitly created and wired in.
- In `aggressive_lab` mode, Metasploit modules can run the requested `--metasploit-action`.
- Provider metadata from Nuclei and NSE is used for selection/recommendation, not direct execution.
- Brute-force, credential, hash, password, persistence, and DoS behavior remains blocked by generation prompts, static validation, and generated-tool review.

If a Nuclei or NSE provider capability has no executable adapter, the runner reports it as metadata-only instead of executing it directly.

Install optional external execution tools:

```bash
scripts/install_redteam_tools.sh nuclei
scripts/install_redteam_tools.sh metasploit
```

These external tools are useful for creating and testing future generated tools. MedFlow executes Metasploit only through the gated lab adapter; Nuclei and NSE remain metadata-only unless represented by a future generated tool or adapter.

## Remaining Architecture Work

The hardcoded config-side generated tools have been removed. Metasploit now has a gated adapter for planning, checking, and exploit-proof execution in isolated labs. The next architecture steps are:

- Run generated Python tools in a true isolated sandbox instead of the current static-validation cache layer.
- Add catalog enrichment from external sources such as NVD/CVE feeds, Exploit-DB metadata, Metasploit module metadata, and Nuclei template metadata.
- Keep execution policy separate from knowledge retrieval, so new intelligence can update recommendations without automatically granting permission to run dangerous actions.
- Expand scoring with exploit reliability, version confidence, target scope, expected proof quality, and cleanup support.
- Add richer dry-run previews that show why each generated or provider-backed tool would run.
- Add more tests for allowlist enforcement, generated-tool validation, cleanup, no-match behavior, and malformed generated specs.

Current live validation notes:

- `metabase_cve_2023_38646` produced a positive Metasploit check: the selected `metabase_setup_token_rce` module reported target version `0.46.6` as vulnerable.
- With `--metasploit-action exploit`, `metabase_cve_2023_38646` produced actual exploit proof in the isolated Vulhub lab: Metasploit opened a command shell session and the runner attempted cleanup with `sessions -K`.
- Live Vulhub proof is currently confirmed for nine labs: Metabase CVE-2023-38646, CouchDB CVE-2017-12636, Apache Shiro CVE-2016-4437, Apache Solr CVE-2019-17558, Apache Struts S2-045, Apache Struts S2-057, Apache Struts S2-032, ThinkPHP 5 RCE, and Apache ActiveMQ CVE-2023-46604.
- Recent live proof reports include `reports/benchmarks/live_vulhub_metasploit_20260703-160415.json` for ThinkPHP and `reports/benchmarks/live_vulhub_metasploit_20260703-162258.json` for ActiveMQ.
- `spring_cve_2022_22963` selects the expected Spring Cloud Function Metasploit module, but the current Vulhub fixture did not produce exploitation proof under Metasploit; manual testing showed Metasploit reports the target as not exploitable for that module.
- `drupal_cve_2018_7600` selected Drupal-specific modules, including Drupalgeddon2, but the current Vulhub container redirected to Drupal installation state during manual validation, so it needs lab setup/fixture work before it is a reliable exploit-proof benchmark.

## Commands

Install the lab and recreate the container:

```bash
python scripts/run_langgraph_redteam_lab.py --setup-lab --recreate-lab --use-sudo --setup-only
```

Run a fast comparison/demo pass:

```bash
python scripts/run_langgraph_redteam_lab.py --provider llama --sources --traces
```

Run a fast pass with controlled exploitation evidence:

```bash
sudo .venv/bin/python scripts/run_langgraph_redteam_lab.py --provider llama --exploit-validation --use-sudo --sources --traces
```

Run the top three selected capabilities:

```bash
sudo .venv/bin/python scripts/run_langgraph_redteam_lab.py --provider llama --exploit-validation --max-exploits 3 --use-sudo
```

Run a broader lab-only validation pass:

```bash
sudo .venv/bin/python scripts/run_langgraph_redteam_lab.py --provider llama --exploit-validation --max-exploits 10 --execution-mode aggressive_lab --use-sudo
```

Run the multi-agent campaign planner without active probing:

```bash
python scripts/run_redteam_campaign.py "Validate identity and web attack paths against the hospital employee portal" --provider llama --report
```

Run the campaign planner with active allowlisted reconnaissance:

```bash
python scripts/run_redteam_campaign.py "Validate identity and web attack paths against the hospital employee portal" --target 172.29.10.10 --execute-recon --provider llama --report --traces
```

Run a fast deterministic campaign demo without LLM calls:

```bash
python scripts/run_redteam_campaign.py "Validate identity and web attack paths against the hospital employee portal" --target 172.29.10.10 --execute-recon --no-llm
```

Run the campaign planner with active recon and capability validation against an allowlisted HTB-style lab target:

```bash
python scripts/run_redteam_campaign.py "Assess an unknown authorized lab target and identify viable validation paths" --target 10.129.32.115 --ports 1-1000 --execute-validation --max-capabilities 8 --execution-mode aggressive_lab --no-llm
```

Keep the goal generic for unknown targets. The campaign logic should learn from observed ports, service fingerprints, web routes, artifacts, and tool outputs rather than from a machine name or challenge hint.

Campaign runs also emit explicit `phases`, a `tool_timeline`, normalized capability `status` values, web fingerprint evidence, and optional graph-memory hits. To let the campaign use prior local memory during capability selection, keep the default graph path or pass it explicitly:

```bash
python scripts/run_redteam_campaign.py "Assess an unknown authorized lab target and identify viable validation paths" --target 10.129.32.115 --ports 1-1000 --execute-validation --max-capabilities 8 --execution-mode aggressive_lab --no-llm --graph-memory data/graph/medflow_graph.json
```

Add `--update-graph --graph-dedup` when you want the new run to be ingested into graph memory immediately. Otherwise the campaign only reads graph memory and writes the campaign report files.

Search graph memory directly without an LLM:

```bash
python scripts/query_graph_memory.py "packet capture exposure web route" --limit 8
```

Run bounded closed-loop validation with explicit budgets:

```bash
python scripts/run_redteam_campaign.py "Assess an unknown authorized lab target and identify viable validation paths" --target 10.129.32.115 --ports 1-1000 --loop --max-rounds 3 --max-tools 12 --execution-mode aggressive_lab --no-llm
```

`--loop` enables validation automatically and stops on success by default. Use `--no-stop-on-success` only when you want it to keep trying additional safe capability checks after a positive result.

Run the stateful differential API agent through the campaign:

```bash
python scripts/run_redteam_campaign.py \
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

The agent discovers OpenAPI 2.x/3.x contracts, models operation and resource dependencies with
Schemathesis, and executes bounded multi-principal workflows. In `safe` mode it is read-only. In
`aggressive_lab` it may register disposable principals and create test resources through operations
documented by the target schema. A BOLA result is confirmed only after an owner baseline and two
successful alternate-principal replays. Anonymous authentication bypasses are also repeated before
confirmation. Secrets and response bodies are excluded from persisted traces.

The standalone runner avoids the rest of the campaign:

```bash
python scripts/run_stateful_api_agent.py 172.19.0.2 \
  --ports 5000 \
  --execution-mode aggressive_lab \
  --max-requests 50 \
  --max-workflows 10
```

Campaign graph output includes `ApiSchema`, `ApiOperation`, and `ApiResource` nodes and
producer/consumer edges. GraphQL and schema-less traffic inference remain future extensions.

Review graph-memory duplicate decisions:

```bash
python scripts/review_graph_memory.py
```

Analyze exported identity evidence without live authentication attempts:

```bash
python scripts/analyze_identity_import.py identity-events.json --type logs
python scripts/analyze_identity_import.py bloodhound-export.json --type bloodhound
```

On-demand generated Python tools live in `data/generated_tools/` instead of committed config-side code:

```text
data/generated_tools/
```

Create a safe generated TCP banner tool and cache it for future ranking:

```bash
python scripts/create_generated_tool.py --id redis_banner --template tcp_banner --service redis --port 6379
```

LLM-generated tools are also supported, but they must pass static validation before being cached:

```bash
python scripts/create_generated_tool.py --id custom_banner --provider llama --prompt "Create a safe TCP banner observation tool for an allowlisted lab service."
```

Generated tools must expose `run(context: dict) -> dict`, use only approved imports, and execute through the `generated_python_tool` runner.

## Dynamic Command Planning

MedFlow keeps local lookup/ranking for capabilities, but command construction can now be delegated to the selected LLM provider during LLM-enabled runs.

- Nmap service discovery uses an LLM-generated argv plan when the campaign is run with LLM enabled.
- Metasploit keeps local module lookup/ranking, then asks the LLM for a Metasploit resource plan.
- Every generated command/resource plan is validated before execution.
- If the LLM is disabled or returns an unsafe/invalid plan, MedFlow falls back to a deterministic safe plan.

Metasploit execution backend:

```bash
# default: try RPC if available, then fall back to msfconsole
export MEDFLOW_METASPLOIT_BACKEND=auto

# require RPC only
export MEDFLOW_METASPLOIT_BACKEND=rpc

# force msfconsole
export MEDFLOW_METASPLOIT_BACKEND=shell
```

RPC settings:

```bash
export MSFRPC_PASSWORD=medflow
export MSFRPC_HOST=127.0.0.1
export MSFRPC_PORT=55552
export MSFRPC_SSL=true
```

To let MedFlow start `msfrpcd` when RPC is selected:

```bash
export MEDFLOW_START_MSFRPCD=1
```

The command planner does not allow arbitrary shell. Nmap plans must use the exact target and exact port list. Metasploit plans must use the selected module, set the exact target, and use only validated resource commands such as `use`, `set`, `check`, `run -j`, `sessions -l`, `sessions -K`, and `exit -y`.

## Debug Review

Campaign JSON reports already contain the raw campaign state. To make manual review easier, export a full debug bundle:

```bash
.venv/bin/python scripts/export_campaign_debug.py
```

By default this reads the latest `reports/redteam_campaign/redteam_campaign_*.json` and writes:

```text
reports/debug/<campaign-report-name>/
  summary.md
  debug.json
  tool_timeline.json
  tool_traces.json
  raw/
  validation_results/
```

Use a specific report when needed:

```bash
.venv/bin/python scripts/export_campaign_debug.py reports/redteam_campaign/redteam_campaign_YYYYMMDD-HHMMSS.json
```

The REST API also exposes debug views:

```text
GET /jobs/{job_id}/debug
GET /debug/campaign-report?path=reports/redteam_campaign/redteam_campaign_YYYYMMDD-HHMMSS.json
```

These debug views are meant for manual accuracy review. They preserve the tool timeline, validation result objects, selected capability scores, proof output, raw recon output, graph memory hits, and role handoffs.

For direct tool validation without the multi-agent campaign layer, use the lab runner:

```bash
python scripts/run_langgraph_redteam_lab.py --target 10.129.32.115 --ports 1-1000 --exploit-validation --max-exploits 8 --execution-mode aggressive_lab
```

For a cleaner demo output, omit `--sources --traces`:

```bash
sudo .venv/bin/python scripts/run_langgraph_redteam_lab.py --provider llama --exploit-validation --use-sudo
```

Use `--report` if you want the generated narrative report printed in the terminal. The report is saved either way.

Run the fuller validation pass:

```bash
python scripts/run_langgraph_redteam_lab.py --provider llama --sources --traces
```

Stop the lab:

```bash
python scripts/run_langgraph_redteam_lab.py --stop-lab --use-sudo
```

## Output

Each run saves:

- A JSON trace with target, services, tool calls, retrieved sources, and LLM output.
- A Markdown report suitable for milestone evidence.

The CLI can print sources with `--sources` and tool calls with `--traces`.

Use `--exploit-validation` when the milestone/demo needs exploitation evidence. Run the whole command with Docker permissions so the marker proof can be verified and cleaned up.

## Current Verified Result

The verified lab scan reached `172.29.10.10` and identified these open services:

- `21/tcp`: FTP, ProFTPD 1.3.5
- `22/tcp`: SSH, OpenSSH 6.6.1p1 Ubuntu
- `139/tcp`: SMB/NetBIOS, Samba
- `445/tcp`: SMB/NetBIOS, Samba
- `3306/tcp`: MySQL
- `6667/tcp`: IRC, UnrealIRCd

The Nmap `default,safe` validation can be slow on this target. Timeouts are recorded as tool evidence instead of failing the entire graph.

## Notes

If Docker status appears unavailable in a normal user run, the scan can still work through `172.29.10.10`. Docker metadata requires either Docker group membership or running the CLI with sudo. Avoid running the whole report command as root unless you are comfortable with root-owned report files.
