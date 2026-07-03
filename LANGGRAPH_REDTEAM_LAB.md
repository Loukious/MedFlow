# LangGraph Red-Team Lab

This milestone implementation keeps the red-team code separate from the Streamlit UI and the older threat-intelligence agents. It uses LangGraph to run a small, safe validation workflow against a local Metasploitable3 Docker target.

## What It Builds

- `config/redteam_lab.json` defines lab target safety, scan ports, and Docker lab settings.
- `config/generated_tools/tool_specs.json` defines seed generated-tool metadata and match rules.
- `config/generated_tools/code/` stores reviewed seed generated Python tools.
- `data/generated_tools/` stores locally generated cached tools created during experimentation.
- `scripts/build_capability_inventory.py` builds a provider-backed capability inventory from Metasploit metadata, Nuclei templates, and local Nmap NSE scripts.
- `data/capabilities/capability_inventory.json` stores the generated capability inventory.
- `src/medflow_redteam/docker_lab.py` manages the Docker lab.
- `src/medflow_redteam/tools.py` is a compatibility dispatcher that calls cached generated tools and keeps target safety checks/parsers.
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

1. `recon_connectivity`: calls the cached generated TCP connectivity tool.
2. `recon_nmap`: calls the cached generated Nmap service discovery tool.
3. `validate_safe_scripts`: optionally calls the cached generated Nmap default/safe script tool against open ports only.
4. `probe_http`: calls the cached generated HTTP probe tool.
5. `select_exploit_tool`: uses observed service evidence to choose matching capabilities from the generated inventory plus generated-tool cache.
6. `controlled_exploitation`: optionally executes the selected exploit tool.
7. `retrieve_attack_context`: searches the MedFlow/ATT&CK vector knowledge bases.
8. `safety_gate`: checks the planned content against the project safety boundary.
9. `report`: asks the selected LLM to produce a concise validation report.

The workflow is intentionally validation-focused. It does not run exploit modules, credential theft, persistence, evasion, destructive actions, or attacks against non-lab systems.

## Multi-Agent Campaign Flow

The campaign workflow converts a high-level red-team goal into a role-separated campaign plan. It is separate from the lab exploitation workflow so campaign planning can remain useful even when no live target is supplied.

The campaign graph runs these cooperating agents:

1. `Campaign Orchestrator Agent`: defines the campaign charter, phases, role tasking, constraints, and success criteria.
2. `Reconnaissance Agent`: collects or plans attack-surface evidence. With `--execute-recon`, it can run active TCP, Nmap, and HTTP probes against an allowlisted target.
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

- Generated Python tools from `config/generated_tools/` and `data/generated_tools/`.
- Metasploit module metadata from `data/capability_sources/metasploit-framework`.
- Nuclei template metadata from `data/capability_sources/nuclei-templates`.
- Local Nmap NSE script metadata from `/usr/share/nmap/scripts`.

The current seed generated tools are:

- `generated:unrealircd_3281_rce`: selected when the scan evidence matches IRC/UnrealIRCd on port `6667`.
- `generated:ftp_anonymous_access`: selected when FTP is exposed and validates whether anonymous access is enabled.
- `generated:mysql_handshake_exposure`: selected when MySQL is exposed and validates unauthenticated handshake exposure.

That means the action is not selected by a hidden hardcoded `if` in the execution step. LangGraph runs a selection node, records the matching reasons, and then passes the selected capabilities to the execution node. Automatic execution is limited to cached generated Python tools that pass the runtime safety filter.

In the CLI output, `verified` means the exploit did more than connect to the service. The workflow caused the lab service to run the benign proof command defined in the generated tool spec, collected the command output, and confirmed the proof file existed inside the Docker target. A successful proof currently looks like `uid=1121(boba_fett) ...`, which shows command execution happened as the vulnerable service user.

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
- Seed and locally generated Python tool capability entries.
- Capability match rules: service, ports, and product/version keywords.
- Tool-specific proof markers, command templates, and evidence collection logic.
- Provider-backed capability metadata from Metasploit, Nuclei, and Nmap NSE.

The code still intentionally enforces:

- Target validation against configured localhost names and CIDR allowlist.
- Execution dispatch: automatic execution runs cached generated Python tools only.
- External provider execution policy: provider inventory items can be selected/recommended, but they are metadata-only until a generated Python tool is cached for them.
- Cleanup verification after exploitation.
- Safety/reporting boundaries.

## Generated Python Tools

Generated Python tools replace the older hardcoded internal runners and operational scanners. They are normal records with `runner: generated_python_tool` plus a Python file that exposes `run(context)`.

Tracked, reviewed tools live in:

```text
config/generated_tools/tool_specs.json
config/generated_tools/code/
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

Create a tool from an LLM prompt:

```bash
.venv/bin/python scripts/create_generated_tool.py --provider llama --prompt "Create a safe observation tool for Redis INFO exposure on port 6379"
```

Create a tool from explicit files:

```bash
.venv/bin/python scripts/create_generated_tool.py --spec spec.json --code tool.py
```

Before a generated tool is cached, the project validates that the Python file defines `run(context)`, only imports from the small allowed import set, and avoids blocked dynamic execution primitives. This is not a full sandbox yet; it is the current review/cache layer before moving generated tools into an isolated execution environment.

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
```

The benchmark labels expected Metasploit modules and acceptable payloads for scoring only. The selector does not receive the expected module as an instruction; it ranks modules from observed service evidence, optional CVE intelligence, web titles/routes, graph memory, and provider inventory metadata. Payload planning is handled separately by `src/medflow_redteam/metasploit_planner.py`, which chooses module options and payload candidates from module metadata, platform/architecture hints, default payloads, and observed service data.

Run the benchmark:

```bash
python scripts/benchmark_metasploit_selection.py --mode both --top-k 10 --save-report
```

Modes:

- `service`: uses only service/product evidence, similar to what active recon can observe.
- `cve`: adds known CVEs to the observed service record, modeling what an NVD/version-enrichment step should provide later.
- `both`: runs both modes.

Current verified benchmark result:

- `service` mode: expected module was in top 5 for all 11 labs.
- `cve` mode: expected module was top 1 for all 11 labs.
- Payload mode: acceptable payload was top 1 for all 22 service/CVE benchmark rows.

The benchmark output now reports:

- module rank
- selected payload and payload rank
- expected modules
- top module candidates
- misses and payload misses in the JSON summary

This is the baseline for a SkillOpt-style improvement loop: run scored lab rollouts, inspect misses and weak rankings, update the ranking/skill policy, and keep changes only when held-out benchmark performance improves.

## Tool Boundary

The deployable LangGraph agent does not depend on Docker. Docker is only used by the local lab setup CLI.

The current deployable agent tools are:

- TCP connectivity checks.
- Generated service discovery.
- Optional generated safe script validation.
- HTTP probing.
- Capability candidate selection from the generated inventory.
- Metasploit module option and payload planning.
- Gated Metasploit `plan`, `check`, and lab-only `exploit` execution for allowlisted lab targets.
- Execution of cached generated Python tools.
- Provider metadata ranking for Nmap NSE, Nuclei, and Metasploit sources.
- MedFlow/ATT&CK retrieval.
- Safety review.
- LLM narrative reporting.

MITRE ATT&CK is used for technique context and reporting, not exploit code. ATT&CK can keep the agent current on tactics, techniques, mitigations, and detection context, but execution requires either cached generated tools or an integration with a maintained exploit framework.

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
- Nmap NSE scripts: categories, service/port hints, and runtime safety classification.

The selector can recommend provider metadata. Cached generated Python tools can execute when their policy allows it. Metasploit modules are handled by a separate gated runner:

- `safe` mode returns a Metasploit plan only.
- `aggressive_lab` mode with `--metasploit-action check` runs `msfconsole check` against allowlisted lab targets.
- `aggressive_lab` mode with `--metasploit-action exploit` can run the selected Metasploit module, prefer a command/reverse command payload when available, infer `LHOST` from the route to the target, collect session/command proof, and attempt session cleanup.

Nuclei and NSE provider items are still metadata-only until a generated tool is cached for that behavior.

Execution policy:

- In `safe` mode, only generated tools whose specs allow `safe` can run.
- In `aggressive_lab` mode, generated tools whose specs allow `aggressive_lab` can run, and Metasploit modules can run the requested `--metasploit-action`.
- Provider metadata from Nuclei and Nmap NSE is used for selection/recommendation, not direct execution.
- Brute-force, credential, hash, password, persistence, and DoS behavior remains blocked by generation prompts, static validation, and generated-tool review.

If a Nuclei or NSE provider capability has no cached generated Python tool, the runner reports it as metadata-only instead of executing it directly.

Install optional external execution tools:

```bash
scripts/install_redteam_tools.sh nuclei
scripts/install_redteam_tools.sh metasploit
```

These external tools are useful for creating and testing generated tools. MedFlow executes Metasploit only through the gated lab adapter; Nuclei and Nmap NSE remain metadata-only unless represented by cached generated Python tools.

## Remaining Architecture Work

The hardcoded internal runners and most provider adapters have been replaced by cached generated Python tools. Metasploit now has a gated adapter for planning, checking, and exploit-proof execution in isolated labs. The next architecture steps are:

- Run generated Python tools in a true isolated sandbox instead of the current static-validation cache layer.
- Add catalog enrichment from external sources such as NVD/CVE feeds, Exploit-DB metadata, Metasploit module metadata, and Nuclei template metadata.
- Keep execution policy separate from knowledge retrieval, so new intelligence can update recommendations without automatically granting permission to run dangerous actions.
- Expand scoring with exploit reliability, version confidence, target scope, expected proof quality, and cleanup support.
- Add richer dry-run previews that show why each generated or provider-backed tool would run.
- Add more tests for allowlist enforcement, generated-tool validation, cleanup, no-match behavior, and malformed generated specs.

Current live validation notes:

- `metabase_cve_2023_38646` produced a positive Metasploit check: the selected `metabase_setup_token_rce` module reported target version `0.46.6` as vulnerable.
- With `--metasploit-action exploit`, `metabase_cve_2023_38646` produced actual exploit proof in the isolated Vulhub lab: Metasploit opened a command shell session and the runner attempted cleanup with `sessions -K`.
- `drupal_cve_2018_7600` selected Drupal-specific modules, including Drupalgeddon2, but the current Vulhub container redirected to Drupal installation state during manual validation, so it needs lab setup/fixture work before it is a reliable exploit-proof benchmark.

## Commands

Install the lab and recreate the container:

```bash
python scripts/run_langgraph_redteam_lab.py --setup-lab --recreate-lab --use-sudo --setup-only
```

Run a fast comparison/demo pass:

```bash
python scripts/run_langgraph_redteam_lab.py --provider llama --skip-safe-scripts --sources --traces
```

Run a fast pass with controlled exploitation evidence:

```bash
sudo .venv/bin/python scripts/run_langgraph_redteam_lab.py --provider llama --skip-safe-scripts --exploit-validation --use-sudo --sources --traces
```

Run the top three selected capabilities:

```bash
sudo .venv/bin/python scripts/run_langgraph_redteam_lab.py --provider llama --skip-safe-scripts --exploit-validation --max-exploits 3 --use-sudo
```

Run a broader lab-only validation pass:

```bash
sudo .venv/bin/python scripts/run_langgraph_redteam_lab.py --provider llama --skip-safe-scripts --exploit-validation --max-exploits 10 --execution-mode aggressive_lab --use-sudo
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

Review graph-memory duplicate decisions:

```bash
python scripts/review_graph_memory.py
```

Analyze exported identity evidence without live authentication attempts:

```bash
python scripts/analyze_identity_import.py identity-events.json --type logs
python scripts/analyze_identity_import.py bloodhound-export.json --type bloodhound
```

Generated Python tools live in a cache instead of hardcoded campaign branches:

```text
config/generated_tools/tool_specs.json
config/generated_tools/code/
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

For direct tool validation without the multi-agent campaign layer, use the lab runner:

```bash
python scripts/run_langgraph_redteam_lab.py --target 10.129.32.115 --ports 1-1000 --skip-safe-scripts --exploit-validation --max-exploits 8 --execution-mode aggressive_lab
```

For a cleaner demo output, omit `--sources --traces`:

```bash
sudo .venv/bin/python scripts/run_langgraph_redteam_lab.py --provider llama --skip-safe-scripts --exploit-validation --use-sudo
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
