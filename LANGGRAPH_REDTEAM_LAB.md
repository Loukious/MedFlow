# LangGraph Red-Team Lab

This milestone implementation keeps the red-team code separate from the Streamlit UI and the older threat-intelligence agents. It uses LangGraph to run a small, safe validation workflow against a local Metasploitable3 Docker target.

## What It Builds

- `config/redteam_lab.json` defines lab target safety, scan ports, and Docker lab settings.
- `config/internal_capabilities.json` defines optional local validation runners, match rules, proof command, and proof marker.
- `scripts/build_capability_inventory.py` builds a provider-backed capability inventory from Metasploit metadata, Nuclei templates, local Nmap NSE scripts, and internal validations.
- `data/capabilities/capability_inventory.json` stores the generated capability inventory.
- `src/medflow_redteam/docker_lab.py` manages the Docker lab.
- `src/medflow_redteam/tools.py` contains the safe local tools used by the agent graph.
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

1. `recon_connectivity`: checks TCP connectivity to allowed lab ports.
2. `recon_nmap`: runs safe service discovery with `nmap -sV -Pn --version-light`.
3. `validate_safe_scripts`: optionally runs Nmap `default,safe` scripts against open ports only.
4. `probe_http`: checks HTTP-like ports for status, headers, and titles.
5. `select_exploit_tool`: uses observed service evidence to choose matching capabilities from the generated inventory plus internal validations.
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

- Internal validation scripts from `config/internal_capabilities.json`.
- Metasploit module metadata from `data/capability_sources/metasploit-framework`.
- Nuclei template metadata from `data/capability_sources/nuclei-templates`.
- Local Nmap NSE script metadata from `/usr/share/nmap/scripts`.

The current internal capabilities are:

- `unrealircd_3281_rce`: selected when the scan evidence matches IRC/UnrealIRCd on port `6667`.
- `ftp_anonymous_access`: selected when FTP is exposed and validates whether anonymous access is enabled.
- `mysql_handshake_exposure`: selected when MySQL is exposed and validates unauthenticated handshake exposure.

That means the action is not selected by a hidden hardcoded `if` in the execution step. LangGraph runs a selection node, records the matching reasons, and then passes the selected capabilities to the execution node. Automatic execution is limited to capabilities that pass the runtime safety filter and have a registered adapter.

In the CLI output, `verified` means the exploit did more than connect to the service. The workflow caused the lab service to run a hardcoded benign command, collected the command output, and confirmed the proof file existed inside the Docker target. A successful proof currently looks like `uid=1121(boba_fett) ...`, which shows command execution happened as the vulnerable service user.

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
- Internal capability entries.
- Capability match rules: service, ports, and product/version keywords.
- Proof marker path and proof command.
- Provider-backed capability metadata from Metasploit, Nuclei, and Nmap NSE.

The code still intentionally enforces:

- Target validation against configured localhost names and CIDR allowlist.
- Runner registry: only known runner adapters can execute.
- External provider execution policy: generated inventory items can be selected/recommended, but execution is still mediated by provider-specific adapters and the lab allowlist.
- Cleanup verification after exploitation.
- Safety/reporting boundaries.

## Tool Boundary

The deployable LangGraph agent does not depend on Docker. Docker is only used by the local lab setup CLI.

The current deployable agent tools are:

- TCP connectivity checks.
- Nmap service discovery.
- Optional Nmap `default,safe` script validation.
- HTTP probing.
- Capability candidate selection from the generated inventory.
- Execution of registered local runner functions.
- Execution of allowed safe/default Nmap NSE scripts.
- Execution of allowed Nuclei templates when the `nuclei` binary is installed.
- Execution of allowed Metasploit modules when `msfconsole` is installed. Auxiliary scanner/check modules run directly; exploit modules run in Metasploit `check` mode in `aggressive_lab`.
- MedFlow/ATT&CK retrieval.
- Safety review.
- LLM narrative reporting.

MITRE ATT&CK is used for technique context and reporting, not exploit code. ATT&CK can keep the agent current on tactics, techniques, mitigations, and detection context, but execution requires either vetted local runners or an integration with a maintained exploit framework.

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

- Metasploit metadata: module paths, CVEs, service hints, ports, and safety metadata.
- Nuclei templates: template IDs, tags, CVEs, severity, and HTTP/service hints.
- Nmap NSE scripts: categories, service/port hints, and runtime safety classification.

The selector can recommend any generated capability, but the executor only runs capabilities with an allowed registered adapter.

Execution policy:

- In `safe` mode, Nmap NSE execution is limited to `safe` and `default` categories.
- In `safe` mode, Metasploit execution is limited to generated modules marked safe, currently auxiliary scanner/version/enum-style modules.
- In `safe` mode, Nuclei execution is limited to templates that are not critical and do not carry DoS tags.
- In `aggressive_lab` mode, the runner may execute vetted local NSE `vuln`, `exploit`, `intrusive`, and `malware` validation scripts against the configured allowlisted lab target.
- In `aggressive_lab` mode, Metasploit exploit modules run in `check` mode, not blind exploit mode.
- Brute-force, credential, hash, password, and DoS indicators are blocked across automatic provider execution.

If `nuclei` or `msfconsole` is not installed, the corresponding runner reports that clearly in the saved result instead of treating the capability as metadata-only.

Install optional external execution tools:

```bash
scripts/install_redteam_tools.sh nuclei
scripts/install_redteam_tools.sh metasploit
```

Metasploit availability depends on your apt sources. Once `msfconsole` is on `PATH`, the MedFlow runner uses it automatically.

## Remaining Architecture Work

To avoid becoming a one-exploit demo, the next step is to replace the small local runner registry with a proper capability layer:

- Add a capability discovery node that can list available vetted tools, such as Metasploit modules, Nuclei templates, custom validation scripts, or internal red-team tools.
- Add catalog enrichment from external sources such as MITRE ATT&CK, NVD/CVE feeds, Exploit-DB metadata, Metasploit module metadata, and Nuclei template metadata.
- Keep execution policy separate from knowledge retrieval, so new intelligence can update recommendations without automatically granting permission to run dangerous actions.
- Add scoring that considers service fingerprint, version confidence, exploit reliability, safety rating, target scope, and cleanup support.
- Add dry-run mode to show selected actions without execution.
- Add unit tests for allowlist enforcement, exploit selection, no-match behavior, cleanup, and malformed config.

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
