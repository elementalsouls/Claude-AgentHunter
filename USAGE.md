# Usage

How to actually run an agent pentest with this bundle. For install, see
[`INSTALL.md`](INSTALL.md); for the threat model, [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

## The one rule

An agent **generates** text; it does not **retrieve** state. A fluent answer looks identical
to a real leak, and a silent probe looks identical to a secure target. So every finding goes
through two gates (`engine/gates.py`):

- **False-Positive gate** — never claim what you can't prove by *effect* (not by the model's word).
- **Negative-Result gate** — never claim "clean" without a **control** proving the probe could have fired.

Report the state / data / action obtained — never what the model said.

## The workflow (`/hunt-agent`)

Describe your target in plain English and the relevant skills auto-load. The command runs
five steps, in order:

1. **Characterize first** — visibility, tool allowlist, egress, oracle semantics, auth/tenancy.
   *Never send a payload before this.*
2. **Select skills by surface:**
   - MCP server → `hunt-agent-mcp-exposure`, `hunt-agent-mcp-supply-chain`
   - chat / RAG → `hunt-agent-prompt-injection`, `hunt-agent-rag`
   - tool-calling / ReAct → `hunt-agent-tool-injection`, `hunt-agent-output-exfil`
   - memory / multi-turn → `hunt-agent-memory-poisoning`, `hunt-agent-native-memory`
   - full catalog: [`docs/skills.md`](docs/skills.md)
3. **Run each skill's Runnable Probe** — plant a known-true **control** first.
4. **Score traces** with the engine — a target is clean only when all arms agree *and* their
   controls fired.
5. **Gate every finding** through `engine/gates.py` and report only actioned findings.

## The engine

Four complementary detection arms over one normalised trace shape — no arm is sufficient alone:

| arm | detects | blind to |
|---|---|---|
| **A · taint** | attacker-planted value reaching a tool argument | injections reusing data the agent already holds |
| **B · unrequested action** | a state-changing call the clean baselines never made | wording drift |
| **C · output echo** | injected content surfacing in the agent's own voice | paraphrase; quoted data |
| **D · provenance** | the agent acting on a value only untrusted content supplied | nothing structural — the general case |

```sh
python3 engine/gates.py                                          # self-check the gate logic
python3 engine/score.py agentdojo <runs_dir> <suite> --baselines d1,d2
```

## The lab — prove it offline

No model, no API key. Each gate encodes a vulnerability class **and** its control.

```sh
python3 lab/run_lab.py        # 21/21 exploit gates — [CONFIRMED] means re-runnable
```

Lab environment lives in `lab/` (`target/vuln_agent.py`, `target/oob_listener.py`,
`mcp/mcp_target.py`). `lab/secret.txt` holds a deliberate, non-reusable flag
(`LAB-FLAG-…`) — it is the exfil oracle, not a real secret.

## Field evidence

Reproducible runs against benchmarks and authorized targets live in `field/`:

| dir | target | result |
|---|---|---|
| `field/agentdojo` | AgentDojo (4 suites) | 949 runs, FN 0 |
| `field/dvmcp` | Damn Vulnerable MCP | 10/10 |
| `field/dvla` | LangChain ReAct banking agent | scratchpad forgery → SQL chain |
| `field/injecagent` | InjecAgent (indirect injection) | arm D 7/7 |
| `field/arkx` | ARKX CTF | direct injection + contract extraction |

## Authorized use only

Test agents you own or are explicitly authorized to assess. The probes send live payloads and
the lab targets are intentionally vulnerable. See [`SECURITY.md`](SECURITY.md).
