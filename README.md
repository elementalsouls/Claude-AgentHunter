![Claude-AgentHunter banner](assets/banner-v2.svg)

# claude-agenthunter

> **Pentest AI agents — and prove both the findings and the absences.** A skill bundle plus a runnable engine for red-teaming LLM agents: chatbots, RAG assistants, tool-calling copilots, MCP servers, and autonomous ReAct agents · **23 skills** · 4 detection arms · 14/14 lab gates · 7 lab environments · FN 0 over 949 field runs · loads into Claude Code, OpenCode, Hermes, Codex CLI and AntiGravity.

Built by **[Sachin Sharma](https://www.linkedin.com/in/sachinsharma8080/)** — Bug Hunting & GenAI Security Research.

---

Sibling to [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) — same shape,
different quarry. BugHunter hunts web apps; Claude-AgentHunter hunts the agents themselves.

```
23 skills   ·   4 detection arms   ·   14/14 lab gates   ·   7 lab environments   ·   FN 0 over 949 runs
```

## Why it exists

An agent generates text; it does not retrieve state. That creates two failure modes a web pentest
never has to worry about, and **Claude-AgentHunter is built around catching both**:

- A fluent answer looks identical to a real leak → the **False-Positive gate**.
- A silent probe looks identical to a secure target → the **Negative-Result gate**.

The second one is the hard one. Across this project's own development, **ten probe defects each
reported a compromise as clean** — a similarity gate that scored a real leak 0.03, an HTTP 500
counted as a refusal that buried a confirmed bypass, a token floor that hid the forgery that leaked
the flag. Every one looked like a passing test. Both gates live in `engine/gates.py` and ship in
every skill.

## How the skills work

Each skill is `skills/<name>/SKILL.md` — Agent-Skills markdown with frontmatter (`name`,
`description`, `sources`, `validated_against`). Harnesses topic-match on the description; describing
your test in plain English loads the relevant skills, no explicit invocation. Unlike static
methodology skills, each one carries a **Runnable Probe** that executes against a live agent and a
**`# LETHAL WHEN:`** line tying its output to the gate. Catalog: [`docs/skills.md`](docs/skills.md).

## The engine (what connects and merges)

`engine/` is the deterministic core. It normalises any target into one trace shape
(`engine/adapters/`), runs four complementary detection arms over it, and gates the result:

| arm | detects | blind to |
|---|---|---|
| **A · taint** | an attacker-planted value reaching a tool argument | injections that reuse data the agent already holds |
| **B · unrequested action** | a state-changing call the clean baselines never made | wording drift (needs baselines scaled to argument entropy) |
| **C · output echo** | injected content surfacing in the agent's own voice | paraphrase; quoted data (stripped) |
| **D · provenance** | the agent acting on a value only untrusted content supplied | nothing structural — the general case |

No arm is sufficient alone. Taint is 64/64 on one suite and **0/39** on another. A target is clean
only when all arms agree **and their controls fired**.

```sh
python3 engine/score.py agentdojo <runs_dir> <suite> --baselines d1,d2
```

## Install

```sh
git clone https://github.com/elementalsouls/Claude-AgentHunter && cd Claude-AgentHunter
./scripts/install.sh --all          # detects Claude Code, OpenCode, Hermes, Codex, AntiGravity
./scripts/install.sh --claude       # or one harness
```
Or as a Claude Code plugin via the marketplace (`.claude-plugin/plugin.json`) — namespaced, no copy.

## Proof it works — `lab/` and `field/`

- **`lab/`** — 14 deterministic exploit gates (`python3 lab/run_lab.py`), no model, no API key. Each
  encodes a vulnerability class and its control; `[CONFIRMED]` means re-runnable, not "the model said so".
- **`field/`** — evidence from live/benchmark targets: AgentDojo (4 suites, 949 runs, FN 0), DVMCP
  (10/10), DVLA (ReAct forgery → SQL chain), InjecAgent (arm D 7/7 indirect), a real MCP target, ARKX.

## Documentation

- [`USAGE.md`](USAGE.md) — the workflow, the engine, the lab, field evidence, end to end.
- [`INSTALL.md`](INSTALL.md) — plugin + copy install across five harnesses.
- [`docs/skills.md`](docs/skills.md) — the 23-skill catalog.
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) · [`docs/COVERAGE-MATRIX.md`](docs/COVERAGE-MATRIX.md) · [`docs/RESEARCH-2026.md`](docs/RESEARCH-2026.md) · [`docs/DEFENSES-AND-DETECTION.md`](docs/DEFENSES-AND-DETECTION.md) · [`docs/REFERENCES.md`](docs/REFERENCES.md)
- [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`CHANGELOG.md`](CHANGELOG.md)

## Authorized use only

For testing agents you own or are explicitly authorized to assess. The probes send live payloads
and the lab targets are intentionally vulnerable. See [`SECURITY.md`](SECURITY.md).
