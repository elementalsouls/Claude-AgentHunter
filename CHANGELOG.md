# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning is loosely [SemVer](https://semver.org/) at the bundle level.

## [0.1.0] — 2026-10-19

Initial public release.

### Added
- **23 `hunt-agent-*` skills + `ai-agent-methodology`** — each is `skills/<name>/SKILL.md`
  (Agent-Skills markdown with `name`, `description`, `sources`, `validated_against`
  frontmatter). Every skill carries a stdlib-only **Runnable Probe** and a `# LETHAL WHEN:`
  line tying its output to a gate. Harnesses topic-match on the description; no invocation
  by name. Catalog in `docs/skills.md`.
- **4-arm detection engine** (`engine/`) — normalises any target into one trace shape
  (`engine/adapters/`) and runs four complementary arms: **A** taint, **B** unrequested
  action, **C** output echo, **D** provenance. A target is clean only when all arms agree
  and their controls fired. Run with `python3 engine/score.py agentdojo <runs_dir> <suite>
  --baselines d1,d2`.
- **The two gates** (`engine/gates.py`) — the **False-Positive gate** (a fluent answer looks
  identical to a real leak) and the **Negative-Result gate** (a silent probe looks identical
  to a secure target). Both ship in every skill.
- **24-gate validation lab** (`lab/`) — deterministic exploit gates, no model and no API key
  (`python3 lab/run_lab.py`). Each encodes a vulnerability class and its control;
  `[CONFIRMED]` means re-runnable.
- **Field evidence** (`field/`) — AgentDojo (4 suites, 949 runs, FN 0), DVMCP (10/10), DVLA
  (ReAct forgery → SQL chain), InjecAgent (arm D 7/7 indirect), a live MCP target, and ARKX.
- **Cross-harness install** — `scripts/install.sh` detects Claude Code, OpenCode, Hermes,
  Codex CLI and AntiGravity. Also installable as a Claude Code plugin via
  `.claude-plugin/plugin.json` + `.claude-plugin/marketplace.json`.
- **`/hunt-agent` command** — the 5-step agent-pentest workflow (characterize → select →
  probe → score → gate).
- **Adaptive red-team harness** (`redteam/`) — evolves injection payloads against a target with
  control-first scoring and lineage-tracked reporting; finds evasions a static probe misses
  (`python3 -m redteam guardrail`). Model-optional: deterministic mutation by default (CI, no key),
  a local-LLM generator as a pluggable opt-in. Regression: `redteam/test_redteam.py`.
- **Repo scaffolding** — `.github/` issue/PR templates + `lab` CI workflow (runs the 24 gates
  on every PR), `.gitignore`, `.gitattributes`, `pyproject.toml`, `CONTRIBUTING.md`,
  `USAGE.md`.

[0.1.0]: https://github.com/elementalsouls/Claude-AgentHunter/releases/tag/v0.1.0
