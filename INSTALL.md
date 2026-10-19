# Install

## Plugin (Claude Code)
```
/plugin marketplace add elementalsouls/Claude-AgentHunter
/plugin install claude-agenthunter@elementalsouls
```
Skills install namespaced under `claude-agenthunter:` and update on version bump — no file copying.
Manifests: `.claude-plugin/plugin.json` + `.claude-plugin/marketplace.json`.

## Copy install (any harness)
```sh
./scripts/install.sh --all
```
Detects which harness config dirs exist and copies `skills/*/` into each:

| harness | skills dir |
|---|---|
| Claude Code | `~/.claude/skills/` |
| OpenCode | `~/.config/opencode/skills/` |
| Hermes | `~/.hermes/skills/` |
| Codex CLI | `~/.codex/skills/` |
| AntiGravity | `~/.antigravity/skills/` |

Only the Claude Code path is verified here; the others are best-known defaults. If a harness reads
skills from elsewhere, point it there and re-run with the single-harness flag (`--opencode`, etc.).

## Engine (standalone, no harness)
```sh
python3 engine/gates.py        # self-check the gate logic
python3 engine/score.py        # usage
python3 lab/run_lab.py         # 21/21 exploit gates
```
Python 3.11+ (3.12 recommended; some harness-driver deps break on 3.14). No install for the lab —
stdlib only.
