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
./scripts/install.sh --all          # macOS / Linux
pwsh ./scripts/install.ps1 -All     # Windows (PowerShell)
```
Detects which harnesses are installed and copies `skills/*/` into each — same routing as the
sibling Claude-BugHunter (the verified convention):

| harness | target skill dir | flag |
|---|---|---|
| Claude Code (baseline) | `~/.claude/skills/` | *(default)* |
| OpenCode | reads `~/.claude/skills/` & `~/.agents/skills/` | *(default)* \| `--agents` |
| OpenAI Codex CLI | `~/.agents/skills/` | `--agents` |
| Hermes Agent | `~/.hermes/skills/` | `--hermes` |
| Google AntiGravity | `~/.gemini/config/skills/` | `--antigravity` |

The skills port to all five. The slash commands and the engine/lab stay Claude-Code / standalone
by design. Only the Claude Code path is verified end-to-end here; if a harness reads skills from
elsewhere, point it there and re-run with the single-harness flag.

## Engine (standalone, no harness)
```sh
python3 engine/gates.py        # self-check the gate logic
python3 engine/score.py        # usage
python3 lab/run_lab.py         # 24/24 exploit gates
```
Python 3.11+ (3.12 recommended; some harness-driver deps break on 3.14). No install for the lab —
stdlib only.
