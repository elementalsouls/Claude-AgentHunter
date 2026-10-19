#!/usr/bin/env bash
# Claude-AgentHunter installer — copies the skills into each agent harness's skill dir.
# Same routing as the sibling Claude-BugHunter (the one verified convention):
#
#   Claude Code (baseline)  ~/.claude/skills/            (default)
#   OpenCode                reads ~/.claude/skills + ~/.agents/skills   (default | --agents)
#   OpenAI Codex CLI        ~/.agents/skills/            (--agents)
#   Hermes Agent            ~/.hermes/skills/            (--hermes)
#   Google AntiGravity      ~/.gemini/config/skills/     (--antigravity)
#
# The skills port to all five. The slash commands and the engine/lab stay Claude-Code /
# standalone by design. Only the Claude Code path is verified end-to-end here.
#
# Usage: ./scripts/install.sh [--all | --claude | --agents | --hermes | --antigravity]
# Pure bash 3.2 (macOS default) — no associative arrays.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILLS="$HERE/skills"

dir_for() {
  case "$1" in
    claude)      echo "$HOME/.claude/skills" ;;
    agents)      echo "$HOME/.agents/skills" ;;        # Codex CLI + OpenCode's secondary path
    hermes)      echo "$HOME/.hermes/skills" ;;
    antigravity) echo "$HOME/.gemini/config/skills" ;;
    *)           echo "" ;;
  esac
}

install_to() {
  local name="$1" dir; dir="$(dir_for "$1")"
  [ -z "$dir" ] && { echo "  ! unknown target: $name"; return; }
  mkdir -p "$dir"
  local n=0
  for s in "$SKILLS"/*/; do
    cp -R "$s" "$dir/$(basename "$s")" && n=$((n+1))
  done
  echo "  ✓ $name -> $dir  ($n skills)"
}

detect() {
  echo "claude"                                                        # baseline, always
  { [ -d "$HOME/.agents" ] || [ -d "$HOME/.codex" ] || [ -d "$HOME/.config/opencode" ] \
      || command -v codex >/dev/null 2>&1; } && echo "agents"          # Codex / OpenCode
  { [ -d "$HOME/.hermes" ] || command -v hermes >/dev/null 2>&1; } && echo "hermes"
  { [ -d "$HOME/.gemini" ] || command -v antigravity >/dev/null 2>&1; } && echo "antigravity"
  true
}

case "${1:---all}" in
  --all)  for h in $(detect); do install_to "$h"; done ;;
  --claude|--agents|--hermes|--antigravity) install_to "${1#--}" ;;
  *) echo "usage: install.sh [--all|--claude|--agents|--hermes|--antigravity]"; exit 1 ;;
esac
echo "done. $(ls -d "$SKILLS"/*/ | wc -l | tr -d ' ') skills available."
