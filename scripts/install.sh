#!/usr/bin/env bash
# Claude-AgentHunter installer — copies skills into harness skill dirs.
# Usage: ./scripts/install.sh [--all | --claude | --opencode | --hermes | --codex | --antigravity]
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILLS="$HERE/skills"

# harness -> skills directory (verified for Claude Code; others best-known, override with $AGENT_HUNTER_DIR)
declare -A DIRS=(
  [claude]="$HOME/.claude/skills"
  [opencode]="$HOME/.config/opencode/skills"
  [hermes]="$HOME/.hermes/skills"
  [codex]="$HOME/.codex/skills"
  [antigravity]="$HOME/.antigravity/skills"
)

install_to() {
  local name="$1" dir="${DIRS[$1]:-}"
  [ -z "$dir" ] && { echo "  ! unknown harness: $name"; return; }
  mkdir -p "$dir"
  local n=0
  for s in "$SKILLS"/*/; do
    cp -R "$s" "$dir/$(basename "$s")" && n=$((n+1))
  done
  echo "  ✓ $name -> $dir  ($n skills)"
}

detect() {
  for h in claude opencode hermes codex antigravity; do
    [ -d "$(dirname "${DIRS[$h]}")" ] && echo "$h"
  done
}

case "${1:---all}" in
  --all)  found=$(detect); [ -z "$found" ] && { echo "no harness config dirs found"; exit 1; }
          for h in $found; do install_to "$h"; done ;;
  --claude|--opencode|--hermes|--codex|--antigravity) install_to "${1#--}" ;;
  *) echo "usage: install.sh [--all|--claude|--opencode|--hermes|--codex|--antigravity]"; exit 1 ;;
esac
echo "done. $(ls -d "$SKILLS"/*/ | wc -l | tr -d ' ') skills available."
