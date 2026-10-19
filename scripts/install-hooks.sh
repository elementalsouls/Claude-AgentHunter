#!/usr/bin/env sh
# Install the repo's git hooks into .git/hooks (opt-in — git hooks are not cloned).
# Idempotent: re-run any time. Uninstall: rm .git/hooks/pre-commit
root="$(git rev-parse --show-toplevel)" || { echo "not a git repository" >&2; exit 1; }
src="$root/scripts/hooks/pre-commit"
dst="$root/.git/hooks/pre-commit"

[ -f "$src" ] || { echo "missing $src" >&2; exit 1; }
mkdir -p "$root/.git/hooks"
chmod +x "$src"

# Prefer a symlink so the hook tracks the committed source; fall back to a copy.
if ln -sf ../../scripts/hooks/pre-commit "$dst" 2>/dev/null; then
  :
else
  cp "$src" "$dst"
fi
chmod +x "$dst" 2>/dev/null || true

echo "installed pre-commit hook -> $dst"
echo "runs scripts/scan_secrets.py on staged files before every commit."
