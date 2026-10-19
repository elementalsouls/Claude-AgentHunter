#!/usr/bin/env python3
"""Repo-wide leak guard. Stdlib only — no deps, no network.

Scans EVERY tracked text file (not just skills/) for the classes of leak that have
actually bitten this repo or would be fatal to publish:

  - real ARKX CTF flag values (flag-<6 hex>), excluding REDACTED/placeholder forms
  - absolute home paths (/Users/<user>, /home/<user>) that leak a username
  - credential tokens: AWS keys, GitHub/Slack tokens, Anthropic/OpenAI keys, private keys
  - a small denylist of specific strings that must never ship (extend as needed)

Run:  python3 scripts/scan_secrets.py            # scan every tracked file (CI)
      python3 scripts/scan_secrets.py <paths...> # scan only these files (pre-commit hook)
Exit 0 = clean, 1 = one or more hits (printed as GitHub annotations).

This is the single source of truth for leak detection; scripts/lint_skills.py validates
skill STRUCTURE only and defers secret scanning to here. The pre-commit hook
(scripts/hooks/pre-commit, installed via scripts/install-hooks.sh) passes the staged
files so a leak is blocked before it is ever committed.
"""
from __future__ import annotations
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Files that legitimately CONTAIN these patterns (the scanners themselves) — never scan them.
SELF = {"scripts/scan_secrets.py", "scripts/lint_skills.py"}

# Binary / non-text extensions to skip (decode errors are also skipped defensively).
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2",
            ".zip", ".gz", ".mp4", ".mov", ".pyc"}

# (label, regex, allowlist substrings that are known-safe if they appear in a hit)
PATTERNS = [
    ("real CTF flag value", re.compile(r"flag-[0-9a-f]{6}\b"), ("flag-redacted", "flag-abc123")),
    ("absolute home path (username leak)", re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+/?"), ()),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), ()),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), ()),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), ()),
    ("Anthropic/OpenAI key", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"), ()),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), ()),
]

# Specific strings that must never appear anywhere (the redacted ARKX flags, etc.).
DENYLIST = (
    "flag-1f4329", "flag-7d3316", "flag-9e47d6", "flag-739b6d",
    "flag-9e3ec1", "flag-3e9aab", "flag-2a33b0", "flag-e935da",
)

errors: list[str] = []


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout
    return [p for p in out.split("\0") if p]


def scan(path: str) -> None:
    rel = os.path.relpath(os.path.abspath(path), ROOT)
    if rel in SELF or os.path.splitext(rel)[1].lower() in SKIP_EXT:
        return
    try:
        text = open(path, encoding="utf-8").read()
    except (UnicodeDecodeError, OSError):
        return   # binary or unreadable — not a text leak surface
    for i, line in enumerate(text.splitlines(), 1):
        for deny in DENYLIST:
            if deny in line:
                errors.append(f"::error file={rel}::line {i}: denylisted string: {deny!r}")
        for label, rx, allow in PATTERNS:
            for m in rx.finditer(line):
                hit = m.group(0)
                if any(a in hit.lower() for a in allow):
                    continue
                errors.append(f"::error file={rel}::line {i}: possible {label}: {hit!r}")


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--"]
    if args:                                   # pre-commit mode: only the given (staged) files
        files = args
        for p in files:
            scan(p)
    else:                                      # CI mode: every tracked file
        files = tracked_files()
        if not files:
            print("no tracked files — run from the repo root", file=sys.stderr)
            return 1
        for rel in files:
            scan(os.path.join(ROOT, rel))
    if errors:
        for e in errors:
            print(e)
        print(f"\nscan-secrets: {len(errors)} potential leak(s) across {len(files)} files", file=sys.stderr)
        return 1
    print(f"scan-secrets: OK — {len(files)} tracked files, no leaks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
