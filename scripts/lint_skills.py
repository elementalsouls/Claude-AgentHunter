#!/usr/bin/env python3
"""Structure gate for every skill. Stdlib only — no deps, no network.

Run from the repo root:  python3 scripts/lint_skills.py
Exit 0 = clean, 1 = one or more errors (printed as GitHub annotations).

Checks, per skills/<name>/SKILL.md:
  - a YAML-ish frontmatter block delimited by ---
  - required keys: name, description, sources, validated_against
  - name is lowercase-hyphen and equals the directory name
  - description <= 1024 chars (Codex/strict-YAML harness ceiling)
  - body carries the two house invariants: "Runnable Probe" and "# LETHAL WHEN:"

Leak detection (flags, home paths, credential tokens) lives in scripts/scan_secrets.py,
which scans the WHOLE repo, not just skills/. Keep that the single source of truth.
"""
from __future__ import annotations
import os
import re
import sys
import glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQUIRED = ("name", "description", "sources", "validated_against")
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

errors: list[str] = []


def err(path: str, msg: str) -> None:
    errors.append(f"::error file={os.path.relpath(path, ROOT)}::{msg}")


def parse_frontmatter(text: str) -> dict[str, str] | None:
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end == -1:
        return None
    fm: dict[str, str] = {}
    for line in text[3:end].splitlines():
        m = re.match(r"^([A-Za-z0-9_]+):\s*(.*)$", line)
        if m:
            fm[m.group(1)] = m.group(2).strip()
    return fm


def lint_skill(skill_md: str) -> None:
    name = os.path.basename(os.path.dirname(skill_md))
    text = open(skill_md, encoding="utf-8", errors="replace").read()
    fm = parse_frontmatter(text)
    if fm is None:
        err(skill_md, "missing or unterminated --- frontmatter block")
        return
    for key in REQUIRED:
        if key not in fm or not fm[key]:
            err(skill_md, f"frontmatter missing required key: {key}")
    fm_name = fm.get("name", "").strip('"').strip("'")
    if fm_name != name:
        err(skill_md, f"frontmatter name '{fm_name}' != directory '{name}'")
    if fm_name and not NAME_RE.match(fm_name):
        err(skill_md, f"name '{fm_name}' is not lowercase-hyphen")
    desc = fm.get("description", "")
    if desc.strip() in (">", "|", ">-", "|-", ">+", "|+"):
        # a YAML block scalar collapses to its indicator here, silently dodging the length gate
        err(skill_md, "description must be a single-line quoted string, not a block scalar (>, |)")
    elif len(desc) > 1024:
        err(skill_md, f"description is {len(desc)} chars (> 1024)")
    body = text[text.find("\n---", 3) + 4:] if fm else text
    if "Runnable Probe" not in body:
        err(skill_md, "body is missing a 'Runnable Probe' section")
    if "LETHAL WHEN" not in body:
        err(skill_md, "body is missing a '# LETHAL WHEN:' line")


def main() -> int:
    skill_mds = sorted(glob.glob(os.path.join(ROOT, "skills", "*", "SKILL.md")))
    if not skill_mds:
        print("no skills found — run from the repo root", file=sys.stderr)
        return 1
    for s in skill_mds:
        lint_skill(s)

    if errors:
        for e in errors:
            print(e)
        print(f"\nskill-lint: {len(errors)} error(s) across {len(skill_mds)} skills", file=sys.stderr)
        return 1
    print(f"skill-lint: OK — {len(skill_mds)} skills, structure clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
