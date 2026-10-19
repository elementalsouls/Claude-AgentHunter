# Contributing

PRs and issues welcome.

## What's in scope for contributions

- **New `hunt-agent-*` skills** for agent attack surface not yet covered — new MCP/A2A
  patterns, new RAG/vector-store classes, new multi-agent or memory vectors.
- **New or better Runnable Probes** — a sharper stdlib-only probe for an existing skill, or
  a tighter `# LETHAL WHEN:` tie to a gate.
- **Engine arms and adapters** — a new `engine/adapters/<target>.py` that normalises another
  benchmark/target into the trace shape; improvements to an arm that cut false positives
  *without* dropping a genuine detection.
- **Lab gates** — a new deterministic exploit gate in `lab/exploits/` (a vuln class **and**
  its control), wired into `lab/run_lab.py`.
- **Field evidence** — reproducible runs against a benchmark or an authorized target, with
  the logs that back the claim.
- **Documentation** — clearer `USAGE.md`, more worked examples, better `INSTALL.md`
  troubleshooting, coverage-matrix additions.

## What's NOT in scope

- Skills or probes that include real exploitation payloads against specific named targets —
  keep everything abstract / class-based.
- Personally-identifiable engagement data — anonymize all examples (target names, account
  UIDs, endpoints, bounty amounts, credentials, PII).
- Generic web/infra vuln classes that already live in the sibling
  [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) bundle — this one is
  AI-agent surface only.
- Anything requiring non-MIT-licensed dependencies. The engine and lab are stdlib-only by
  design; keep them that way.

## How to propose a change

### Small fix or doc improvement

1. Fork the repo
2. Make the change on a branch
3. Open a PR with a short description of what changed and why

### New skill

1. Open a **New skill proposal** issue first (name, purpose, the gap it fills, a sketch of
   the Runnable Probe + `# LETHAL WHEN:`).
2. Get feedback on scope/overlap before writing the full SKILL.md.
3. Once agreed, submit a PR with:
   - `skills/<name>/SKILL.md` — `name` (lowercase-hyphen), `description` ≤ 1024 chars weaving
     in trigger keywords, `sources:` + `validated_against:` frontmatter, a Runnable Probe,
     and a `# LETHAL WHEN:` line.
   - An entry in `docs/skills.md` and the `README.md` catalog.
   - One worked example showing the skill triggering correctly.

## Skill quality standards

- **Frontmatter**: `name` (lowercase-hyphen-only) + `description` (≤ 1024 chars, trigger
  keywords as natural prose) + `sources` + `validated_against`.
- **Runnable Probe**: stdlib-only, copy-paste, plants a known-true **control** first
  (Negative-Result gate rule 1).
- **Score by the sink, not the model's words** — a clever response is not a finding; the
  value equals the tool action / data / cross-tenant effect it reaches.
- **Single responsibility**, and cross-reference complementary skills.

## Testing changes

- `python3 lab/run_lab.py` — the 14 exploit gates must stay 14/14.
- `python3 engine/gates.py` — gate self-check, if you touched the gates.
- `cd engine && python3 test_arms.py` — the four detection arms' regression tests (DVLA adapter + synthetic fixtures); must stay green if you touch `engine/score.py` or an adapter.
- `python3 scripts/lint_skills.py` — skill frontmatter + the Runnable-Probe / `# LETHAL WHEN:` invariants, plus a secret scan (leaked flags, home paths, tokens). CI runs it on every skill change.
- For a skill: install it locally, open a fresh session, describe a test in plain English,
  and confirm the skill auto-triggers and its probe behaves.
- **Judge a tuning change by whether a genuine detection dropped, not by the FP count**
  (Negative-Result gate rule 8).

## Code of conduct

- Be respectful in PRs and issues.
- Never include personal data, credentials, or specific target identifiers in examples.
- Cite sources when adapting from disclosed reports, CVEs, or research.

## Licensing

By contributing, you agree your changes are licensed under the same MIT license as the rest
of the repo.
