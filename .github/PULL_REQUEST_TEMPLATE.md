<!-- Thanks for contributing to Claude-AgentHunter. Keep PRs focused. -->

## What does this change?

<!-- One or two sentences. Link the proposal issue for new skills (#NN). -->

## Type

- [ ] New skill
- [ ] Improvement to an existing skill
- [ ] Engine / gate / lab change
- [ ] Docs / examples
- [ ] Tooling / scripts / CI
- [ ] Other:

## Checklist

- [ ] **No client/engagement data** — no real target names, account UIDs, endpoints, bounty amounts, credentials, or PII. All examples are class-based / anonymized.
- [ ] `python3 lab/run_lab.py` passes locally (14/14 exploit gates).
- [ ] `python3 engine/gates.py` self-check passes if you touched the gates.
- [ ] For a **new skill**: a proposal issue was opened and agreed first; `name` is lowercase-hyphen; description ≤ 1024 chars and weaves in trigger keywords; body stays focused; it carries a **Runnable Probe** and a `# LETHAL WHEN:` line.
- [ ] For a new skill: listed in `docs/skills.md` and the `README.md` catalog, with one worked trigger example.
- [ ] Sources cited (`sources:` / `validated_against:` frontmatter) for anything adapted from disclosed reports / research.
- [ ] Cross-references complementary skills ("see also …") where there's topical overlap.

## Anything reviewers should know?

<!-- Overlap with existing skills, follow-ups, open questions. -->
