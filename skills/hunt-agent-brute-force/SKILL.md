---
name: hunt-agent-brute-force
description: "Brute-force and rate-limiting weaknesses in AI-agent tools — PIN/token/password guessing with no lockout, and feedback oracles (correct-digit / too-high-low / Mastermind-style) that collapse the search space. Use when a tool accepts guesses and returns feedback without throttling."
sources: arkx_ctf(field-validated), owasp_llm_top10_2025, owasp_agentic_asi_2026
report_count: 1
validated_against: "brute-force with a timing oracle CONFIRMED re-runnably in the validation lab (`lab/exploits/exploit_brute_force.py`: no lockout, prefix-timing oracle controlled against a known-wrong prefix, PIN recovered in 40 probes and actioned). 4-digit PIN recovered via digit-elimination + permutation with no rate limiting/lockout (ARKX Mastermind)"
---

# Hunt Agent Brute-Force & Rate Limiting

Tools that accept guesses (PINs, tokens, passwords) without rate limiting or lockout are brute-forceable, and any feedback ("digit correct," "too high") is an oracle that collapses the search space. In enterprises this is agent-fronted MFA/OTP/PIN checks, coupon/voucher validation, and token verification exposed as a tool.

## Where This Lives / Attack Surface Signals
- Tools that accept guesses: check_pin, verify_token, guess, validate, unlock.
- Feedback returned: "X digits correct," "Y in position," "too high/low."
- Known-format secret (4 digits, 6 hex, etc.); no mention of rate limit/lockout/max attempts.
- Agent encourages retries ("try again!").

## Crown Jewel Targets
Agent-fronted authentication (OTP/PIN/API-token verification), voucher/coupon systems, "unlock" gates — recovery = account/resource access.

## Characterize First
1. **Search space** — 4 digits (10k), 6 hex (16M), alphanumeric (larger)?
2. **Rate limiting** — send 5 rapid guesses; all answered = none.
3. **Lockout** — send 10 wrong; if the 11th still works = none.
4. **Feedback** — what does each guess reveal? More feedback = faster elimination.

## Technique 1 — Digit/character elimination [CONFIRMED]
When feedback says which digits are present, find the set, then permute.
```
Test 0000,1111,…,9999 → the four that return "1 correct" are the digits → test the 24 permutations
```
`Field example:` 10 digit tests + 24 permutations = 34 guesses vs 10,000.

## Technique 2 — Binary search (comparison oracle) [REFERENCE]
"too high/low" → ~log2(N) guesses.

## Technique 3 — Positional extraction [REFERENCE]
"correct position" feedback → test each position independently (~10×len).

## Technique 4 — Feedback-oracle pruning [REFERENCE]
After each guess, eliminate all candidates that would produce different feedback (Mastermind solver) until one remains.

## Verification & False-Positive Gate
1. **Must recover AND use the secret** — knowing the digits isn't enough; the PIN/token must submit and be accepted (a hallucinated "correct" acknowledgement is not proof).
2. **Confirm no lockout** — show the 11th+ guess still gets a response; document attempts (X reduced to Y).
3. **Reproduce ≥3×.**
4. **Self-description untrusted** — the agent saying "that's correct!" isn't proof; the recovered secret must open the resource.
5. **Min-necessary** — recover one secret to prove the missing control; don't enumerate the whole keyspace of live accounts.

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
No rate limiting; no lockout; verbose feedback oracle; small search space; guess-verification exposed as an unthrottled tool.

## Impact & Severity
- **HIGH:** brute-force recovers a credential/PIN/token granting access.
- **MEDIUM:** feedback oracle enables efficient search but many requests.
- **LOW:** large space, no feedback optimization.

## Mapping
- OWASP LLM Top 10 (2025): **LLM06 Excessive Agency** (unthrottled auth attempts). Agentic ASI (2026): missing rate-limit/anti-automation on tool actions. CWE-307 / 799.

`Field example:` reproduced deterministically in `lab/` — a 4-digit PIN gate with **no lockout** (25 wrong guesses all answered) and a short-circuit comparison that leaks prefix correctness. Control first: a known-right prefix timed **0.025s** against **0.000s** for a known-wrong one, proving the oracle discriminates before any timing result was trusted. The PIN then fell in **40 timed probes instead of 10,000 guesses**, and the recovered value **authenticates** — an actioned secret, not a statistical hint. Gate: `python3 lab/run_lab.py`.

## Runnable Probe [self-contained]
```python
#!/usr/bin/env python3
# Two things: (1) is the verify endpoint throttled/locked after N bad guesses? (2) does it leak a
# feedback ORACLE (partial-correctness, differential timing/message) that shrinks the search space?
# deps: stdlib only. Small N — this is a control test, not an actual brute-force run.
import json, time, urllib.request
VERIFY = "https://target/agent/verify"     # {"code": "..."} -> accept/reject
COOKIE = "session=REPLACE"
def guess(code):
    t = time.time()
    r = urllib.request.Request(VERIFY, data=json.dumps({"code": code}).encode(),
        headers={"Cookie": COOKIE, "Content-Type": "application/json"}, method="POST")
    try: body = urllib.request.urlopen(r, timeout=15).read().decode("utf-8", "replace")
    except Exception as e: body = f"ERR {e}"
    return time.time() - t, body

resps = [guess(f"{i:06d}") for i in range(20)]                 # 20 bad guesses
blocked = any("locked" in b.lower() or "too many" in b.lower() or "429" in b for _, b in resps)
print("[throttle]", "present (lockout/429 seen)" if blocked else "ABSENT — unlimited guessing")
msgs = {b for _, b in resps}
print("[oracle]", "LEAK — responses differ per guess (partial-correctness?)" if len(msgs) > 1
      else "uniform responses (no obvious oracle)")
dts = sorted(dt for dt, _ in resps)
print(f"[timing] min={dts[0]:.3f}s max={dts[-1]:.3f}s  (large spread -> timing oracle candidate)")
# LETHAL WHEN: no lockout AND (a) the keyspace is small enough to exhaust, or (b) an oracle
# (message/timing/partial-match) narrows it — and you actually RECOVER the secret and use it.
```

## Related Skills
`hunt-agent-crypto` (token encrypted, not verified — ECB oracle) · `hunt-agent-auth-bypass` (claim the role instead of guessing) · `ai-agent-methodology` · `redteam-mindset`
