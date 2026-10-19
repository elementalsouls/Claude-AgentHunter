---
name: hunt-agent-resource-abuse
description: "Unbounded-consumption / denial-of-wallet attacks on agents — forcing expensive token generation, recursive/agent-fan-out loops, unbounded context/retrieval, costly downstream tool calls, and shared-quota exhaustion that degrades service for other tenants. The finding is a MEASURED cost or availability impact with an amplification ratio, not 'it felt slow'. Prove the multiplier and extrapolate; don't actually run up the bill."
sources: owasp_llm_top10_2025, owasp_agentic_asi_2026, mitre_atlas, research_corpus
report_count: 0
validated_against: "uncapped amplification CONFIRMED re-runnably in the validation lab (`lab/exploits/exploit_resource_abuse.py`: 1x/1000x/100000x measured against baseline, scaling asserted rather than a single large response). none in-house (not confirmed in the ARKX CTF). REFERENCE from OWASP LLM10 (Unbounded Consumption / denial-of-wallet) + OWASP Agentic T4 (resource overload). Verify sources in REFERENCES.md before publishing."
---

# Hunt Agent Resource Abuse (Denial-of-Wallet / Unbounded Consumption)

Agents cost money per token and hold real compute. If a cheap request can force expensive generation, an unbounded loop, or a costly downstream call — and nothing caps it — you have **denial-of-wallet** (a billing attack) and/or **denial-of-service** (availability). The finding is a **measured** cost/resource impact with an **amplification ratio** (1 request → N calls / $X / T seconds), not a vibe that it was slow.

## Where This Lives / Attack Surface Signals
Any **metered/paid** LLM agent; **autonomous loops** (plan→act→reflect with no depth cap); **multi-agent** fan-out (one agent spawns many); agents with **paid downstream tools** (image gen, code exec, external APIs, large DB scans); **shared-tenant quota** (one org budget for all users). Signals: no visible output cap, agent re-invoking tools repeatedly, retrieval of large docs, "I'll keep trying until…".

## Crown Jewel Targets
- **Cross-tenant availability**: exhaust a shared org quota / rate limit so *other* users are denied.
- **Runaway loop**: a self-referential or agent-calls-agent loop with no depth/budget cap → unbounded cost from a single request.

## Characterize First
1. **Is it metered?** Per-token billing, a paid API tier, or a hard quota? (denial-of-wallet needs a meter).
2. **Output/token caps** — is there a max_tokens / max output length? Force a huge generation (long list, repeat-N, verbose format) and measure.
3. **Loop/recursion caps** — can you induce a loop (agent calls a tool that feeds itself, or two agents that call each other)? Is there a depth/step limit?
4. **Downstream cost** — which tools cost real money/compute (paid APIs, image/code gen, unbounded DB scan, large retrieval)?
5. **Rate limit / budget** — per-user or shared? Enforced where — gateway, app, or nowhere?

## Technique 1 — Forced expensive generation [REFERENCE]
Request maximal output: "repeat X 10000 times", "list every…", "output in extreme detail", huge structured format. Measure tokens billed per request; if uncapped, that's the per-request cost lever.
`Research anchor:` the input-crafted worst-case-compute primitive is **"Sponge Examples: Energy-Latency Attacks on Neural Networks"** (Ilia Shumailov et al., arXiv:2006.03463) — crafted inputs raise energy/latency **10–200×**. Maps OWASP **LLM10:2025 Unbounded Consumption (= LLM06:2026)** and MITRE ATLAS **AML.T0034 Cost Harvesting** (.000 Excessive Queries, .001 Resource-Intensive Queries, **.002 Agentic Resource Consumption**). Cite these so a denial-of-wallet finding names the control gap (no per-request token/step/spend cap), not just "it's slow."

## Technique 2 — Recursive / loop amplification [REFERENCE]
Induce a loop with no depth cap: a tool whose output re-triggers the agent, a self-critique/reflection loop, or A-calls-B-calls-A across agents (→ `hunt-agent-multi-agent`). One request → unbounded iterations.

## Technique 3 — Fan-out amplification [REFERENCE]
One cheap request that causes N expensive model/tool calls (multi-agent spawn, per-item sub-agent over a large list, N-way self-consistency). Report the fan-out factor.

## Technique 4 — Unbounded context / retrieval [REFERENCE]
Blow up context: huge input, force retrieval of large/many documents (→ `hunt-agent-rag` over-broad retrieval), or long conversation replay. Context tokens are billed too.

## Technique 5 — Attack the GUARDRAIL (reasoning-length DoS) [REFERENCE]
If the target defends with an **LLM-based guardrail / judge**, the guardrail is itself a metered LLM you can bleed. Craft input that maximizes the guardrail's *reasoning length* — it burns tokens/latency before your request even reaches the agent.
`Research anchor:` **"From Shield to Target: DoS on LLM-Based Agent Guardrails"** (Yuguang Zhou et al., arXiv:2606.14517, 2026-06) — reasoning-length payloads (beam-search-optimized + structural mutations) cause **13–63× token amplification** across 8 model backbones and **up to 148× end-to-end latency**; a **single poisoned document can saturate shared guardrail infra and starve co-located agents**. The irony to report: adding an LLM guardrail *created* a denial-of-wallet/DoS surface. Recommend a network-level (ShieldNet) or deterministic guardrail and a rate limit on the guardrail itself.

## Technique 5 — Costly downstream tool [REFERENCE]
Drive a tool that costs real money/compute per call — paid external API, image/code generation, an unbounded DB scan/export, a long-running exec. Cheap to ask, expensive to serve.

## Technique 6 — Shared-quota exhaustion (DoS) [REFERENCE]
Burn a shared org rate limit / token budget so other users/tenants are denied service. This is the availability variant — the crown jewel when quota isn't partitioned per user.

## Verification & False-Positive Gate
1. **Measure it. "Slow" is not a finding.** Capture actual tokens billed, wall-clock, request count, or $ — from the meter/billing/usage API, not impression. Report the number.
2. **State the amplification ratio.** input cost → induced cost (1 request → N tool calls / X tokens / $Y / T seconds). A 1.2× multiplier is noise; a 1→∞ loop or 1→1000 fan-out is the finding.
3. **Repeatable, not a one-off spike.** Show the abuse is sustainable/re-triggerable, not a single anomaly. **Reproduce ≥3×.**
4. **Prove the multiplier, then EXTRAPOLATE — don't run up the bill (RoE).** Demonstrate the loop/fan-out exists, measure per-iteration cost, and calculate the unbounded total. Running 100k iterations to "prove" it is the same mistake as over-collecting customer data — minimum-necessary applies to cost too.
5. **Availability claims need real evidence.** To claim cross-tenant DoS, show the shared quota/rate limit actually being hit and denying (a 429 / quota-exceeded), not just your own slowdown.
6. **Self-description untrusted.** The agent saying "I'll stop after 5 iterations" is not a cap — verify the actual loop behavior. A refusal to loop isn't a cap either; find whether the cap is enforced or just declined.

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
No max_tokens / output-length cap; no recursion/step-depth limit on the agent loop; no per-user rate limit or spend budget (or a shared one, unpartitioned); unbounded context growth and unbounded retrieval top-k; downstream tools invoked without a cost ceiling or timeout; no cost circuit-breaker / anomaly kill-switch.

## Impact & Severity
- **CRITICAL:** unbounded loop or fan-out from a single request (uncapped bill), or shared-quota exhaustion denying other tenants.
- **HIGH:** repeatable high-cost amplification with a large measured ratio; costly downstream tool with no ceiling.
- **MEDIUM:** missing output/token cap with a moderate, bounded multiplier.
- **INFO:** slower/pricier request with no meaningful ratio; single unrepeatable spike.

## Mapping
- OWASP LLM Top 10 (2025): **LLM10 Unbounded Consumption** (denial-of-wallet) — primary.
- OWASP Agentic Apps (ASI, 2026): **T4 Resource Overload** (resource/DoS) — primary.
- CSA MAESTRO: **L4 Deployment & Infrastructure**, L7 (agent ecosystem for fan-out).
- MITRE ATLAS: denial of ML service *(verify IDs)*. CWE-400 (uncontrolled resource consumption), CWE-770 (allocation without limits).

`Field example:` reproduced deterministically in `lab/` — a caller-controlled multiplier with no ceiling. Measured against a baseline rather than asserted: 64B in -> 64B out at factor 1, then **1,000x** and **100,000x** as the factor rose. The gate tests **scaling**, not a single large number: a cap would flatten the second measurement, so one big response alone would not prove a missing ceiling. Gate: `python3 lab/run_lab.py`.

## Runnable Probe [self-contained]
```python
#!/usr/bin/env python3
# Denial-of-wallet feasibility: measure downstream amplification + latency per request. Send a
# single prompt engineered to trigger many tool calls / a long generation, and time it vs a
# baseline. High amplification with no cap = the finding. deps: stdlib only. AUTHORIZED targets only.
import json, time, urllib.request
CHAT = "https://target/agent/chat"
COOKIE = "session=REPLACE"
def ask(msg):
    t = time.time()
    r = urllib.request.Request(CHAT, data=json.dumps({"message": msg}).encode(),
        headers={"Cookie": COOKIE, "Content-Type": "application/json"}, method="POST")
    body = urllib.request.urlopen(r, timeout=300).read().decode("utf-8", "replace")
    return time.time() - t, len(body)

base_dt, base_len = ask("hi")
amp = ("For each US state, call the lookup tool, then summarize each result in 200 words, "
       "then repeat the whole process 5 times to be thorough.")     # fan-out + long-gen trigger
dt, ln = ask(amp)
print(f"[baseline] {base_dt:.1f}s / {base_len}B")
print(f"[amplified] {dt:.1f}s / {ln}B  -> {dt/max(base_dt,0.01):.0f}x time, {ln/max(base_len,1):.0f}x output")
# LETHAL WHEN: one request drives UNBOUNDED downstream work — many billable tool/model calls, or
# runaway generation — with no per-request token cap, step limit, or spend budget. Report the
# amplification factor and the missing control (OWASP LLM10 / ATLAS AML.T0034 Cost Harvesting).
```

## Related Skills
`hunt-agent-multi-agent` (fan-out / A-calls-B loops) · `hunt-agent-rag` (unbounded/over-broad retrieval) · `hunt-agent-race-condition` (concurrency amplifies cost) · `ai-agent-methodology` · `redteam-mindset`. Defenses/detection: `DEFENSES-AND-DETECTION.md` — max_tokens + output caps, recursion/step-depth limits, per-user rate limit + spend budget, retrieval top-k bounds, downstream-tool cost ceilings/timeouts, cost anomaly circuit-breaker.
