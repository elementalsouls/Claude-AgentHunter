---
name: ai-agent-methodology
description: "Master orchestrator for AI-agent red-team assessments — enterprise copilots, DevOps/SRE agents, RAG assistants, coding/IDE agents, MCP/A2A tool servers, autonomous workflow agents. Load at the START of any agent test, when facing a new agent target, or when unsure what to test next. Routes to the hunt-agent-* skills by tool surface and architecture, and enforces the discipline that makes findings genuine: characterize first, verify every claim, reproduce, extract the minimum."
sources: arkx_ctf(field-validated), owasp_llm_top10_2025, owasp_agentic_asi_2026, mitre_atlas
version: 4.0.0
validated_against: 27 agent levels across 4 tracks (see hunt-agent-* skills)
---

# AI Agent Red-Team Methodology

You attack an AI agent through its **tools**, not through URLs and forms. The LLM is middleware; the tools are the sink; the real prize is what those tools can reach — cloud IAM, customer data, secrets managers, internal services, actions taken on a user's behalf. This skill routes you to the right hunt-agent-* skill AND enforces the verification discipline that separates an impactful, genuine finding from a confident-wrong one. In real engagements a false "the copilot leaked customer PII" is worse than useless — it burns client trust and gets the whole report dismissed. The discipline is not optional.

---

## PART 0 — THE VERIFICATION LAW (applies to every skill, every finding)

Agents **generate** text; they don't **retrieve** state. That is why a verification step is mandatory — a fluent answer can be a hallucination that looks identical to a real leak. Before you claim ANYTHING:

1. **Self-description is untrusted.** The agent's account of its own tools/limits is generated and frequently false ("I pass your input verbatim," "I don't have access to that"). Verify by effect.
2. **Verify the channel discriminates.** Prove known-true vs known-false give different results before trusting an oracle; confirm your OOB listener receives a literal marker before trusting exfil.
3. **Marker-fired ≠ data-fired.** A control landing is not your data leaving. Unique, non-guessable marker per hypothesis.
4. **Reproduce ≥3×.** Non-determinism means one hit can be luck. Report hit-rate for probabilistic bugs.
5. **OOB-or-it-didn't-happen.** Exfil confirmed only when the listener receives your marker + real data.
6. **Refusal ≠ secure; compliance ≠ vuln; enumeration ≠ impact; "it parsed" ≠ RCE.** The finding is the state/data/action obtained, not what the model said.
7. **Actioned secret.** A leaked credential/secret/record is confirmed only when it authenticates, the record verifiably belongs to another tenant/user, or the OOB callback carries it.
8. **Minimum-necessary extraction.** Prove the missing control with 2–3 records; volume is client liability, not stronger evidence. Synthetic markers; don't persist customer data.

> Why these exist (field war-stories): trusting an agent's "I don't sanitize" claim (false); mistaking a literal OOB probe for the real payload firing; misreading a binary status oracle; planning a boolean-oracle extraction against a tool whose allowlist made it impossible. Every rule above is a mistake that cost hours.

---

## PART 0b — THE NEGATIVE-RESULT LAW (what must be true before you report "clean")

PART 0 stops you claiming a finding you cannot prove. This stops the opposite and more common
failure: **a probe that reports clean because it never looked.** "We tested it and found nothing"
is a claim to the client with the same evidentiary burden as a finding.

1. **A control must prove the probe could have fired** — plant a known-true case and see it
   detected in the same run.
2. **Denylist the read-only tools; never allowlist the dangerous ones** — an allowlist ignores
   every tool it has not heard of.
3. **Errors are their own verdict** — 5xx, timeout, empty audit, dead dependency = UNMEASURABLE,
   never "refused".
4. **Prove the plant persisted before reporting isolation** — no memory to cross means no result.
5. **Tokenise identifiers at ONE character** — ids are routinely a single digit.
6. **Word boundaries; normalise whitespace before subtracting** — substrings invent findings,
   verbatim matching against re-wrapped text deletes them.
7. **A fixed-size effect is not proof; a SCALING one is** — constant overhead is an extra model
   turn, not execution.
8. **Judge a tuning change by whether a GENUINE detection dropped**, not by the FP count.
9. **Do not inherit another tool's verdict** — benchmarks and scanners have their own bugs.

> Measured in this bundle: a similarity gate scored a real system-prompt leak at 0.03 and said
> no-fire; a curated tool list hid two attacker-booked reservations; a two-character token floor
> missed the forged-observation attack that leaked the flag; a whitespace mismatch erased all 14
> detections in a run; an HTTP 500 read as a refusal buried a confirmed auth bypass. Each was a
> probe calling a compromise clean.

---

## PART 1 — WHERE AGENTS LIVE (enterprise context)

| Deployment | Reached via | Auth model to probe | Crown jewel |
|---|---|---|---|
| Support/customer copilot | Web widget, Slack/Teams | per-user vs shared service account | cross-tenant customer PII |
| DevOps/SRE agent | Chatops, internal portal | service account (broad) | cloud IAM/metadata, prod shell |
| RAG knowledge assistant | Web, email/ticket ingest | per-user | cross-doc/tenant data, indirect injection |
| Coding/IDE agent | IDE, PR/CI bot | repo/CI token | source, secrets, CI execution |
| MCP / A2A tool server | Direct endpoint | often separate from web auth | protected resources, privileged tools |
| Autonomous workflow agent | API, schedule, webhook | delegated | on-behalf actions (payments, approvals) |

Two questions decide most findings: **per-user identity or a shared service account?** (shared → confused-deputy) and **multi-tenant?** (yes → cross-tenant access is the crown jewel).

---

## PART 2 — AGENT TAXONOMY → SKILL

| Agent Type / tool surface | Route to |
|---|---|
| Single-agent + tools | `hunt-agent-tool-injection`, `hunt-agent-blind-exfil` |
| Multi-agent / orchestrator / A2A protocol | `hunt-agent-multi-agent`, `hunt-agent-race-condition` |
| MCP-connected (probing an exposed server) | `hunt-agent-mcp-exposure` |
| MCP third-party/community servers, dynamic tools, no manifest pinning | `hunt-agent-mcp-supply-chain` (tool poisoning / rug-pull / shadowing) |
| RAG-augmented / doc-ingesting / vector store | `hunt-agent-rag` (poisoning, cross-tenant retrieval, embedding inversion), `hunt-agent-prompt-injection` (indirect) |
| Persistent memory / stored profile / writable knowledge | `hunt-agent-memory-poisoning` |
| Code execution (eval/exec) | `hunt-agent-tool-injection` (code path) |
| Data parser (YAML/JSON/XML/pickle) | `hunt-agent-deserialization` |
| Tool wraps a native/compiled binary or legacy service (banner, `%p` pointer, libc error, tight byte-cap, arch in a debug tool) | `hunt-agent-native-memory` (overflow / leaked-pointer / ret2shellcode) |
| Agent operates a browser/desktop by vision or DOM (AI browser, computer-use, RPA copilot) — reads a screen/page, clicks & navigates | `hunt-agent-browser-use` (DOM/OCR injection, adversarial pixels, screen TOCTOU, cross-origin ATO) |
| Coding/IDE/CLI agent that reads project config (CLAUDE.md/AGENTS.md/.cursorrules/settings.json/.mcp.json/hooks) or can write its own config | `hunt-agent-config-poisoning` (rules-file backdoor, YOLO self-toggle, MCP/hook write-to-execute) |
| Network/fetch/URL/webhook | `hunt-agent-tool-injection` (SSRF), `hunt-agent-blind-exfil` (OOB) |
| DB access | `hunt-agent-tool-injection` (SQL/NoSQL) |
| Crypto tools (encrypt/decrypt/token) | `hunt-agent-crypto` |
| Guess/PIN/token verify, no lockout | `hunt-agent-brute-force` |
| Output hidden / DLP-filtered | `hunt-agent-blind-exfil` |
| Ingests external content (docs/URLs/email/tickets/RAG) or acts via tools | `hunt-agent-prompt-injection` (direct/indirect/multimodal) |
| Output rendered as markdown/HTML in a client (web/Slack/Teams/email/IDE) | `hunt-agent-output-exfil` (zero-click / link / HTML) |
| Secret likely in context / need tool contract | `hunt-agent-prompt-extraction` |
| Role/persona gate (admin/owner/root) | `hunt-agent-auth-bypass` |
| Time/day/window gate | `hunt-agent-time-gate` |
| Human approval / confirm step before a consequential action | `hunt-agent-hitl-bypass` |
| Log/diagnostic/file tools | `hunt-agent-info-disclosure` |
| Safety classifier / refusal / moderation / DLP blocks the payload | `hunt-agent-guardrail-evasion` (amplifier — layer onto the sink skill) |
| Metered/paid, autonomous loops, fan-out, paid downstream tools, shared quota | `hunt-agent-resource-abuse` (denial-of-wallet / DoS) |

---

## PART 3 — THE 4-PHASE WORKFLOW
```
1. CHARACTERIZE ─▶ 2. INJECT/ACCESS ─▶ 3. EXFILTRATE/EXTRACT ─▶ 4. ESCALATE/CHAIN
```
### Phase 1 — CHARACTERIZE (never skip; where hours are saved)
- [ ] Enumerate every tool (per agent); note params + **output visibility** (full / status / timing / blind).
- [ ] **Trifecta check:** does this agent simultaneously have (a) access to private data, (b) exposure to untrusted content, and (c) an outbound/exfil channel? All three = prioritize target; any two = watch; one or none = low exfil risk.
- [ ] Identify the interpreter (`2+2`, `check <host>`, `key: value`, `{{7*7}}`, `SELECT 1`).
- [ ] **Map the allowlist/denylist** — probe commands one at a time; don't assume `cat`/`grep`/`id` exist.
- [ ] **Egress test** — can it reach your OOB listener? which protocol (DNS usually; HTTP/TCP often blocked)?
- [ ] **Oracle semantics** — what drives the status (last exit code? stdout match? reachability?).
- [ ] **Auth model + tenancy** — per-user vs service account; single vs multi-tenant.
- [ ] Extract the tool contract (`hunt-agent-prompt-extraction`) — the system prompt often states the injection point.
- [ ] Confirm **on the wire** (proxy), not just the chat UI (client filters, newline stripping).

### Phase 2 — INJECT / ACCESS
Separators (`;` `\n` `&&` `|` `$()`), then **resolve the newline mode** (Mode A shell-exec vs Mode B the-agent-splits-into-a-tool-call — decides whether `$()` fires; see `hunt-agent-tool-injection`). Or bypass the agent via MCP/A2A.

### Phase 3 — EXFILTRATE / EXTRACT
Pick the channel by what Phase 1 proved: OOB (usually the winner for blind) → boolean oracle (only if a comparator runs) → timing (last resort, statistics required). `hunt-agent-blind-exfil`.

### Phase 4 — ESCALATE / CHAIN
| You have | Escalate to | How |
|---|---|---|
| File read | Credential theft | `.env`, config, keys, **cloud metadata/IAM**, secrets manager |
| Command exec | Persistence / lateral | authorized_keys, cron, pivot to internal services / other agents |
| MCP/A2A resource access | Full data exfil | enumerate resources/tools, chain agents |
| Race condition | Financial/material loss | double-spend, limit bypass, on-behalf approval |
| Blind injection | Full extraction | OOB automation (min-necessary) |
| Single-agent RCE | Multi-agent / cross-tenant | use trust/shared state to reach privileged tools or other tenants |

---

## PART 4 — WHAT COUNTS
| Engagement | Finding | Rejected |
|---|---|---|
| AI-agent pentest | tool injection, verified data exfil, MCP/A2A exposure, race, deserialization, crypto, auth/time bypass — with verified impact | "LLM said something," prompt injection with no sink, hallucinated secret |
| Bug bounty (AI platform) | impact-demonstrated exploitation | bare prompt disclosure (unless a real secret) |
| Red team | full chain: access → exfil → persistence → lateral / cross-tenant | isolated findings, no chaining |
| Internal audit | control-mapped (below), minimum-necessary evidence | findings without mapping; over-collected customer data |

---

## PART 5 — STANDARDS MAPPING (right list — two different documents)
- **Model-level = OWASP LLM Top 10.** Cite 2025 IDs by default, 2026 equivalent in parens (a reviewer may be on either edition). Watch the renumber: Excessive Agency LLM06:2025 → LLM03:2026; System Prompt Leakage LLM07:2025 → renamed Hidden Context Exposure LLM08:2026; Improper Output Handling LLM05:2025 → LLM10:2026. (Never use the retired 2023 "Insecure Plugin Design.")
- **Agent-level = OWASP Agentic Apps.** Two real docs: **Top 10 for Agentic Applications 2026 (ASI01–ASI10**, publ. 2025-12-09) for the headline class, and **Agentic AI: Threats & Mitigations v1.1 (T1–T17**, Dec 2025) for the specific threat. Most tool findings = **ASI02 Tool Misuse** / **ASI03 Identity & Privilege Abuse** / **ASI06 Memory & Context Poisoning**.
- **MITRE ATLAS v5.6.0 + CWE** as applicable. Note **AML.T0053 = AI Agent Tool Invocation** (not "Plugin Compromise"). Full verified ID list: `RESEARCH-2026.md`.
- **Reproduce & anchor.** Where possible, reproduce on a public benchmark and cite the number — **AgentDojo** (629 security cases), **InjecAgent** (ReAct-GPT-4 vuln 24%), **ASB** (84.3% peak ASR), **PoisonedRAG** (5 texts → 90% for RAG). Tooling: garak, PyRIT, promptfoo, mcp-scan / MCPSafetyScanner. See `RESEARCH-2026.md` §3/§6.

---

## PART 6 — SKILL ROSTER (23)
`hunt-agent-prompt-injection` · `hunt-agent-output-exfil` · `hunt-agent-memory-poisoning` · `hunt-agent-rag` · `hunt-agent-guardrail-evasion` · `hunt-agent-resource-abuse` · `hunt-agent-tool-injection` · `hunt-agent-blind-exfil` · `hunt-agent-deserialization` · `hunt-agent-mcp-exposure` · `hunt-agent-mcp-supply-chain` · `hunt-agent-multi-agent` (incl. A2A) · `hunt-agent-prompt-extraction` · `hunt-agent-race-condition` · `hunt-agent-auth-bypass` · `hunt-agent-time-gate` · `hunt-agent-info-disclosure` · `hunt-agent-crypto` · `hunt-agent-brute-force` · `hunt-agent-hitl-bypass` · `hunt-agent-native-memory` · `hunt-agent-browser-use` · `hunt-agent-config-poisoning` · `redteam-mindset` (discipline). See `_CONTRACT.md` for the standard every skill must meet.

## PART 7 — PROBE INDEX
Every hunt-agent skill carries a self-contained `## Runnable Probe` (stdlib-only, copy-paste, ends with `# LETHAL WHEN:`). Grab the one for the surface you're on; each produces a discriminating oracle you then escalate to a real sink.

Status: **FIELD-FIRED** = validated on a live ARKX agent pod. **UNTESTED** = probe exists but hasn't been fired against a live agent (backed by public research/CVEs, pending field confirmation).

| Skill | Probe produces (the oracle) | Status |
|---|---|---|
| prompt-injection | canary page + OOB beacon → content-becomes-instructions (BANANA) + will-exfil | FIELD-FIRED |
| prompt-extraction | structural dump + run-twice reproducibility ratio → real leak vs confabulation | FIELD-FIRED |
| tool-injection | separator sweep: `sleep` timing delta + `nslookup` OOB → command exec | FIELD-FIRED |
| blind-exfil | OOB-DNS sink w/ literal-vs-substitution control → data in the DNS label | FIELD-FIRED |
| output-exfil | zero-click OOB listener + expired-allowlist-domain checker | UNTESTED |
| mcp-exposure | direct MCP client: initialize→list→read sensitive resource (bypass agent) | FIELD-FIRED |
| mcp-supply-chain | `tools/list` scan → hidden-Unicode + injection phrases in tool descriptions | UNTESTED |
| multi-agent | marker propagation A→B → confused-deputy action or self-replication | FIELD-FIRED |
| memory-poisoning | two-session marker → cross-session/user memory leak (MINJA shape) | UNTESTED |
| rag | poison-marker retrieval + cross-tenant filter IDOR | UNTESTED |
| guardrail-evasion | synthetic-token filter fingerprint → regex vs classifier + tag-smuggler | FIELD-FIRED |
| resource-abuse | amplification meter → one request → N billable calls (denial-of-wallet) | UNTESTED |
| native-memory | crash-offset binary-search + leaked-pointer regex | FIELD-FIRED |
| config-poisoning | craft hidden-Unicode rules file + repo scanner for invisible tags | UNTESTED |
| browser-use | 3-vector poisoned page (DOM/hidden/OCR) + OOB → cross-origin exfil | UNTESTED |
| auth-bypass | role claims + privilege-field bisection → names the effective field | FIELD-FIRED |
| deserialization | parser fingerprint + OOB-confirmed XXE | FIELD-FIRED |
| crypto | ECB repeated-block + padding-oracle detection | FIELD-FIRED |
| brute-force | throttle check + feedback/timing oracle | FIELD-FIRED |
| info-disclosure | traversal/encoding sweep → real secret-shaped content | FIELD-FIRED |
| race-condition | N concurrent identical requests → double-spend | FIELD-FIRED |
| time-gate | out-of-window + injected-time-claim → gate is prompt not server-clock | FIELD-FIRED |
| hitl-bypass | approval-summary vs actual-execution diff | UNTESTED |

Discipline: probes are single-target, marker-based, authorized-testing only. The probe gives you the oracle; PART 0 (Verification Law) + the skill's 8-point gate decide whether it's a finding.
