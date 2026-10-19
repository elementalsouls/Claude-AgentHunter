# Coverage Matrix — skills × standards

Which skill covers which control, and where the gaps are. IDs per `THREAT-MODEL.md` (verify against `REFERENCES.md`). Status: ✅ shipped · 🟡 partial · 🔲 planned (Phase B).

## Shipped skills → controls

Agentic column uses the **Threats & Mitigations v1.1 (T1–T17)** IDs; the parallel **ASI01–ASI10 Top-10** class is named in each skill body. ATLAS IDs verified against **v5.6.0** (2026-09-10) — see `RESEARCH-2026.md`.

| Skill | OWASP LLM 2025 (2026) | OWASP Agentic (T1–T17) | MAESTRO layer | MITRE ATLAS v5.6.0 | Confirmed |
|---|---|---|---|---|---|
| `hunt-agent-prompt-injection` | **LLM01** | **T6, T2**, T1 | L1, L3 | AML.T0051 | 2 |
| `hunt-agent-output-exfil` | **LLM05**, LLM02 | exfiltration, T15 | L7, L5 | exfil (CWE-79) | lab |
| `hunt-agent-memory-poisoning` | **LLM04**, LLM01/LLM08 | **T1**, T6 | L2, L3 | poisoning/persistence | lab |
| `hunt-agent-rag` | **LLM08**, LLM04, LLM01/LLM02 | T1, T2 | L2, L1 | poisoning/repo-access | 0 (ref) |
| `hunt-agent-guardrail-evasion` | **LLM01** (inherits unlocked) | **T6**, T1/T2 | L1, L6 | AML.T0054, T0068 | 2 |
| `hunt-agent-resource-abuse` | **LLM10** | **T4** | L4, L7 | denial-of-ML-service | 0 (ref) |
| `hunt-agent-mcp-supply-chain` | **LLM03**, LLM01/LLM06 | **T2, T3**, T15 | L3, L7 | supply-chain-compromise | lab |
| `hunt-agent-hitl-bypass` | **LLM06**, LLM01 | **T10, T15** | L6, L7 | oversight-gap | 0 (ref) |
| `hunt-agent-tool-injection` | LLM05 (LLM01 if prompt-enabled) | T2 Tool Misuse, T11 RCE | L3, L4 | AML.T0053 | 5 |
| `hunt-agent-blind-exfil` | LLM05 | T2, exfiltration | L3, L5 | AML.T0053, T0057, T0025 | 3 |
| `hunt-agent-deserialization` | LLM05 | T2, T11 | L3 | AML.T0053 | 1 |
| `hunt-agent-mcp-exposure` | LLM06, LLM02 | T3, T9, T16 (ASI02/03) | L3, L7 | AML.T0053, T0055 | 1 |
| `hunt-agent-multi-agent` (incl. A2A) | LLM01, LLM06 | T3, T9, T12, T13, T1(mem) | L3, L7 | AML.T0051/53 | 1 |
| `hunt-agent-prompt-extraction` | LLM07 (→LLM08:2026), LLM02 | T6 (recon) | L1, L5 | AML.T0056, T0069 | 3 |
| `hunt-agent-race-condition` | LLM06 (→LLM03:2026) | T2, unsafe concurrency | L3, L4 | CWE-367 (no ATLAS TOCTOU) | 1 |
| `hunt-agent-auth-bypass` | LLM01, LLM06 | T3, T6 | L3, L6 | AML.T0051 | 3 |
| `hunt-agent-time-gate` | LLM06 (→LLM03:2026) | T4-adjacent, TOCTOU | L3, L4 | CWE-367 (no ATLAS TOCTOU) | 1 |
| `hunt-agent-info-disclosure` | LLM02, LLM07 | T2, disclosure | L2, L5 | AML.T0056 | 5 |
| `hunt-agent-crypto` | LLM05 (insecure tool design) | T2, T9 | L3 | — | 1 |
| `hunt-agent-brute-force` | LLM06 | T4 (resource), auth | L3, L6 | — | 1 |
| `hunt-agent-native-memory` | LLM06, LLM05, LLM03(3P) | **T2, T11**, T17 (ASI05/ASI04) | L3, L4 | AML.T0053 → T0050 | 1 |
| `hunt-agent-browser-use` | **LLM01**, LLM02, LLM06 | **T6, T2, T15** (ASI01/03/09) | L1, L7 | AML.T0051.001, T0068 | 0 (ref) |
| `hunt-agent-config-poisoning` | **LLM01, LLM06, LLM03** | **T17, T2, T11** (ASI04/02/05) | L3, L4, L7 | AML.T0051.001, T0053→T0050, T0061 | 0 (ref) |

## Former Phase B skills (now all shipped)

| Planned skill | Fills | OWASP LLM 2025 | OWASP Agentic | Why it matters |
|---|---|---|---|---|
| ✅ `hunt-agent-prompt-injection` | **SHIPPED** — direct/indirect/multimodal + multi-turn jailbreaks | **LLM01** | **T6, T2, T1** | the #1 agent risk (was scattered; now a dedicated skill) |
| ✅ `hunt-agent-output-exfil` | **SHIPPED** — markdown-image zero-click, HTML/XSS, link injection, CSP bypass | LLM05, LLM02 | exfiltration, T15 | primary real-world data-theft path (lethal trifecta) |
| ✅ `hunt-agent-memory-poisoning` | **SHIPPED** — persistent cross-session/user memory, spAIware | LLM04 | **T1** | ASI top threat |
| ✅ `hunt-agent-rag` | **SHIPPED** — corpus poisoning, cross-tenant retrieval (IDOR), embedding inversion, citation spoof | **LLM08**, LLM04 | T1, T2 | RAG is the most common enterprise pattern |
| ✅ `hunt-agent-resource-abuse` | **SHIPPED** — denial-of-wallet, loop/fan-out amplification, unbounded retrieval, shared-quota DoS | **LLM10** | **T4** | real cost/availability impact |
| ✅ `hunt-agent-mcp-supply-chain` | **SHIPPED** — tool-description injection, rug-pull, cross-server shadowing, line-jumping, token theft | **LLM03** | T2, T3 | emerging MCP ecosystem risk |
| ✅ `hunt-agent-guardrail-evasion` | **SHIPPED** — encoding, Unicode-tag smuggling, low-resource-lang, GCG suffix, payload-split, many-shot, Crescendo | LLM01 | T6 | cross-cutting; makes other skills land |
| ✅ `hunt-agent-hitl-bypass` | **SHIPPED** — summary/action mismatch, fatigue/batching, standing-grant abuse, timeout-approve, unguarded sibling path | LLM06 | **T10, T15** | approval steps are the last line of defense |

## Standards gaps still open after Phase B
- **LLM09 Misinformation / T5 Cascading Hallucination / T7 Deceptive behaviour** — largely *evaluation/safety* problems, weakly "pentestable"; document as out-of-scope-for-offense with a pointer to eval tooling (PyRIT/garak/promptfoo) rather than faking a skill.
- **T8 Repudiation & Untraceability** — a detection/telemetry finding; belongs in `DEFENSES-AND-DETECTION.md`, not an attack skill.

## How to read this
A finding should cite **one model-level (LLM) ID + one agent-level (ASI) ID + a MAESTRO layer**, plus MITRE ATLAS/CWE where applicable. Single-ID findings usually mean you haven't located the real impact yet.
