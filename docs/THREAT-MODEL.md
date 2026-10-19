# AI Agent Red-Team — Threat Model & Taxonomy

Purpose: give this skill library a defensible, standards-mapped foundation so findings map to recognised frameworks and reviewers can see *why* each skill exists. This is the taxonomy the `hunt-agent-*` skills implement; `COVERAGE-MATRIX.md` shows which skill covers which control.

> Provenance note: framework names, control IDs, and threat lists below are transcribed from memory (offline). **Verify exact IDs, versions, and links against the primary sources in `REFERENCES.md` before publishing** — treat any specific numbering as "to-confirm," not gospel. Framework IDs and the attack/defense corpus were re-verified against primary sources — see **`RESEARCH-2026.md`**.
>
> Umbrella survey (the map of this whole space): **"A Survey on Agentic Security: Applications, Threats and Defenses"** (Asif Shahriar et al., arXiv:2510.06445, 2025-10) — taxonomizes **260+ papers** and concludes agentic systems are "structurally fragile by default," requiring defenses across the whole lifecycle rather than single points. Read it as the index to the taxonomy this file implements.

---

## 1. The agent attack model (why agents differ from web apps)

A web app **retrieves** state deterministically; an agent **generates** behaviour non-deterministically and **acts through tools**. Four consequences drive everything:

1. **The tool interface is the attack surface** — not URLs/forms. The LLM is middleware; the tools reach the real assets (cloud IAM, data, secrets, actions).
2. **Output is generated, not retrieved** — a fluent answer can be a hallucination indistinguishable from a real leak → verification is mandatory (see the gate in `_CONTRACT.md`).
3. **Trust boundaries are blurry** — untrusted input (docs, tickets, web pages, other agents) flows into the same context as instructions → indirect prompt injection.
4. **Agency = blast radius** — an agent with tools + autonomy can take irreversible real-world actions on a user's behalf.

**The "lethal trifecta" lens (Willison):** an agent is exploitable-for-exfil when it simultaneously has (a) access to private data, (b) exposure to untrusted content, and (c) an outbound/exfil channel. Flag any target that combines all three.

---

## 2. The agent kill chain (phases → skills)

```
Recon/            Injection/         Execution/         Exfiltration/      Escalation/
Characterize  ──▶ Access        ──▶  Action        ──▶  Extraction    ──▶  Chaining
```
- **Recon/Characterize** — enumerate tools, visibility, allowlist, egress, auth model, tenancy → `ai-agent-methodology`, `hunt-agent-prompt-extraction`.
- **Injection/Access** — reach an interpreter or bypass the agent (MCP/A2A) → `tool-injection`, `deserialization`, `mcp-exposure`, `multi-agent`, `auth-bypass`, `time-gate`, `crypto`, `brute-force`.
- **Execution/Action** — run code / take a tool action.
- **Exfiltration/Extraction** — get data out (blind/OOB, rendered-output channels, DLP bypass) → `blind-exfil`, `info-disclosure`.
- **Escalation/Chaining** — cloud creds, lateral, cross-tenant, cross-agent → `multi-agent`, chaining in `methodology` Phase 4.

---

## 3. Framework mapping (the standards this library speaks to)

### 3a. OWASP Top 10 for LLM Applications (2025) — model-level
LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM03 Supply Chain · LLM04 Data & Model Poisoning · LLM05 Improper Output Handling · LLM06 Excessive Agency · LLM07 System Prompt Leakage · LLM08 Vector & Embedding Weaknesses · LLM09 Misinformation · LLM10 Unbounded Consumption.

### 3b. OWASP Agentic Security Initiative — Agentic AI Threats & Mitigations (2025/26) — agent-level (the primary home for most of this library)
T1 Memory Poisoning · T2 Tool Misuse · T3 Privilege Compromise · T4 Resource Overload · T5 Cascading Hallucination · T6 Intent Breaking & Goal Manipulation · T7 Misaligned & Deceptive Behaviour · T8 Repudiation & Untraceability · T9 Identity Spoofing & Impersonation · T10 Overwhelming Human-in-the-Loop · T11 Unexpected RCE & Code Attacks · T12 Agent Communication Poisoning · T13 Rogue Agents in Multi-Agent Systems · T14 Human Attacks on Multi-Agent Systems · T15 Human Manipulation. *(verify T-numbering vs current doc)*

### 3c. CSA MAESTRO — 7-layer agentic threat-modeling reference
L1 Foundation Models · L2 Data Operations · L3 Agent Frameworks · L4 Deployment & Infrastructure · L5 Evaluation & Observability · L6 Security & Compliance (cross-cutting) · L7 Agent Ecosystem. Use MAESTRO to locate *where in the stack* a finding lives (e.g. MCP exposure = L3/L7; SSRF-to-IMDS = L4; memory poisoning = L2).

### 3d. MITRE ATLAS — adversarial-ML tactics/techniques
Reconnaissance → Resource Development → Initial Access → AI Model Access → Execution → Persistence → Exfiltration → Impact. Relevant techniques (ATLAS **v5.6.0**, IDs verified 2026-09-10): **AML.T0051 LLM Prompt Injection** (.000 Direct / .001 Indirect / .002 Triggered), **AML.T0053 AI Agent Tool Invocation** (NOT "LLM Plugin Compromise" — that name is wrong), **AML.T0056 Extract LLM System Prompt** + **AML.T0069 Discover LLM System Information**, **AML.T0054 LLM Jailbreak**, **AML.T0057 LLM Data Leakage**, **AML.T0070 RAG Poisoning**, **AML.T0034.002 Agentic Resource Consumption**, **AML.T0061 LLM Prompt Self-Replication** (worms), **AML.T0050 Command and Scripting Interpreter**. See `RESEARCH-2026.md` §1 for the full verified list.

### 3e. Governance references
NIST AI RMF + NIST AI 600-1 (Generative AI Profile) · Google SAIF · EU AI Act (high-risk-system obligations) — used for the audit/compliance framing, not for offense.

---

## 4. Coverage stance (honest)
This library was **field-validated on a 19-level agent CTF** and cross-checked against the frameworks above. Some agent-level threats are **not yet covered** and are tracked as planned skills (see `COVERAGE-MATRIX.md`): prompt-injection (dedicated), output-rendering exfil (zero-click/markdown-image/XSS), memory poisoning, RAG/embedding, resource overload / denial-of-wallet, MCP supply-chain (tool rug-pull), guardrail evasion, human-in-the-loop bypass. Gaps are stated, not hidden — that is the difference between a research artifact and a vibe.

---

## 5. Engagement discipline (applies to every phase)
Authorization scope up front; **data-minimization** (prove the missing control with 2–3 records, never exfiltrate the store); synthetic/recoverable markers; no persistence of customer data; extreme care with destructive/irreversible tool actions (agents can send/delete/transact). See `_CONTRACT.md` gate points 7–8 and `REFERENCES.md` for RoE sources.
