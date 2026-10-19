# References

The public research this library builds on. This replaces "sources: one CTF" with a defensible evidence base — the difference between a research artifact and a vibe.

> Verification status: framework IDs and the technique/real-world corpus were re-fetched from primary sources on **2026-09-10** — the full evidence layer, with per-source dates and corrections, is in **`RESEARCH-2026.md`** (read that first; it supersedes any stale ID here).

## Frameworks & standards *(re-verified 2026-09-10 — see RESEARCH-2026.md §1 for full IDs)*
- **OWASP Top 10 for LLM Applications — 2025** — https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/ ; per-risk pages under https://genai.owasp.org/llmrisk/
- **OWASP Top 10 for LLM Applications — 2026** (renumbered: Excessive Agency→LLM03, Unbounded Consumption→LLM06, System Prompt Leakage renamed **LLM08 Hidden Context Exposure**, Improper Output Handling→LLM10) — https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ *(resource page: publ. 2026-08-03)*
- **OWASP Top 10 for Agentic Applications 2026 — ASI01–ASI10** (publ. **2025-12-09**; ASI01 Agent Goal Hijack · ASI02 Tool Misuse · ASI03 Identity & Privilege Abuse · ASI04 Agentic Supply Chain · ASI05 Unexpected Code Execution · ASI06 Memory & Context Poisoning · ASI07 Insecure Inter-Agent Comms · ASI08 Cascading Failures · ASI09 Human-Agent Trust Exploitation · ASI10 Rogue Agents) — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- **OWASP Agentic AI: Threats and Mitigations — v1.1 (Dec 2025), T1–T17** (v1.0 was T1–T15; added **T16 Insecure Inter-Agent Protocol Abuse**, **T17 Supply Chain Compromise**) — https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
- **Cloud Security Alliance — MAESTRO** (Ken Huang, 2025-02-06; L1 Foundation Models · L2 Data Operations · L3 Agent Frameworks · L4 Deployment & Infrastructure · L5 Evaluation & Observability · L6 Security & Compliance · L7 Agent Ecosystem) — https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro
- **MITRE ATLAS v5.6.0** (data through 2026-04-30) — https://atlas.mitre.org ; machine-readable https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml . Key IDs: **AML.T0053 AI Agent Tool Invocation** (NOT "Plugin Compromise"), T0051 Prompt Injection (.000/.001/.002), T0054 Jailbreak, T0056 Extract System Prompt, T0057 Data Leakage, T0070 RAG Poisoning, T0034.002 Agentic Resource Consumption, T0061 Prompt Self-Replication, T0050 Command & Scripting Interpreter.
- **NIST AI RMF (AI 100-1, Jan 2023)** and **NIST AI 600-1 GenAI Profile (Jul 2024)** — https://www.nist.gov/itl/ai-risk-management-framework *(verified 2026-09-04)*
- **Google SAIF** (Secure AI Framework) — https://safety.google/intl/en/safety/saif/ ; saif.google *(verified 2026-09-04)*
- **PortSwigger — Web LLM attacks** (indirect injection, insecure output rendering → XSS, excessive agency) — https://portswigger.net/web-security/llm-attacks *(verified 2026-09-04)*
- **Model Context Protocol** spec **rev 2025-11-25** — Security Best Practices enumerate: Confused Deputy · Token Passthrough · SSRF via OAuth metadata discovery · Session Hijacking · Local MCP Server Compromise · OAuth Authorization URL Validation (javascript:→XSS→RCE) · stdio Transport Proxy escalation · Scope Minimization — https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices
- **A2A protocol v1.0** — enterprise/security model (auth via HTTP transport, Agent Card `security` field, per-skill authz) — https://a2a-protocol.org/latest/topics/enterprise-ready/
- **OpenAI — Preventing URL-Based Data Exfiltration in LM Agents** (2026-02; allowlist = indexed+user-typed URLs, concedes residual bit-leakage) — https://cdn.openai.com/pdf/dd8e7875-e606-42b4-80a1-f824e4e11cf4/prevent-url-data-exfil.pdf

## Technique corpus (attribute techniques to these)
- **Simon Willison** — prompt injection, indirect injection, the **"lethal trifecta"** (private data + untrusted content + external comms) — https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/ *(verified 2026-09-04)*
- **Johann Rehberger (Embrace The Red)** — **spAIware** persistent-memory data exfiltration (ChatGPT macOS) — https://embracethered.com/blog/posts/2024/chatgpt-macos-app-persistent-data-exfiltration/ *(verified 2026-09-04)*; also AI kill-chain, markdown-image zero-click exfil, ASCII/Unicode-tag smuggling — embracethered.com *(root for those)*
- **Invariant Labs** — MCP **Tool Poisoning Attack** (direct poisoning, shadowing, sleeper rug-pull) — https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks ; PoC repo https://github.com/invariantlabs-ai/mcp-injection-experiments *(verified 2026-09-04)*
- **Russinovich, Salem, Eldan (Microsoft)** — **Crescendo** multi-turn jailbreak — arXiv:2404.01833 ; USENIX Security '25 *(verified 2026-09-04)*
- **Zou, Wang, Carlini, Nasr, Kolter, Fredrikson** — **GCG** universal & transferable adversarial suffixes — arXiv:2307.15043 ; https://github.com/llm-attacks/llm-attacks *(verified 2026-09-04)*
- **Anthropic** — **Many-shot Jailbreaking** (long-context, hundreds of demos) — anthropic.com research (Many_Shot_Jailbreaking, 2024-04) *(verified 2026-09-04)*
- **Yong, Menghini, Bach** — **Low-Resource Languages Jailbreak GPT-4** — arXiv:2310.02446 *(verified 2026-09-04)*
- **Greshake, Abdelnabi, Mishra, Endres, Holz, Fritz** — "Not what you've signed up for: …Indirect Prompt Injection" — arXiv:2302.12173 *(verified 2026-09-10)*

### Benchmarks & agent-attack papers *(verified 2026-09-10; see RESEARCH-2026.md §3)*
- **AgentDojo** (Debenedetti et al., NeurIPS 2024 D&B) — 97 tasks / 629 security cases — arXiv:2406.13352 ; github.com/ethz-spylab/agentdojo
- **InjecAgent** (Zhan et al., ACL 2024 findings) — 1,054 cases; ReAct-GPT-4 vuln 24% — arXiv:2403.02691
- **Agent Security Bench (ASB)** (Zhang et al., ICLR 2025) — peak 84.30% ASR — arXiv:2410.02644
- **AgentHarm** (Andriushchenko et al., ICLR 2025) — 110 malicious tasks, 11 categories — arXiv:2410.09024
- **PoisonedRAG** (Zou, Geng, Wang, Jia) — 5 poison texts → 90% ASR — arXiv:2402.07867
- **AgentPoison** (Zhaorun Chen et al., NeurIPS 2024) — trigger backdoor, >80% ASR at <0.1% poison rate — arXiv:2407.12784
- **Dissecting Adversarial Robustness of Multimodal LM Agents** (Wu et al., ICLR) — <5% pixels → 67% ASR on VisualWebArena — arXiv:2406.12814
- **ToolLeak / Red-Teaming Coding Agents** (Yuchong Xie et al., 2025-09) — prompt-leak 19/25 pairs → RCE on every tested coding agent (Cursor/Claude Code/Copilot/Windsurf/Cline/Trae) — arXiv:2509.05755
- **RedTeamCUA** (Zeyi Liao et al., ICLR 2026) — RTC-Bench 864 web-OS examples; Claude 3.7 Sonnet CUA 42.9% ASR, Operator 7.6% — arXiv:2505.21936
- **OS-Harm** (Thomas Kuntz et al.) — 150 computer-use tasks on OSWorld (misuse/PI/misbehavior) — arXiv:2506.14866
- **WASP** (Ivan Evtimov et al.) — web-UI-agent PI benchmark, up to 86% partial ASR — arXiv:2504.18575
- **LivePI** (Lei Zhao et al., 2026-05) — realistic indirect-PI benchmark, 10.7–29.6% ASR — arXiv:2605.17986
- **A Survey on Agentic Security: Applications, Threats and Defenses** (Asif Shahriar et al., 2025-10) — 260+ papers, umbrella taxonomy — arXiv:2510.06445
- **MCPTox** (Zhiqiang Wang et al.) — tool poisoning on 45 real MCP servers/353 tools; 72.8% ASR; capable models more susceptible — arXiv:2508.14925
- **MCPSecBench** (Yixuan Yang et al.) — 17 attacks × 4 MCP surfaces; protections <30% effective — arXiv:2508.13220
- **MCP-SafetyBench** (Xuanjun Zong et al.) — 20 MCP attack types, 5 domains; host-side 81.94% ASR, Identity Injection 100%/13 models — arXiv:2512.15163
- **GCG — Universal & Transferable Adversarial Attacks on Aligned LMs** (Zou et al.) — arXiv:2307.15043
- **Crescendo — "Great, Now Write an Article About That"** (Russinovich et al., USENIX Security 2025) — arXiv:2404.01833
- **MCP Safety Audit** (Radosevich & Halloran) — MCPSafetyScanner — arXiv:2504.03767

### Defenses (with measured cost) *(verified 2026-09-10; DEFENSES-AND-DETECTION.md maps to these)*
- **CaMeL — "Defeating Prompt Injections by Design"** (Debenedetti et al.) — control/data-flow separation + capabilities; ~77% AgentDojo utility WITH provable security vs 84% without — arXiv:2503.18813
- **Design Patterns for Securing LLM Agents against Prompt Injections** (Beurer-Kellner et al.) — six patterns: Action-Selector, Plan-Then-Execute, LLM Map-Reduce, Dual-LLM, Code-Then-Execute, Context-Minimization — arXiv:2506.08837
- **The Attacker Moves Second** (Nasr, Carlini, Sitawarin et al., OpenAI+Anthropic+DeepMind, 2025-10) — adaptive attacks break **12 defenses at >90% ASR**, human red-team 100% — arXiv:2510.09023
- **Adaptive Attacks Break Defenses Against Indirect PI on LLM Agents** (Zhan et al., NAACL 2025) — 8 defenses all broken, >50% ASR — arXiv:2503.00061
- **StruQ** (structured queries, <2% vs optimization-free) — arXiv:2402.06363 · **SecAlign** (Sizhe Chen et al., preference-opt, <10% in-distribution, 72.5–82.5% adaptive) — arXiv:2410.05451
- **Agents Rule of Two** (Meta, 2025-10-31) — ≤2 of {untrusted input · sensitive access · state-change/external-comms} per session, else HITL — the design constraint to recommend
- **Adaptive Evaluation of Out-of-Band Defenses** (CaMeL/FIDES/Progent/RTBAS/FORGE family) — arXiv:2606.26479 · **RETA** (reasoning-enabled task alignment, <10% adaptive ASR) — arXiv:2606.15441
- **ShieldNet** (Zhuowen Yuan et al., 2026-04) — network-level guardrail (MITM proxy + classifier); SC-Inject-Bench 10,000+ malicious MCP tools; **0.995 F1 @ 0.8% FP**, beats MCP scanners/LLM guardrails — arXiv:2604.04426
- **LlamaFirewall** (Sahana Chennabasappa et al., 2025-05) — open-source guardrail: PromptGuard 2 + Agent Alignment Checks + CodeShield — arXiv:2505.03574
- **From Shield to Target: DoS on LLM Agent Guardrails** (Yuguang Zhou et al., 2026-06) — reasoning-length payloads, 13–63× token / 148× latency, starves shared guardrail infra — arXiv:2606.14517

### Real-world corpus (Embrace The Red / Rehberger — "Month of AI Bugs" 2025 + 2026) *(verified 2026-09-10)*
- EchoLeak (M365 Copilot, **CVE-2025-32711, CVSS 9.3**, "LLM Scope Violation", Aim Security) · **ForcedLeak (Salesforce Agentforce, CVSS 9.4, Noma Security — $5 expired CSP-allowlisted domain)** · **Rules File Backdoor (Pillar — hidden-Unicode config)** · **config-injection RCE CVEs: CVE-2025-53773 (Copilot YOLO), CVE-2025-54135 CurXecute (Cursor 8.6), CVE-2025-59536 (Claude Code 8.7)** · ChatGPT Deep Research connector spill (ShadowLeak class) · Claude Pirate (Files-API exfil past allowlist) · Cross-Agent Privilege Escalation · AgentHopper (AI virus, self-replication) · Agent Commander (promptware C2, HEARTBEAT.md persistence) · Computer-Use TOCTOU · Comet ATO + screenshot/OCR injection (Brave) · Scary Agent Skills (Unicode-tag) · DiLLMa ANSI→DNS exfil · Windsurf SpAIware. Indexes: https://embracethered.com/blog/ · https://brave.com/blog/ · https://noma.security/blog/

## Tooling (reference, don't reinvent)
- **NVIDIA garak** — LLM vulnerability scanner — github.com/NVIDIA/garak
- **Microsoft PyRIT** — risk-identification / red-team automation — github.com/Azure/PyRIT
- **promptfoo** — eval & red-team harness — promptfoo.dev
- **Rebuff** — prompt-injection detection — github.com/protectai/rebuff
- **mcp-scan / Invariant** — MCP server scanning — github.com/invariantlabs-ai/mcp-scan
- **MCPSafetyScanner** — first agentic MCP-server auditor — github.com/johnhalloran321/mcpSafetyScanner
- **AgentDojo** — reproduce tool/injection findings on 629 security cases — github.com/ethz-spylab/agentdojo
- **ASCII Smuggler** (Embrace The Red) — reveal invisible Unicode-tag instructions
- **Fickling** (Trail of Bits) — inspect/detect/create malicious pickle & ML-model files (`fickling --check model.pkl`) — github.com/trailofbits/fickling
- **PickleBall** — policy-enforcing safe pickle loader for ML models (arXiv:2508.15987)
- **ShieldNet** — network-level agent guardrail (MITM proxy + classifier, 0.995 F1) — arXiv:2604.04426
- **LlamaFirewall** — open-source agent guardrail (PromptGuard 2 / Alignment Checks / CodeShield) — arXiv:2505.03574
- **Burp Collaborator / interactsh** — OOB DNS/HTTP validation (the exfil-proof channel used throughout `blind-exfil`)

## Per-skill primary attribution (fill deep links on verification)
| Skill | Primary source(s) |
|---|---|
| prompt-injection | OWASP LLM01; Willison (lethal trifecta); Greshake (indirect, arXiv:2302.12173); benchmarks AgentDojo/InjecAgent/WASP(2504.18575)/LivePI(2605.17986); PortSwigger |
| output-exfil | Rehberger (markdown-image zero-click, ASCII smuggling); OWASP LLM05/LLM02 |
| memory-poisoning | Rehberger spAIware (embracethered 2024, persistent-memory exfil); OWASP Agentic T1 |
| rag | OWASP LLM08 (Vector & Embedding Weaknesses) + LLM04; PoisonedRAG (arXiv:2402.07867, 5 texts→90%); AgentPoison (arXiv:2407.12784, >80% at <0.1%); ATLAS T0070 RAG Poisoning / T0066 |
| guardrail-evasion | Zou GCG (arXiv:2307.15043); Anthropic many-shot; Russinovich Crescendo (arXiv:2404.01833); Yong low-resource (arXiv:2310.02446); Rehberger (Unicode-tag) |
| resource-abuse | OWASP LLM10 (Unbounded Consumption); OWASP Agentic T4 (CWE-400/770) |
| mcp-supply-chain | Invariant Labs TPA (rug-pull/shadowing); MCPTox (2508.14925, 45 servers/353 tools, 72.8% ASR); MCPSecBench (2508.13220, protections <30%); OWASP LLM03; MCP spec (CWE-829/494) |
| hitl-bypass | OWASP LLM06; OWASP Agentic T10/T15 (CWE-863/807) |
| tool-injection | OWASP LLM05/LLM01; PortSwigger LLM attacks; general OS-command-injection (CWE-78) |
| blind-exfil | Rehberger (tool-invocation exfil); Burp Collaborator methodology; classic blind-injection theory |
| deserialization | OWASP LLM05; classic deserialization/XXE research (CWE-502/611); model supply chain: nullifAI (ReversingLabs 2025-01, HF pickle RCE), Sleepy Pickle (Trail of Bits 2024-06, Fickling), PickleBall (2508.15987); OWASP LLM03/04, ASI04, ATLAS T0010.003/T0011.000/T0058 |
| mcp-exposure | MCP Security Best Practices (spec rev 2025-11-25): confused deputy, token passthrough, OAuth-metadata SSRF, session hijacking, scope minimization; MCP-SafetyBench (2512.15163, host-side 81.94%, Identity Injection 100%/13 models); CWE-441/918/863; CSA/Invariant MCP guidance |
| multi-agent (A2A) | OWASP Agentic T12/T13; A2A protocol spec; CSA MAESTRO L7 |
| prompt-extraction | OWASP LLM07; Willison; Rehberger; ToolLeak (2509.05755, prompt-leak via tool-arg retrieval, 19/25 pairs) |
| race-condition | classic TOCTOU (CWE-367); OWASP Agentic unsafe-concurrency |
| auth-bypass | OWASP LLM01/LLM06; Willison (instruction vs data) |
| time-gate | TOCTOU (CWE-367); OWASP Agentic T4 |
| info-disclosure | OWASP LLM02/LLM07; Rehberger (data-exfil chains) |
| crypto | classic ECB/padding-oracle research (CWE-327/347) |
| brute-force | CWE-307/799; OWASP Agentic T4 |
| native-memory | ARKX (field, defcon L1); CWE-121/122/787/733; ATLAS T0053→T0050; MCP spec local-server compromise |
| browser-use | Brave (Comet ATO 2025-08, screenshot/OCR 2025-10); Wu et al. adversarial pixels (2406.12814); benchmarks RedTeamCUA(2505.21936, ICLR26)/OS-Harm(2506.14866)/WASP(2504.18575); Rehberger computer-use TOCTOU (2026-06); OWASP LLM01/ASI01/ASI03/ASI09 |
| config-poisoning | Pillar Rules File Backdoor (Cursor/Copilot 2025); ToolLeak (2509.05755, RCE on every tested coding agent); CVE-2025-53773 (Copilot YOLO→RCE), CVE-2025-54135/54136 (Cursor CurXecute/MCPoison), CVE-2025-59536/CVE-2026-21852 (Claude Code, Check Point); Rehberger cross-agent + AgentHopper; OWASP LLM01/06/03, ASI04, ATLAS T0061 |

## Citation rule for the skills
Each skill's `sources:` and `validated_against:` must distinguish **[CONFIRMED]** (validated in an agent context — cite where) from **[REFERENCE]** (from the corpus above — cite the author/framework). Never blur the two.
