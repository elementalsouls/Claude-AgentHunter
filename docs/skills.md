# Skills catalog

23 agent-pentest skills. `field-validated` = a CONFIRMED technique proven against a live or lab agent; `reference` = cross-domain, validate per target.

| skill | status | focus |
|---|---|---|
| `hunt-agent-auth-bypass` | field-validated | Authorization bypass in AI-agent tools — role/persona claims, unverifiable named-credentia |
| `hunt-agent-blind-exfil` | field-validated | Extract data from AI-agent tools that execute but hide output — status-only, exit-code-onl |
| `hunt-agent-browser-use` | reference | Attacks specific to computer-use and browser agents — agents that see a screen/DOM and act |
| `hunt-agent-brute-force` | field-validated | Brute-force and rate-limiting weaknesses in AI-agent tools — PIN/token/password guessing w |
| `hunt-agent-config-poisoning` | field-validated | The agent's OWN configuration, instruction, and settings files as an attack surface — CLAU |
| `hunt-agent-crypto` | field-validated | Cryptographic weaknesses in AI-agent tools that encrypt/decrypt/sign or mint tokens — ECB  |
| `hunt-agent-deserialization` | field-validated | Unsafe deserialization in AI-agent tools that parse structured data — YAML, pickle, JSON,  |
| `hunt-agent-guardrail-evasion` | field-validated | Cross-cutting techniques for getting a payload past input/output guardrails — safety class |
| `hunt-agent-hitl-bypass` | field-validated | Defeating the human-in-the-loop approval gate — the last line of defense before a conseque |
| `hunt-agent-info-disclosure` | field-validated | Information disclosure in AI-agent tools — log/diagnostic leakage, environment dumps via m |
| `hunt-agent-mcp-exposure` | field-validated | MCP (Model Context Protocol) exposure in AI agents: direct resource access, tool enumerati |
| `hunt-agent-mcp-supply-chain` | field-validated | Trust/supply-chain attacks on the MCP tool ecosystem an agent connects to — tool-descripti |
| `hunt-agent-memory-poisoning` | field-validated | Persistent poisoning of an AI agent's long-term memory / stored profile / writable knowled |
| `hunt-agent-multi-agent` | field-validated | Cross-agent trust, privilege, and shared-state abuse in multi-agent systems, including A2A |
| `hunt-agent-native-memory` | field-validated | Memory-safety exploitation of the NATIVE program behind an agent tool — stack/heap overflo |
| `hunt-agent-output-exfil` | field-validated | Client-side data exfiltration through AI-agent OUTPUT rendered in a UI — zero-click markdo |
| `hunt-agent-prompt-extraction` | field-validated | Extract an AI agent's system prompt, tool contract, hidden instructions, and embedded secr |
| `hunt-agent-prompt-injection` | field-validated | Prompt injection in AI agents — direct (chat box is the trust boundary), indirect (payload |
| `hunt-agent-race-condition` | field-validated | TOCTOU / race conditions in AI-agent tools: double-spend, limit bypass, coupon reuse, priv |
| `hunt-agent-rag` | field-validated | Attacks on retrieval-augmented agents and their vector stores — knowledge/corpus poisoning |
| `hunt-agent-resource-abuse` | field-validated | Unbounded-consumption / denial-of-wallet attacks on agents — forcing expensive token gener |
| `hunt-agent-time-gate` | field-validated | Temporal-constraint bypass in AI-agent tools — future-dating, weekend/maintenance-window e |
| `hunt-agent-tool-injection` | field-validated | Command/code injection in AI-agent tools — shell, Python/JS eval, SQL, SSRF via fetch tool |
