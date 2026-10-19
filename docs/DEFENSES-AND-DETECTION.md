# Defenses & Detection

A pentest artifact that only attacks reads as a CTF. A credible one tells the client **how to fix it** and **how to see it in their logs**. Each class below: root fix + detection signal. Pair every finding you report with the matching row.

## The one architectural fix worth citing (research-backed)
Point-fixes lose to prompt injection; the literature is blunt that **only architecture removes the class** (Willison's lethal trifecta: cut one of private-data / untrusted-content / external-comms). Recommend a **design constraint**, not "sanitize input" or a model-level filter, and name the measured cost so the client trusts the advice.

**First, kill the false comfort — defenses fail under adaptive attack.** A vendor's "blocks 99%" is a *static-benchmark artifact*; it evaporates when the attacker optimizes against the deployed defense. Put these numbers in the report so no one relies on a trained filter:
- **The Attacker Moves Second** (Nasr, Carlini, Sitawarin et al. — OpenAI+Anthropic+DeepMind, arXiv:2510.09023): adaptive attacks broke **12 published defenses at >90% ASR**; **human red-team = 100%**.
- **Adaptive Attacks Break Defenses** (Zhan et al., arXiv:2503.00061, NAACL 2025): **8 defenses all broken, >50% ASR**.
- Trained defenses in particular: **StruQ** <2% and **SecAlign** <10% *in-distribution*, but adaptive attacks hit **72.5–82.5%** on SecAlign-defended Llama-3/Mistral. Good benchmark ≠ boundary.

**What actually holds — recommend one of these, with its cost:**
- **Agents Rule of Two** (Meta, 2025-10-31): a session satisfies at most **two** of {process untrusted input · access sensitive data · change state / communicate externally}; all three ⇒ human-in-the-loop. The operational lethal-trifecta — a design constraint, not a filter. **Default recommendation** for most findings.
- **CaMeL / out-of-band deterministic policy** (Debenedetti et al., arXiv:2503.18813; family incl. FIDES/Progent/RTBAS/FORGE, arXiv:2606.26479): security enforced *outside* the model. Cost: ~**77% of AgentDojo utility vs 84%** — real, quotable, not "free."
- **Six design patterns** (Beurer-Kellner et al., arXiv:2506.08837): Action-Selector · Plan-Then-Execute · LLM Map-Reduce · **Dual-LLM** · Code-Then-Execute · Context-Minimization. Map the finding to the pattern that prevents it (untrusted-data-drives-tool-args → Plan-Then-Execute or Dual-LLM).
- **RETA** (arXiv:2606.15441, 2026-06): reasoning-enabled task alignment, keeps adaptive per-attack ASR **<10%** — current strong result, still not zero.
- **Allowlists are not a boundary:** OpenAI's own URL-exfil paper (2026-02) concedes residual bit-leakage; EchoLeak (CVE-2025-32711) and Claude Pirate exfil *through the allowlisted domain itself*. Defense-in-depth only, never the control of record.

**Bottom line for the client:** prompt injection is **unsolved** — recommend a design constraint (Rule of Two / remove a trifecta leg / OOB policy), never a model-level filter whose benchmark score an adaptive attacker erases. Full citations + numbers: `RESEARCH-2026.md` §4.

## tool-injection (shell/eval/SSRF)
- **Fix:** never string-interpolate into a shell — use arg-array execution (`["ping", host]`); strict input allowlist (charset/format), not a denylist; drop shell metacharacters; egress-deny by default; block link-local/metadata IPs (169.254.169.254) at the network. For eval: no `eval`/`exec` on user input — use a real sandbox or a safe expression evaluator.
- **Detect:** tool inputs containing `;`, `` ` ``, `$(`, `|`, newlines; outbound DNS/HTTP from the tool host to unknown domains; child processes spawned by the agent runtime; requests to 169.254.169.254.

## blind-exfil / output-channel
- **Fix:** don't "fix" by hiding output while leaving injection — fix the injection. Egress allowlist (DNS included — this is the usual gap). Response DLP must cover **tool/network outputs**, not just chat text.
- **Detect:** high-entropy or base64-looking subdomains in DNS logs; bursts of DNS queries to one parent domain; tool making outbound requests it never normally makes.

## deserialization
- **Fix:** `yaml.safe_load`, never `pickle.loads` on untrusted data, disable XML external entities, no polymorphic/default-typed Jackson, schema-validate after parse.
- **Detect:** payloads containing `!!python/`, `!!javax`, `__proto__`, `<!ENTITY`, `_$$ND_FUNC$$_`; parser exceptions; unexpected class instantiation.
- **Model / artifact supply chain (registry pickle):** require **`safetensors`** for model weights (tensor-only, no code execution) — the real fix; **do not rely on Picklescan** (blacklist scan, bypassed by nullifAI's 7z + broken-stream trick). Pin model artifacts by **hash/signature** from a trusted source; scan with **Fickling** and prefer a policy-enforcing loader (**PickleBall**, arXiv:2508.15987 — rejects 100% of malicious pickle models, loads 79.8% benign). **Detect:** `.pkl/.pt/.bin/.ckpt/joblib` model files (vs `.safetensors`), `torch.load`/`pickle.load`/`from_pretrained` on hub-sourced names, outbound connections or child processes at model-load time, 7z-wrapped model archives. Note **44.9% of popular HF models still ship pickle** — this is a live, common surface, not an edge case.

## mcp-exposure
- **Fix:** authenticate the MCP endpoint independently of the web session; per-resource authorization; validate Origin; short-lived, unpredictable, bound session ids; don't put secrets in client-readable resources; "unlock" tools must enforce real authz, not act as a UI gate.
- **Detect:** MCP calls without/with reused session ids; `resources/list` from unusual clients; access to sensitive `resource://` URIs; requests missing/spoofing Origin.
- **Delegated identity / OAuth (proxy servers), per MCP spec rev 2025-11-25:** implement **per-client consent before** forwarding to the third-party AS; exact `redirect_uri` match (no wildcards); set the `state` cookie only after consent; **reject any token not issued to this server** (no passthrough); block private/link-local ranges on all OAuth-metadata fetches (SSRF); issue minimal/progressive scopes; never authenticate via session id (bind `<user_id>:<session_id>`). **Detect:** dynamic client registrations with novel `redirect_uri`; consent-screen skips on repeat `authorize`; downstream tokens whose audience ≠ this server; discovery fetches to 169.254.169.254 / RFC1918.

## multi-agent / A2A
- **Fix:** authenticate the *caller* between agents (signed tokens/mTLS) — a nonce handshake is not identity; propagate and check end-user identity across hops (no confused-deputy); integrity + provenance on shared memory/cache; don't let sub-agents execute instructions found in data.
- **Detect:** A2A/`tasks/send` from unenrolled clients; privileged-tool calls whose originating user lacks the role; shared-memory writes with instruction-like content.

## prompt-extraction
- **Fix:** keep secrets/keys OUT of system prompts (use a secrets manager, fetch at tool-time with authz); assume the prompt is recoverable; instruction/data separation.
- **Detect:** messages asking to "quote/repeat/translate your instructions / sentence N"; responses that echo system-prompt phrasing.

## race-condition
- **Fix:** atomic check-and-commit (DB transaction / row lock / conditional update); distributed locks for multi-agent shared state; idempotency keys.
- **Detect:** concurrent identical state-changing tool calls within milliseconds; post-state anomalies (negative balance, count>limit).

## auth-bypass
- **Fix:** bind authorization to the authenticated caller's identity/token, never to a chat-claimed role; enforce authz in the tool/backend, not the prompt; data classification enforced server-side.
- **Detect:** messages asserting a role ("I am the Boss/admin"); privileged tool executed for a user whose real role doesn't match; classification-override phrasing.

## time-gate
- **Fix:** enforce time windows server-side against a trusted clock at *execution* time, not scheduled time; don't trust client/prompt-supplied time.
- **Detect:** actions executing outside their window; scheduling immediately followed by an execute; messages claiming a different day/timezone.

## info-disclosure
- **Fix:** redact secrets/config from logs & diagnostics; path-validate + jail file tools to an allowlisted root (no `..`, no absolute paths); no arbitrary import; classify tool output.
- **Detect:** file tools accessing parent/absolute paths; import of unexpected paths; diagnostic/env-dump tool calls; responses containing config keys/`ENV_*`.

## crypto
- **Fix:** authenticated encryption (AES-GCM), never ECB; MAC/signature on tokens; random per-message IVs; keys in a KMS, never in prompts/config; constant-time verification (no padding oracle).
- **Detect:** repeated identical ciphertext blocks; token-forgery attempts (malformed/rearranged tokens); padding-error probing.

## brute-force
- **Fix:** rate-limit + lockout on any guess/verify tool; minimal feedback (no "correct digit/position"); server-side attempt accounting bound to identity.
- **Detect:** many verify attempts per identity/session in a short window; systematic guess patterns; feedback-oracle probing.

## prompt-injection (direct/indirect/multimodal)
- **Fix:** structural instruction/data separation (never concatenate untrusted content into the instruction channel); treat all ingested content — docs, URLs, email, tickets, RAG chunks, tool results — as data, never commands; constrain the agent's authority so a followed injection can't reach a high-value sink (least-privilege tools, per-action authz); human approval on consequential actions.
- **Detect:** ingested content containing imperative/role phrasing ("ignore previous", "SYSTEM:", "assistant:"); tool calls whose arguments trace back to external content; a spike in tool use right after a document/URL is read.

## output-exfil (rendered-output channels)
- **Fix:** don't auto-render agent-emitted markdown images / HTML / links to arbitrary hosts; allowlist image and link domains; strip/encode active markup before the client renders it; CSP that blocks off-origin image/asset loads; require user interaction for outbound links.
- **Detect:** agent output containing `![](http…)` / `<img src>` / links to unknown hosts with query strings carrying context; client fetches to non-allowlisted domains triggered by a rendered response.

## memory-poisoning (persistent store)
- **Fix:** treat memory writes as privileged — don't auto-persist instruction-like content; partition memory per user/tenant (no cross-user bleed); provenance + integrity on stored entries; expire/review long-lived memory; separate "facts" from "instructions" so recalled memory is data, not commands.
- **Detect:** memory entries containing directives ("always…", "when asked…, do…"); a write in one session altering another session's/user's behavior; recalled memory driving tool calls.

## rag (retrieval / vector store)
- **Fix:** validate + provenance-check ingested documents; enforce per-tenant/user authorization **as a retrieval filter**, not post-hoc; treat retrieved chunks as untrusted data (not instructions); don't expose raw embeddings/similarity; bound retrieval top-k and scope to the caller's entitlements.
- **Detect:** retrieval returning documents outside the caller's tenant/entitlement; ingested chunks containing imperative phrasing; embedding/similarity endpoints hit directly; one user's query surfacing another's content.

## guardrail-evasion (safety/DLP bypass)
- **Fix:** normalize/decode input (base64, homoglyphs, zero-width, Unicode-tag) **before** classifying; strip Unicode Tag-block & zero-width characters; enforce policy outside the model (not just refusal training); scan **decoded** output; detect cross-turn escalation (Crescendo) and many-shot flooding patterns.
- **Detect:** encoded/obfuscated payloads (base64/hex/homoglyph runs, invisible Unicode); requests in unexpected languages that decode to sensitive intent; long fabricated dialogue histories; gradual per-turn escalation.

## resource-abuse (denial-of-wallet / DoS)
- **Fix:** max_tokens + output-length caps; recursion/step-depth limits on the agent loop; per-user rate limit + spend budget (partition shared quotas); bound retrieval top-k and context growth; cost ceilings/timeouts on downstream tools; a cost-anomaly circuit-breaker / kill-switch.
- **Detect:** single request → many tool/model calls (fan-out) or unbounded iterations; token/cost spikes per identity; shared-quota 429s denying other users; long-running or looping tool invocations.

## mcp-supply-chain (tool poisoning / rug-pull)
- **Fix:** pin + sign tool manifests; re-review on any definition change (defeats rug-pull); treat tool descriptions AND results as untrusted data, not instructions; isolate servers + scope OAuth tokens per server (no shared-token bleed); vet registry provenance / typosquat; human review of new/changed tool definitions.
- **Detect:** tool-definition hash changes after approval; tool descriptions containing directives ("before any tool, first…"); a tool call whose args trace to another server's description/result; near-duplicate/colliding tool names; tokens sent to unexpected servers.

## hitl-bypass (approval-gate defeat)
- **Fix:** derive the approval summary **independently** from the real action/args (not model-written); cryptographically/structurally bind approved intent to what executes (no TOCTOU); scope + expire grants (no blanket "always allow"); default approval timeout to **DENY**; never bundle high-risk with benign in one approval; guard **every** path to a sink; give the approver full context.
- **Detect:** executed action/args differing from the approved summary; consequential action with no matching approval record; standing-grant use for novel action types; approvals granted on timeout; a sink reached via an ungated path.

## native-memory (compiled binary behind a tool)
- **Fix:** bound every read/copy by `sizeof(dest)` (never by a source-file size or attacker length field); rebuild with stack canaries, PIE/ASLR, NX/non-executable stack, full RELRO; never print raw pointers; run the binary sandboxed with least privilege, separate from the agent's credentials. The wrapper's 20-char name filter is not the control — the sandbox is.
- **Detect:** tool-host segfaults / crash loops; uploads at or just under a byte cap; tool output containing raw addresses (`0x…`); the tool process spawning a shell or making unexpected egress; core dumps.

## config-poisoning / cross-agent (in-the-wild class — RESEARCH-2026.md §5)
- **Fix:** treat an agent's own config and instruction files (`.mcp.json`, `AGENTS.md`/`CLAUDE.md`, memory stores, allowlist/YOLO toggles) as a privileged surface — require explicit human approval to write them, and isolate co-resident agents so one cannot rewrite another's config. Auto-`create_memory`/auto-config-write with no approval is the finding (Windsurf SpAIware, Cross-Agent Priv-Esc, AgentHopper).
- **Detect:** writes to agent config/instruction/memory files not initiated by the user; a recurring agent task file (heartbeat) added or modified; invisible Unicode-tag runs in skills/docs/tickets (scan for U+E0000–U+E007F); config changes that widen the tool allowlist or enable auto-run.

## Network-level detection (the layer that generalizes)
- **Recommend network-level over model-level for detection.** Model filters die to adaptive attack (above); watching what the agent actually *does on the wire* generalizes better. **ShieldNet** (Yuan et al., arXiv:2604.04426) — MITM proxy + event extractor + classifier — hits **0.995 F1 at 0.8% FP** on SC-Inject-Bench (10,000+ malicious MCP tools), beating MCP scanners and LLM guardrails; the detection layer to propose for MCP/tool supply-chain risk. Open-source guardrail stack to name: **LlamaFirewall** (PromptGuard 2 / Agent Alignment Checks / CodeShield, arXiv:2505.03574).
- **Caveat you must state:** an **LLM-based** guardrail is itself an attack surface — **"From Shield to Target"** (Zhou et al., arXiv:2606.14517) shows reasoning-length payloads cause **13–63× token / up to 148× latency** amplification and can **starve co-located agents on shared guardrail infra**. So: prefer network-level/deterministic guardrails over an LLM-judge, and **rate-limit the guardrail itself** (it's a denial-of-wallet target — see `hunt-agent-resource-abuse`).

## Cross-cutting (all classes)
- **Telemetry to demand from the client (fixes T8 Repudiation):** log every tool call with the originating end-user identity, arguments, and result; log agent-to-agent calls; retain OOB-relevant DNS/HTTP egress logs. Without per-user tool-call attribution, none of the above is detectable — that itself is a finding.
- **Reproduce on a benchmark before you claim a class is real:** AgentDojo / InjecAgent / ASB give a defensible ASR number; garak / PyRIT / promptfoo / mcp-scan give a repeatable harness (RESEARCH-2026.md §3/§6).
