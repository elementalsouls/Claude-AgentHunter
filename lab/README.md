# Phase C — Validation Lab

Makes `[CONFIRMED]` mean **re-runnable**, not "the model said so". Each exploit
either passes its verification gate (exit 0) or fails — deterministically,
every run.

## Design (why there's no LLM here)

The vulnerabilities this library reports live in the **tool/sink layer**, not
in the model. So the lab reproduces the *sink behaviour directly* — a small
deterministic HTTP "agent" whose tools are vulnerable exactly the way the real
targets were. No model, no API key, no flakiness. The exploit and its gate are
the unit of truth.

This lab reproduces the **class** of vulnerability, not any specific engagement
or CTF. The secret in `secret.txt` is a synthetic lab marker.

## What's covered

14 exploit gates. The seven below the original four were added when an audit found those classes had no runnable exercise anywhere in the bundle — only prose.

### Increment 1

| Exploit | Class | Gate proven |
|---|---|---|
| `exploits/exploit_tool_injection.py` | tool-injection | `;`-filter **newline bypass** + `$()` expansion in **Mode A** (shell); the same payload is **inert in Mode B** (arg-split, `shell=False`) — the library's central distinction, shown empirically |
| `exploits/exploit_blind_exfil.py` | blind-exfil | secret leaves via an **out-of-band** callback against a **blind** target — "OOB-or-it-didn't-happen" |
| `exploits/exploit_info_disclosure.py` | info-disclosure | **path traversal** in a `read_log` tool (no jail): reads the lab secret out of the log root and escapes to `/etc/passwd` — the finding is the **data**, escape **verified** |
| `exploits/exploit_race_condition.py` | race-condition | non-atomic check→act on a single-use voucher: 20 concurrent redemptions all pass the check, confirmed by **end state** (balance + redemption count), not by counting cheerful replies |
| `exploits/exploit_time_gate.py` | time-gate | window adjudicated from a **client-supplied clock** and a client-settable maintenance flag; the target replies identically whether it ran or refused, so the gate scores only the **effect log**, with a negative control proving the window exists |
| `exploits/exploit_hitl_bypass.py` | hitl-bypass | the approval summary is derived and lossy (`$10`) while execution replays the **raw** request (`$10000`); asserts the audit trail is populated first, so an empty audit is ERROR rather than a fabricated mismatch |
| `exploits/exploit_brute_force.py` | brute-force | no lockout (25 guesses answered) plus a prefix-timing oracle **controlled against a known-wrong prefix** (0.025s vs 0.000s); PIN recovered in 40 probes and **actioned** |
| `exploits/exploit_crypto.py` | crypto | ECB cut-and-paste: baseline token is `role=user`, a spliced block yields a token the server accepts as `role=admin` |
| `exploits/exploit_deserialization.py` | deserialization | `pickle.loads` on caller bytes; benign control round-trips, payload proven by an **on-disk side effect** rather than a returned string |
| `exploits/exploit_config_poisoning.py` | config-poisoning | Unicode Tag characters flip `require_approval` True->False while the visible note reads innocuous; visible-only control changes nothing |
| `exploits/exploit_native_memory.py` | native-memory | reproducible 65-byte boundary + `0x7ffd3ab41c90` disclosed in the fault; re-tests a short input afterwards so a dead host reads UNMEASURABLE, not clean |
| `exploits/exploit_rag.py` | rag | tenant argument accepted and ignored; own-tenant control passes first, then acme's query returns GLOBEX's `INITECH-7742` |
| `exploits/exploit_resource_abuse.py` | resource-abuse | caller-controlled multiplier with no ceiling; 1x/1000x/100000x measured against baseline — the gate asserts **scaling**, since a cap would flatten the second reading |
| `mcp/mcp_target.py` | mcp-supply-chain | a **real** MCP server (official SDK) with 3 benign + 2 poisoned tool descriptions: decode-then-scan catches 2/2 with 0/3 false positives, raw-regex scraping catches 0/2 — see `mcp/README.md` |
| `exploits/exploit_prompt_extraction.py` | prompt-extraction | direct ask **refused** (refusal≠secure), bypass phrasing leaks the system-prompt secret, and the leaked key **authenticates to `/admin`** — **actioned-secret**, not bare disclosure |

Components:
- `target/vuln_agent.py` — the vulnerable agent. `/mode_a` interpolates input
  into a shell (with a naive `;` first-line filter); `/mode_b` splits on
  newlines into arg-array calls. Both are **blind** (status only).
- `target/oob_listener.py` — the exfil-proof channel (stands in for Burp
  Collaborator / interactsh). `GET /__hits` returns recorded callbacks.
- `run_lab.py` — starts both, runs every exploit, exits non-zero on any gate
  failure. This is the check.

## Run

```bash
# Local (needs python3, curl, ping):
python3 run_lab.py

# Isolated (recommended before adding sharper payloads):
docker compose up --build
```

Ports default to 18080 (target) / 18081 (listener) to dodge a local
intercepting proxy on 8080; the exploits also bypass `HTTP_PROXY`. Override with
`TARGET_PORT` / `LISTENER_PORT` / `TARGET_URL` / `LISTENER_URL` / `LISTENER_ADDR`.

## Extending

One exploit script per `[CONFIRMED]` class, each exiting 0 on a proven gate.
Add the script to `EXPLOITS` in `run_lab.py`. Keep payloads benign; run in
Docker for anything that isn't. Next candidates (all CONFIRMED in the matrix):
race-condition, crypto (ECB cut-and-paste), brute-force.
