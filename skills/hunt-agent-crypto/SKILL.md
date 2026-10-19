---
name: hunt-agent-crypto
description: "Cryptographic weaknesses in AI-agent tools that encrypt/decrypt/sign or mint tokens — ECB cut-and-paste and byte-at-a-time, padding oracles, missing MAC, hardcoded keys/predictable IVs. Use when an agent exposes crypto operations as tools."
sources: arkx_ctf(field-validated), owasp_llm_top10_2025, owasp_agentic_asi_2026, mitre_atlas
report_count: 1
validated_against: "ECB cut-and-paste token forgery CONFIRMED re-runnably in the validation lab (`lab/exploits/exploit_crypto.py`: baseline token role=user, spliced token accepted as admin). AES-ECB cut-and-paste to forge an admin token from a known format (ARKX The Keymaker)"
---

# Hunt Agent Crypto Weaknesses

Agents sometimes expose crypto as tools — encrypt, decrypt, sign, verify, mint tokens. Weak algorithms (ECB), missing authentication (no MAC), predictable keys/IVs, or a decrypt oracle turn the crypto tool into an auth-bypass / secret-extraction primitive. In enterprises this is session/API-token minting and document encryption behind a copilot.

## Where This Lives / Attack Surface Signals
- Tools: encrypt, decrypt, create_token, sign, verify, hash, generate_key.
- Agent mentions a mode (ECB/CBC/CTR/GCM) or "block size"/"padding".
- Token format documented in the system prompt / a `*_info` tool.
- Tool prepends/appends user input to a secret before encrypting.
- Encrypt-only or decrypt-only availability → an oracle.

## Crown Jewel Targets
Forged auth/session tokens → account/admin takeover; byte-at-a-time recovery of an appended secret; padding-oracle decryption of protected ciphertext.

## Characterize First
1. **Algorithm details** — "what cipher, mode, block size, padding?"
2. **Token/ciphertext format** — structure and where user input sits.
3. **Block behaviour** — send 0/1/15/16/17 bytes; count output blocks (find the 16-byte AES boundary).
4. **Oracle direction** — can you encrypt? decrypt? verify? Each enables different attacks.

## Technique 1 — ECB cut-and-paste (known format) [CONFIRMED]
ECB encrypts each block independently → rearrange ciphertext blocks.
```
Format: role=guest&user=<input>   (prefix = one 16-byte block)
1. Encrypt input crafted so "role=admin&user=" forms its own block
2. Keep the "role=admin&user=" ciphertext block + padding block; drop the "role=guest" block
3. Submit the rearranged blocks → decrypts to role=admin → access granted
```
`Field example:` forged an admin token this way without knowing the key.

## Technique 2 — ECB byte-at-a-time (input prepended to secret) [REFERENCE]
Control input length so one unknown secret byte fills a block; brute that byte by comparing blocks; repeat.

## Technique 3 — Padding oracle [REFERENCE]
If decrypt distinguishes "padding error" vs "invalid": manipulate padding to decrypt the last block byte-by-byte.

## Technique 4 — Hardcoded key / predictable IV [REFERENCE]
Ask for key/IV/config; test for reused IVs (CBC) or a static key in the prompt.

## Verification & False-Positive Gate
1. **The forged token/decrypted value must WORK** — submit it, authenticate with it, or verify it decrypts to the target. A plausible-looking token that's rejected is not a finding.
2. **Reproduce ≥3×** — deterministic crypto should reproduce exactly; if it doesn't, you've mis-modelled the scheme.
3. **Confirm the mode** — the ECB attacks require ECB (or an ECB-like independent-block behaviour); prove it via the block-boundary test, don't assume.
4. **Self-description untrusted** — the agent's stated "AES-256-GCM" may be wrong; verify by block behaviour.
5. **Impact required; min-necessary** — forge one admin token to prove it; don't harvest every user's.

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
ECB mode (independent blocks → cut-and-paste / byte-at-a-time); no MAC (malleable ciphertext); documented/known format; hardcoded prefix; PKCS#7 padding oracle; static key / predictable IV.

## Impact & Severity
- **CRITICAL:** forge admin/session tokens → authentication bypass; decrypt protected secrets.
- **HIGH:** ECB oracle → full appended-secret recovery.
- **MEDIUM:** disclosure of crypto parameters only.

## Mapping
- OWASP LLM Top 10 (2025): **LLM05 Improper Output Handling** / insecure tool design (NOT the retired 2023 "LLM07 Insecure Plugin Design"). Agentic ASI (2026): insecure tool implementation. CWE-327 (broken crypto / ECB), CWE-329 (predictable IV), CWE-347 (no MAC).

`Field example:` reproduced deterministically in `lab/` — an ECB-mode session token whose plaintext the caller partly controls. Control: an unmodified token comes back **role=user**, so the forgery has something to be measured against. Splicing an attacker-supplied block over the role block produced a token the server accepted as **role=admin**. The finding is the accepted privilege claim, not the detection of block repetition. Gate: `python3 lab/run_lab.py`.

## Runnable Probe [self-contained]
```python
#!/usr/bin/env python3
# Detect ECB (identical plaintext blocks -> identical ciphertext blocks) and padding-oracle behaviour
# on a token/encrypt tool. ECB + attacker-controlled plaintext = cut-and-paste token forgery.
# deps: stdlib only.
import json, re, urllib.request
ENC = "https://target/agent/encrypt"       # returns hex/base64 ciphertext for supplied plaintext
DEC = "https://target/agent/decrypt"        # returns distinct error on bad padding (oracle)
COOKIE = "session=REPLACE"
def call(url, obj):
    r = urllib.request.Request(url, data=json.dumps(obj).encode(),
        headers={"Cookie": COOKIE, "Content-Type": "application/json"}, method="POST")
    return urllib.request.urlopen(r, timeout=30).read().decode("utf-8", "replace")

ct = re.sub(r"[^0-9a-fA-F]", "", call(ENC, {"plaintext": "A"*48}))     # 3 identical 16-byte blocks
blocks = [ct[i:i+32] for i in range(0, len(ct), 32)]                   # 32 hex = 16 bytes
print("[ECB]", "DETECTED — repeated blocks -> cut-and-paste forgery" if len(blocks) != len(set(blocks))
      else "not ECB (blocks differ)")
r_ok  = call(DEC, {"token": ct})
r_bad = call(DEC, {"token": ct[:-2] + ("00" if ct[-2:] != "00" else "01")})   # corrupt last byte
print("[padding-oracle]", "LIKELY — distinct error on bad padding" if r_ok != r_bad else "no obvious oracle")
# LETHAL WHEN: you forge a token that AUTHENTICATES / elevates (ECB block cut-and-paste, or padding-
# oracle decrypt/encrypt) — proven by using the forged token, not by the mode detection alone.
```

## Related Skills
`hunt-agent-brute-force` · `hunt-agent-auth-bypass` · `hunt-agent-info-disclosure` · `ai-agent-methodology` · `redteam-mindset`
