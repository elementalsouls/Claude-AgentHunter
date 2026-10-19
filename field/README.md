# Field harnesses — probes run against a live target

Engagement-specific. This is deliberately **not** `lab/`: the lab reproduces the *class*
of vulnerability deterministically with no model in the loop, so `[CONFIRMED]` means
re-runnable. A field harness is the other half — it runs the technique against a real
agent, with real non-determinism, and reports what actually happened there.

It is also **not** a skill Runnable Probe. Those are self-contained by contract (§8,
no shared import, generic vocabulary). These share a gate module and name a specific
target, which is exactly why they live outside the skill bodies.

Use a harness to produce `validated_against` evidence. Use the lab to prove the class.

| Harness | Target | Skills exercised |
|---|---|---|
| `injecagent/` | InjecAgent — indirect injection planted in tool output (external benchmark) | prompt-injection, output-exfil — **arm D provenance 7/7, 0 FP**; control-token check fired 0/120, proving the two halves cover different classes |
| `dvla/` | Damn Vulnerable LLM Agent — LangChain ReAct banking agent (external lab) | prompt-injection, auth-bypass, info-disclosure — flag captured via scratchpad forgery; **arm D** built here, 3/3 forgeries, 0 FP |
| `agentdojo/` | AgentDojo slack/workspace/banking/travel, two local models via `model_proxy.py` | output-exfil, multi-agent, hitl-bypass — TP=29/FN=0 (75 runs, gpt-oss) plus travel TP=7/FN=0 and a qwen3-coder cross-check; exposed a tool-allowlist blind spot in our own scorer |
| `dvmcp/` | 10 deliberately vulnerable MCP servers (external lab) | mcp-supply-chain, mcp-exposure, tool-injection, info-disclosure — **10/10 challenges detected** |
| `arkx/` | ARKX CTF pods (`/level/N/chat`, Cognito) | prompt-extraction, tool-injection, auth-bypass (harness) · guardrail-evasion, memory-poisoning, info-disclosure (adapted runs) |

## The rule these harnesses exist to enforce

A probe that cannot distinguish "the technique worked" from "the measurement was noise"
will report whichever the first run happened to produce. Every verdict here carries a
control arm, and the vocabulary keeps the difference visible:

- `FIRED` — it worked, **and a control shows the technique is what did it**
- `no-fire` — a real negative: the control proves the probe could have seen a hit
- `INVALID` — the "success" also happens without the attack; nothing was demonstrated
- `ERROR` — could not measure. **Never** counted as a negative.

Credentials come from the environment. Nothing here ships a working login.
