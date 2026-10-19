---
name: report-agent
description: Write a submission-ready agent-pentest finding after it passes /validate-agent. Scores by the SINK reached (tool action / data / cross-tenant effect), not by what the model said. Usage: /report-agent
---
Write the finding only once it has cleared `/validate-agent`. Structure:

1. **Title** — `<sink reached> via <vector> in <agent/tool>` (e.g. "Cross-tenant record read via ReAct scratchpad forgery → SQL tool").
2. **Severity** — by the sink, not the model's compliance. Injection alone is Informational; score the tool action, data exfiltration, or cross-user/tenant effect it reaches.
3. **Reproduction** — the Runnable Probe, the planted CONTROL, and the hit-rate (≥3 runs for probabilistic bugs).
4. **Proof** — the state/data/action obtained (tool arg, state change, OOB callback), never the agent's words. Minimum-necessary extraction: 2–3 synthetic markers, no customer data.
5. **Impact + remediation** — what an attacker gains; the smallest fix (provenance check / allowlist / human approval on the sink).

Keep it class-based and anonymized — no real target identifiers.
