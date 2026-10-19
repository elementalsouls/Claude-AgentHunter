# Security & authorized use

Claude-AgentHunter runs **active probes** — it sends live payloads to the target agent and executes
intentionally-vulnerable code in `lab/`. Use it only against agents you own or are explicitly,
in-writing authorized to assess.

**Before any probe:** confirm scope, rules of engagement (permitted techniques, rate limits,
testing window), and that production user data / live financial flows are either off-limits or
covered by the authorization. The skills' Runnable Probes assume this is settled.

**Do not** point it at third-party agents, shared MCP servers you don't control, or hosted
assistants without authorization — a prompt-injection probe against someone else's agent is an
attack, not a test.

Findings handling follows the two gates: report the state/data/action obtained, use synthetic
markers, extract the minimum necessary (2-3 records), never persist another party's data.

Report issues in the toolkit itself via GitHub issues; do not include real target data or secrets.
