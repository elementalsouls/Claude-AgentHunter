# DVMCP harness — 10 deliberately vulnerable MCP servers

External lab: [harishsg993010/damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server).
Used to test the MCP and tool-injection skills against targets somebody else designed — the point
being that they can surprise us, which our own lab cannot.

```sh
python3 -m venv venv && ./venv/bin/pip install "mcp[cli]<2" uvicorn starlette httpx
git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server dvmcp
# challenges hardcode ports 8001-8010; run_dvmcp.py remaps without editing the repo
./venv/bin/python run_dvmcp.py dvmcp/challenges/easy/challenge1/server.py 8801
./venv/bin/python audit_final.py     # passive sweep, all 10
./venv/bin/python audit_dvmcp4.py    # active arms (C8 RCE, C3 traversal, C6 enumeration)
```

Challenge 5 needs `sed 's/, listed=False//g'` — it uses a kwarg this SDK version dropped.

## Result: 10/10 detected (9 passive + C8 active)

| ch | class | detected by |
|---|---|---|
| 1 | Basic Prompt Injection | secret resource `internal://credentials` |
| 2 | Tool Poisoning | poisoned descriptions ×2 |
| 3 | Excessive Permission Scope | secret resource + `/etc/passwd` via `read_file` (controls passed) |
| 4 | Rug Pull | **behaviour diff** — metadata diff saw nothing |
| 5 | Tool Shadowing | poisoned description + `system://secrets` |
| 6 | Indirect Prompt Injection | production keys in `internal_memo.txt` after name enumeration |
| 7 | Token Theft | secrets in `check_email` output |
| 8 | Malicious Code Execution | **differential-sleep oracle**, scaling +6.0s, `uid` returned |
| 9 | Remote Access Control | behaviour diff on `traceroute` |
| 10 | Multi-Vector | poisoned descriptions ×2 + secret resource |

## What the passes taught (each arm exists because a pass missed something)

1. **v1 description scan** — caught 3/10. Tool poisoning and shadowing only.
2. **v2 read resource CONTENT** — listing URIs is not auditing them; four credential stores appeared.
3. **v3 behaviour diff** — the rug pull mutates `__doc__` at runtime, but FastMCP cached the
   registration-time description, so `tools/list` was byte-identical across the flip. Metadata
   diffing is not enough; compare outputs across identical calls.
4. **v4 argument enumeration** — a document tool called with `{"document_name": "test"}` returns
   nothing. Enumerate real names from the listing resource, then replay them.
5. **widened secret pattern** — `internal_memo.txt` held `api_prod_…` / `pg_live_…` keys that a
   `key\s*[:=]` / `sk-` pattern skipped. Widened to vendor-prefixed tokens; still does not flag the
   benign weather and announcement text on the same servers (control).

## The one that matters most

C8 gave the **differential-sleep oracle its first true positive**: `+3.01s` at sleep 3 and `+9.01s`
at sleep 9, scaling `+6.01s`, corroborated by `id` returning a real uid. Against ARKX the same
oracle correctly refused a `+3.0s` fixed delay whose scaling was only `+1.2s`. An oracle that only
ever says "no" is not conservative, it is untested — this is the run that showed it discriminates.
