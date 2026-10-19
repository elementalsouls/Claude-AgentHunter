"""DVMCP final sweep — every arm the earlier passes taught us to add.

Arms, each added because a pass missed something real:
  1 description scan          (v1)
  2 resource CONTENT read     (v2: v1 never read resources)
  3 behaviour diff on repeat  (v3: rug pull mutates __doc__, which tools/list caches)
  4 argument enumeration      (v4: generic args never named the poisoned document)
  5 widened secret pattern    (this pass: vendor-prefixed keys like api_prod_xxx were missed)
"""
import asyncio, json, re
from mcp import ClientSession
from mcp.client.sse import sse_client

RED = re.compile(r"(ignore (previous|above)|do not (tell|mention|reveal)|before providing|"
                 r"<important>|do not (explicitly )?mention|include the api keys|system://|internal://)", re.I)
# widened: a labelled credential line, a vendor-prefixed token, or a classic key shape
SECRET = re.compile(r"(password\s*[:=]|api[_ -]?key\s*[:=]|sk-[A-Za-z0-9]{8,}|postgresql://|"
                    r"BEGIN (RSA|OPENSSH)|credential|"
                    r"\b[a-z]{2,6}[_-](?:prod|live|test|dev)[_-][A-Za-z0-9]{10,}\b|"
                    r"^.*(api|access|secret)\s*key.*:\s*\S{12,})", re.I | re.M)
NAMES = {1:"Basic Prompt Injection",2:"Tool Poisoning",3:"Excessive Permission Scope",
         4:"Rug Pull Attack",5:"Tool Shadowing",6:"Indirect Prompt Injection",7:"Token Theft",
         8:"Malicious Code Execution",9:"Remote Access Control",10:"Multi-Vector Attack"}
GEN = {"city":"London","username":"admin","user_id":"1","filename":"/etc/passwd","path":"/etc/passwd",
       "query":"test","expression":"1+1","command":"id","code":"print(1)","host":"127.0.0.1",
       "document_name":"internal_memo.txt","name":"test","id":"1","text":"test","message":"test"}

async def out_of(s, name, args, timeout=25):
    try:
        r = await asyncio.wait_for(s.call_tool(name, args), timeout=timeout)
        return " ".join(getattr(c,"text","") or "" for c in r.content)
    except Exception as e:
        return f"__err__ {type(e).__name__}"

async def audit(n):
    o = {"n":n,"name":NAMES[n],"findings":{},"err":None}
    try:
        async with sse_client(f"http://127.0.0.1:{8800+n}/sse", timeout=15) as (r,w):
            async with ClientSession(r,w) as s:
                await asyncio.wait_for(s.initialize(), timeout=20)
                tools = (await asyncio.wait_for(s.list_tools(), timeout=20)).tools
                F = o["findings"]
                # 1 description
                bad = [t.name for t in tools if (t.description or "") and
                       ([c for c in t.description if 0xE0000<=ord(c)<=0xE007F] or RED.search(t.description))]
                if bad: F["poisoned_description"] = bad
                # 2 resources + collect document names for arm 4
                docs, res_hits = [], []
                try:
                    for res in (await asyncio.wait_for(s.list_resources(), timeout=10)).resources:
                        try:
                            c = await asyncio.wait_for(s.read_resource(res.uri), timeout=10)
                            txt = " ".join(getattr(x,"text","") or "" for x in c.contents)
                        except Exception: continue
                        docs += re.findall(r"[\w-]+\.txt", txt)
                        if SECRET.search(txt): res_hits.append(str(res.uri))
                except Exception: pass
                if res_hits: F["secret_resource"] = res_hits
                # 3 + 4 behaviour diff and argument enumeration
                behav, out_sec, out_inj = [], [], []
                for t in tools:
                    props = list((t.inputSchema.get("properties") or {}).keys())
                    argsets = [{p: GEN.get(p,"test") for p in props}]
                    if props and docs:
                        argsets += [{props[0]: d} for d in sorted(set(docs))]
                    outs = []
                    for a in argsets:
                        for _ in range(4 if len(argsets)==1 else 1):
                            outs.append(await out_of(s, t.name, a))
                    real = [x for x in outs if not x.startswith("__err__")]
                    if len(argsets)==1 and len(set(real))>1: behav.append(t.name)
                    for x in real:
                        if SECRET.search(x) and t.name not in out_sec: out_sec.append(t.name)
                        if RED.search(x) and t.name not in out_inj: out_inj.append(t.name)
                if behav:  F["behaviour_changed"] = behav
                if out_sec: F["secret_in_output"] = out_sec
                if out_inj: F["injection_in_output"] = out_inj
    except Exception as e:
        o["err"] = f"{type(e).__name__}: {str(e)[:60]}"
    return o

async def main():
    rows = [await audit(n) for n in range(1,11)]
    print(f"{'ch':3} {'class':28} findings")
    hit = 0
    for o in rows:
        if o["err"]: print(f" {o['n']:<2} {o['name']:28} ERROR {o['err']}"); continue
        if o["findings"]: hit += 1
        keys = ", ".join(f"{k}={v}" for k,v in o["findings"].items()) or "— none —"
        print(f" {o['n']:<2} {o['name']:28} {keys[:120]}")
    print(f"\n{hit}/10 DVMCP challenges detected by the refined skill logic")
    json.dump(rows, open("dvmcp_final.json","w"), indent=1)

asyncio.run(main())
