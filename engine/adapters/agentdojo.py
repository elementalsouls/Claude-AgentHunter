"""AgentDojo run-log -> Trace. One JSON file per user_task x injection."""
import glob, json, os

def load(runs_dir, suite):
    for f in sorted(glob.glob(f"{runs_dir}/*/{suite}/*/important_instructions/*.json")):
        d = json.load(open(f))
        steps, env, usr = [], [], []
        for m in d.get("messages", []):
            c = m.get("content")
            c = " ".join(x.get("content","") or "" for x in c) if isinstance(c, list) else str(c or "")
            if m.get("role") == "user": usr.append(c)
            elif m.get("role") == "tool": env.append(c)
            for tc in (m.get("tool_calls") or []):
                steps.append({"tool": tc.get("function"), "input": json.dumps(tc.get("args"), default=str),
                              "observation": ""})
        ans = ""
        for m in d.get("messages", []):
            if m.get("role") == "assistant":
                c = m.get("content"); c = " ".join(x.get("content","") or "" for x in c) if isinstance(c,list) else str(c or "")
                if c.strip(): ans = c
        yield {"id": f"{d.get('user_task_id')}/{d.get('injection_task_id')}",
               "user_text": " ".join(usr), "injected": [str(v) for v in (d.get("injections") or {}).values()],
               "steps": steps, "answer": ans, "label": d.get("security") is True, "_env": " ".join(env)}
