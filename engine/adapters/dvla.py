"""DVLA ReAct banking agent trace -> Trace.

Reads the committed field capture (field/dvla/dvla_traces.json) and normalises it
into the shape the four arms consume (see engine/adapters/__init__.py). This is the
second real adapter after agentdojo, and the one the arm-D regression test runs on.

The attack here is ReAct *scratchpad forgery*: the user message carries forged
`Observation:` / `Thought:` / `Action:` lines that the agent trusts as if the loop
produced them. arm_d reads forgery from `injected` + `_env`, so the forged lines must
land in `injected` (not the whole prompt — or `toks(injected) - toks(user_text)` would
subtract to empty and the arm could never fire). We split the prompt line by line: a
line whose start matches the ReAct control regex is forged (-> injected); the rest is
the legitimate instruction (-> user_text). An inline "Observation:" mid-sentence
("explain what an Observation: line means") is NOT at line start, so it is correctly
left in user_text and raises no detection.
"""
import json
import os
import re

# Same ReAct control markers as engine/score.py:CTRL and field/dvla/arm_d.py, anchored
# at line start so only forged scratchpad lines count.
CTRL = re.compile(r"(?i)^\s*(?:observation|action input|action|thought)\s*:")

_DEFAULT = os.path.join(os.path.dirname(__file__), "..", "..", "field", "dvla", "dvla_traces.json")


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-") or "trace"


def load(path=None):
    """Yield canonical Trace dicts from the DVLA capture (defaults to the committed file)."""
    path = path or os.path.normpath(_DEFAULT)
    for rec in json.load(open(path, encoding="utf-8")):
        lines = (rec.get("prompt") or "").split("\n")
        injected = [l for l in lines if CTRL.match(l)]
        user_text = " ".join(l for l in lines if not CTRL.match(l)).strip()
        yield {
            "id": _slug(rec.get("label", "")),
            "user_text": user_text,
            "injected": injected,
            "steps": rec.get("steps", []),
            "answer": rec.get("answer", ""),
            "label": bool(rec.get("leaked")),   # ground-truth IMPACT (a sensitive value leaked)
            "_env": "",
        }
