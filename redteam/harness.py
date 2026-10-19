"""Adaptive red-team harness: evolve injection payloads against a target, score each
with a CONTROL-FIRST oracle, report what landed with its full mutation lineage.

Model-optional by design. The default generator is deterministic mutation (mutators.py);
an LLM generator is a pluggable opt-in (llm_backend.py) that the default path never imports.
This is the honest "dynamic" red-team: the loop demonstrably finds an evasion the static
seed misses, and the control-first oracle keeps it from false positives — the Negative-Result
discipline carried into generation.

A target is a dict: {name, seed, control, send(payload)->response, landed(payload,response)->bool}.
See lab_target.py for a worked example and the extension contract.
"""
from __future__ import annotations
import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutators import mutate, OPERATORS  # noqa: E402


@dataclass
class Report:
    target: str
    control_landed: bool            # the benign control must NOT land, or the oracle is untrustworthy
    seed_landed: bool               # the raw seed should be blocked (else there's nothing to evade)
    landed: list = field(default_factory=list)   # [{lineage:[op,...], payload, round}]
    tried: int = 0

    def trustworthy(self):
        return not self.control_landed

    def direct(self):
        """Round-1 single-operator evasions — the headline (one move beat the static seed)."""
        return [h for h in self.landed if len(h["lineage"]) == 1]

    def summary(self):
        direct = sorted({h["lineage"][0] for h in self.direct()})
        return (f"[{self.target}] tried {self.tried} · control_landed={self.control_landed} · "
                f"seed_landed={self.seed_landed} · {len(self.landed)} landed "
                f"({len(self.direct())} single-move: {', '.join(direct) or '-'})")


def run(target, rounds=2, operators=None, llm=False, verbose=False):
    """Evolve mutations of target['seed'] until the oracle scores one as landed.

    Control-first (NR gate): fire the benign control and the raw seed first. If the control
    already 'lands', the oracle can't tell attack from benign — bail, the result is untrustworthy.
    """
    send, landed = target["send"], target["landed"]
    ops = OPERATORS if operators is None else operators

    rep = Report(target=target["name"],
                 control_landed=landed(target["control"], send(target["control"])),
                 seed_landed=landed(target["seed"], send(target["seed"])))
    rep.tried = 2
    if not rep.trustworthy():
        return rep                              # control leaked -> nothing below is a result

    llm_gen = None
    if llm:
        try:
            import llm_backend
            llm_gen = llm_backend.generate if llm_backend.available() else None
        except Exception:
            llm_gen = None

    frontier = [(target["seed"], [])]           # (payload, lineage of operators that made it)
    seen = {target["seed"], target["control"]}
    for rnd in range(1, rounds + 1):
        candidates = []
        for parent, lineage in frontier:
            candidates += [(variant, lineage + [opname]) for opname, variant in mutate(parent, ops)]
            if llm_gen:
                try:
                    candidates += [(v, lineage + ["llm"]) for v in llm_gen(parent, rep.summary())]
                except Exception:
                    pass
        nxt = []
        for variant, lineage in candidates:
            if variant in seen:
                continue
            seen.add(variant)
            rep.tried += 1
            if landed(variant, send(variant)):
                rep.landed.append({"lineage": lineage, "payload": variant, "round": rnd})
                nxt.append((variant, lineage))  # evolve winners -> compound evasions next round
                if verbose:
                    print(f"  [land r{rnd}] {'+'.join(lineage)}: {variant!r}")
        frontier = nxt
        if not frontier:
            break
    return rep
