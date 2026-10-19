"""CLI: python3 -m redteam [target] [--rounds N] [--llm]   (needs a running lab target)."""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab_target import TARGETS   # noqa: E402
from harness import run          # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(prog="redteam", description="adaptive red-team harness (lab)")
    ap.add_argument("target", nargs="?", default="guardrail", choices=sorted(TARGETS))
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--llm", action="store_true",
                    help="augment the mutation generator with a local Ollama model if reachable")
    a = ap.parse_args(argv)

    print(f"[redteam] evolving against '{a.target}' (rounds={a.rounds}, llm={a.llm})")
    rep = run(TARGETS[a.target], rounds=a.rounds, llm=a.llm, verbose=True)
    print(rep.summary())
    if not rep.trustworthy():
        print("UNTRUSTWORTHY: the control payload landed — the oracle can't discriminate.")
        return 2
    hits = rep.direct() or rep.landed
    if hits:
        best = hits[0]
        print(f"DISCOVERED: the static seed was blocked, but '{'+'.join(best['lineage'])}' evaded it "
              f"-> {best['payload']!r}")
        return 0
    print("no evasion found within the mutation budget")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
