#!/usr/bin/env python3
"""Integration regression for the adaptive harness. Starts the lab target + OOB listener
(the same way lab/run_lab.py does), evolves against /guard, and asserts the loop discovers
an evasion the static seed misses — with the control-first oracle discriminating.

Stdlib only, no API key. Proves the one thing that matters: adaptive mutation beats the
static probe, and the control keeps it honest.
"""
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.join(os.path.dirname(HERE), "lab", "target")
sys.path.insert(0, HERE)

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def wait_up(url, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            _opener.open(url, timeout=1)
            return True
        except urllib.error.HTTPError:
            return True                 # server responded = up
        except Exception:
            time.sleep(0.2)
    return False


def main():
    listener = subprocess.Popen([sys.executable, "oob_listener.py"], cwd=LAB)
    target = subprocess.Popen([sys.executable, "vuln_agent.py"], cwd=LAB)
    try:
        assert wait_up("http://127.0.0.1:18081/__hits"), "listener did not start"
        assert wait_up("http://127.0.0.1:18080/settings"), "target did not start"

        from lab_target import GUARDRAIL
        from harness import run
        rep = run(GUARDRAIL, rounds=2)

        n = 0
        assert not rep.control_landed, "benign control landed -> the oracle can't discriminate"
        n += 1
        assert not rep.seed_landed, "the raw seed was NOT blocked -> there is nothing to evade"
        n += 1
        assert rep.landed, "the harness found no evasion the static seed missed"
        n += 1
        direct = {h["lineage"][0] for h in rep.direct()}
        assert "homoglyph" in direct, f"expected the homoglyph single-move evasion; got {sorted(direct)}"
        n += 1

        print(f"  tried {rep.tried} payloads; single-move evasions: {sorted(direct)}")
        print(f"{n}/{n} redteam checks pass")
        return 0
    finally:
        for p in (target, listener):
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"FAIL redteam: {e}")
        sys.exit(1)
