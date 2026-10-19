#!/usr/bin/env python3
"""
Lab runner — the re-runnable check behind every [CONFIRMED] finding.

Starts the OOB listener + vulnerable target locally, runs each exploit, and
exits non-zero if any exploit fails its verification gate. This is the whole
point of Phase C: [CONFIRMED] means "this script exits 0", not "the model said
so".

    python3 run_lab.py          # local (needs python3, curl, ping)

For isolation (recommended before extending with sharper payloads):
    docker compose up --build   # see docker-compose.yml
"""
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EXPLOITS = ["exploit_tool_injection.py", "exploit_blind_exfil.py",
            "exploit_info_disclosure.py", "exploit_prompt_extraction.py",
            "exploit_race_condition.py", "exploit_time_gate.py",
            "exploit_hitl_bypass.py",
            # the seven classes that previously had no lab exercise at all
            "exploit_brute_force.py", "exploit_crypto.py", "exploit_deserialization.py",
            "exploit_config_poisoning.py", "exploit_native_memory.py", "exploit_rag.py",
            "exploit_resource_abuse.py"]


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def wait_up(url, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            _opener.open(url, timeout=1)
            return True
        except urllib.error.HTTPError:
            return True                 # server responded (e.g. 501 on GET) = up
        except Exception:
            time.sleep(0.2)
    return False


def main():
    env = dict(os.environ)
    listener = subprocess.Popen([sys.executable, "target/oob_listener.py"],
                                cwd=HERE, env=env)
    target = subprocess.Popen([sys.executable, "target/vuln_agent.py"],
                              cwd=HERE, env=env)
    try:
        if not wait_up("http://127.0.0.1:18081/__hits"):
            print("FAIL: listener did not start"); return 2
        # target has no health route; a 501 on GET still means it's up
        if not wait_up("http://127.0.0.1:18080/mode_a"):
            time.sleep(0.5)
        print("[lab] target + listener up\n")

        failed = []
        for ex in EXPLOITS:
            print(f"===== {ex} =====")
            rc = subprocess.run([sys.executable, ex],
                                cwd=os.path.join(HERE, "exploits"),
                                env={**env, "PYTHONPATH": os.path.join(HERE, "exploits")}).returncode
            print()
            if rc != 0:
                failed.append(ex)

        n = len(EXPLOITS)
        print(f"{n - len(failed)}/{n} exploits passed their gate.")
        if failed:
            print("FAILED: " + ", ".join(failed)); return 1
        print("ALL CONFIRMED classes re-runnable ✓")
        return 0
    finally:
        for p in (target, listener):
            p.terminate()
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    sys.exit(main())
