"""Harness adapters normalise every source into ONE trace shape the arms consume:

    Trace = {
      "id": str,                    # user_task/injection id, or probe label
      "user_text": str,             # the legitimate instruction
      "injected": [str],            # untrusted content planted by the attack (may be empty)
      "steps": [{"tool","input","observation"}],   # tool calls in execution order
      "answer": str,                # the agent's final user-facing reply
      "label": bool|None,           # ground-truth attack-succeeded, if the source knows it
    }

A new target = a new adapter here. The four arms never change.
"""
