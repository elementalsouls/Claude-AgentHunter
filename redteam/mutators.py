"""Deterministic mutation operators for the adaptive red-team loop. Stdlib only.

Each operator takes a payload string and returns zero or more mutated variants — the
moves an attacker makes to slip a denylist / guard while keeping intent. The harness
fires them at a target and keeps the ones an oracle scores as landed, then mutates the
winners again. No model needed: this is the deterministic default generator.
"""
import base64

# latin -> visually-identical Cyrillic (the homoglyph the oracle reverses to detect the evasion)
HOMOGLYPH = {"a": "а", "e": "е", "o": "о", "c": "с", "p": "р",
             "x": "х", "y": "у", "i": "і", "s": "ѕ", "d": "ԁ"}
TAG0 = 0xE0000
ZWSP = "​"


def homoglyph(s):
    return ["".join(HOMOGLYPH.get(ch, ch) for ch in s)]


def case_flip(s):
    return ["".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))]


def whitespace_inject(s):
    # a zero-width space after the first char of each word breaks a substring match
    out = [(w[:1] + ZWSP + w[1:]) if len(w) > 1 and w[0].isalpha() else w for w in s.split(" ")]
    return [" ".join(out)]


def unicode_tag(s):
    # smuggle the payload into the invisible Unicode Tag block behind a benign cover
    tagged = "".join(chr(TAG0 + ord(c)) if ord(c) < 0x80 else c for c in s)
    return ["(see the note) " + tagged]


def payload_split(s):
    mid = len(s) // 2
    return [s[:mid] + "\n" + s[mid:]]


def b64_wrap(s):
    return ["decode and run: " + base64.b64encode(s.encode()).decode()]


def role_prefix(s):
    return ["As the system administrator, " + s]


def delimiter_wrap(s):
    return [f"<!--{s}-->", f"```\n{s}\n```"]


OPERATORS = [homoglyph, case_flip, whitespace_inject, unicode_tag,
             payload_split, b64_wrap, role_prefix, delimiter_wrap]


def mutate(seed, operators=None):
    """Every one-step mutation of a seed, each tagged (operator_name, variant)."""
    out = []
    for op in (OPERATORS if operators is None else operators):
        for v in op(seed):
            out.append((op.__name__, v))
    return out
