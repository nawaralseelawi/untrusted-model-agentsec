"""Tests: (1) layers off => run_episode_plus == run_episode, bit-for-bit; (2) A4 is independent of model susceptibility."""
import random
from dataclasses import replace
from agentsec_plus import *
import agentsec_sim as base

def test_equivalence(n=300):
    P, H = Params(), HParams()
    bad = 0; tot = 0
    for D in DEFENSES:
        for att in [None] + ATTACKERS:
            for t in TASKS:
                r1 = random.Random(f"x-{D.key}-{att.key if att else 'b'}-{t.id}")
                r2 = random.Random(f"x-{D.key}-{att.key if att else 'b'}-{t.id}")
                m1, m2 = set(), set()
                for j in range(1, 6):
                    o1 = base.run_episode(t, D, P, r1, att, j, m1)
                    o2 = run_episode_plus(t, plain(D), P, H, r2, att, j, m2)
                    tot += 1
                    if any(o1[k] != o2[k] for k in o1):
                        bad += 1
    assert bad == 0, f"{bad}/{tot} episodes differ"
    print(f"equivalence OK ({tot} episodes, all fields identical)")

def test_a4_model_independence():
    D = BY_KEY["H2"]; H = HParams()
    vals = []
    for a0 in (-4, 0, 4):
        P = replace(Params(), a0=a0)
        r = iid_stats(D, P, replace(H, esc_load=0.5), ATT_BY_KEY["A4"], 150, "t-a4")
        vals.append(round(r["asr"], 6))
    assert len(set(vals)) == 1, vals
    print("A4 independence of model susceptibility OK", vals)

def test_human_monotone():
    P = Params()
    prev = None
    for h0 in (0.0, 0.5, 1.0):
        r = iid_stats(BY_KEY["H1"], P, HParams(h0=h0, fatigue_coef=0, spam_decay=1.0), ATT_BY_KEY["A4"], 200, "t-h")
        if prev is not None: assert r["asr"] <= prev + 1e-9
        prev = r["asr"]
    print("human detection monotonicity OK")

if __name__ == "__main__":
    test_equivalence(); test_a4_model_independence(); test_human_monotone()
