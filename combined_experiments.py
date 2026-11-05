#!/usr/bin/env python3
"""Combined experiments C1-C6 (base harness + human/taint/severity layers). Writes results_combined.json and CSVs."""
import json, os, sys, time
from dataclasses import replace
import numpy as np, pandas as pd
from agentsec_plus import *

SCALE = float(os.environ.get("SCALE", "1.0"))
def N(x): return max(10, int(x * SCALE))
OUTD = "results_combined"; os.makedirs(OUTD, exist_ok=True)
t0 = time.time()
def log(*a): print(f"[{time.time()-t0:6.1f}s]", *a, flush=True)
P, H = Params(), HParams()
kw = dict(n_iid=N(600), n_camp=N(80), n_a4=N(150), n_ben=N(1000))

# ---------------- C1: main comparison (all 14 defences) ----------------
rows = []
for PD in ALL:
    r = evaluate(PD, P, H, tag="c1", **kw); r["label"] = PD.label or PD.base.label; rows.append(r); log("C1", PD.key)
C1 = pd.DataFrame(rows); C1.to_csv(f"{OUTD}/C1_main.csv", index=False)

# ---------------- C2: threshold sweep for the layered defence H2 ----------------
rows = []
for ht in [3, 5, 7, 8, 9, 10]:
    for tt in [3, 5, 8, 9]:
        r = evaluate(BY_KEY["H2"], P, replace(H, human_thr=ht, taint_thr=tt), tag="c2", n_iid=N(300), n_camp=N(40), n_a4=N(100), n_ben=N(500))
        r.update(human_thr=ht, taint_thr=tt); rows.append(r)
    log("C2 human_thr", ht)
C2 = pd.DataFrame(rows); C2.to_csv(f"{OUTD}/C2_thresholds.csv", index=False)

# ---------------- C3: taint-coverage failure x human gate threshold ----------------
rows = []
covs = [1.0, .95, .9, .8, .6, .4, .2, 0.0]
for nm, PD, ht in [("H2 human_thr=8", BY_KEY["H2"], 8), ("H2 human_thr=10", BY_KEY["H2"], 10), ("H3 human_thr=8", BY_KEY["H3"], 8), ("H3 human_thr=10", BY_KEY["H3"], 10), ("H1 (no taint)", BY_KEY["H1"], 8), ("D7 (no human)", BY_KEY["D7"], 8)]:
    for cv in covs:
        r = evaluate(PD, P, replace(H, taint_cov=cv, human_thr=ht), tag="c3", n_iid=N(300), n_camp=N(40), n_a4=N(100), n_ben=N(400))
        r.update(config=nm, taint_cov=cv); rows.append(r)
    log("C3", nm)
C3 = pd.DataFrame(rows); C3.to_csv(f"{OUTD}/C3_taint_coverage.csv", index=False)

# ---------------- C4: policy-coverage degradation x layering ----------------
rows = []
full = sorted(POLICY_RULES["P3"])
for c in [1.0, .8, .6, .4, .2, 0.0]:
    fn = (lambda rng, c=c, full=full: frozenset(r for r in full if rng.random() < c))
    for key in ["D7", "H1", "H2", "H5"]:
        PD = BY_KEY[key]
        rf = fn if PD.base.policy == "P3" else None
        r = evaluate(PD, P, H, tag="c4", n_iid=N(300), n_camp=N(40), n_a4=N(100), n_ben=N(400), rules_fn=rf)
        r.update(config=key, policy_cov=c); rows.append(r)
    log("C4 cov", c)
C4 = pd.DataFrame(rows); C4.to_csv(f"{OUTD}/C4_policy_coverage.csv", index=False)

# ---------------- C5: reviewer fatigue / approval spamming ----------------
rows = []
for fat in [0.0, 0.3, 0.5]:
    for sd in [1.0, 0.95, 0.9, 0.8]:
        for key in ["H2", "H3", "H5"]:
            r = evaluate(BY_KEY[key], P, replace(H, fatigue_coef=fat, spam_decay=sd), tag="c5", n_iid=N(200), n_camp=N(40), n_a4=N(100), n_ben=N(300))
            r.update(config=key, fatigue=fat, spam_decay=sd); rows.append(r)
    log("C5 fatigue", fat)
C5 = pd.DataFrame(rows); C5.to_csv(f"{OUTD}/C5_fatigue.csv", index=False)

# ---------------- C6: model-susceptibility sweep for the layered defences (independence check) ----------------
rows = []
for a0 in [-4, -2, -1.1, 0, 2, 4]:
    for key in ["D1", "D3", "D7", "H2"]:
        r = evaluate(BY_KEY[key], replace(P, a0=a0), H, tag="c6", n_iid=N(200), n_camp=N(30), n_a4=N(60), n_ben=N(100))
        r.update(config=key, a0=a0); rows.append(r)
    log("C6 a0", a0)
C6 = pd.DataFrame(rows); C6.to_csv(f"{OUTD}/C6_susceptibility.csv", index=False)
# ---------------- C7: deterministic approval budget (counter to approval spamming) ----------------
rows = []
for cap in [None, 8, 4, 2, 1]:
    for key in ["H2", "H3", "H5"]:
        r = evaluate(BY_KEY[key], P, replace(H, esc_cap=cap), tag="c7", n_iid=N(300), n_camp=N(40), n_a4=N(100), n_ben=N(500))
        r.update(config=key, esc_cap=("none" if cap is None else cap)); rows.append(r)
    log("C7 cap", cap)
C7 = pd.DataFrame(rows); C7.to_csv(f"{OUTD}/C7_approval_budget.csv", index=False)
log("ALL DONE")
