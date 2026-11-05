#!/usr/bin/env python3
"""Runs all experiments (E1-E6) and writes results.json. Deterministic given SEED."""
import json, math, random, sys, time
from dataclasses import replace
import numpy as np
from scipy.stats import spearmanr
from agentsec_sim import *

SEED = 20261026
K_MAX = 25
KS = [1, 2, 3, 5, 10, 25]
N_IID = 3000        # episodes / task / cell for i.i.d. attackers (A0-A2)
N_CAMP = 400        # adaptive campaigns / task / defence (A3)
N_A4 = 300
N_BEN = 3000
OUT = {}


def R(*parts):
    return random.Random("-".join(map(str, (SEED,) + parts)))


def iid_counts(D, att, P, n, tag, rules_fn=None):
    """per task: (violations, leaks, completions) over n single-attempt episodes."""
    res = {}
    for t in TASKS:
        rng = R(tag, D.key, att.key, t.id)
        v = l = c = 0
        for _ in range(n):
            rules = rules_fn(rng) if rules_fn else None
            o = run_episode(t, D, P, rng, att, 1, None, rules)
            v += o["viol"]; l += o["leak"]; c += o["comp"]
        res[t.id] = (v, l, c)
    return res


def campaign_first_success(D, att, P, n, tag, k=K_MAX, rules_fn=None):
    """per task: list of first-success attempt index (inf if none within k)."""
    out = {}
    for t in TASKS:
        rng = R(tag, D.key, att.key, t.id)
        fs = []
        for _ in range(n):
            mem = set()
            rules = rules_fn(rng) if rules_fn else None
            first = math.inf
            for j in range(1, k + 1):
                o = run_episode(t, D, P, rng, att, j, mem, rules)
                if o["viol"]:
                    first = j
                    break
            fs.append(first)
        out[t.id] = fs
    return out


def macro_asr_at_k_from_p(pt, k):
    return float(np.mean([1 - (1 - p) ** k for p in pt.values()]))


def boot_ci_iid(counts, n, k, B=400, seed=1):
    rng = np.random.default_rng(seed)
    ps = np.array([counts[t.id][0] / n for t in TASKS])
    est = np.mean(1 - (1 - ps) ** k)
    bs = []
    for _ in range(B):
        pb = rng.binomial(n, ps) / n
        bs.append(np.mean(1 - (1 - pb) ** k))
    return float(est), float(np.percentile(bs, 2.5)), float(np.percentile(bs, 97.5))


def class_of(tid):
    return TASK_BY_ID[tid].cls


# ----------------------------------------------------------------------------- E1
def E1():
    P = Params()
    res = {"iid": {}, "adaptive": {}, "a4": {}, "benign": {}, "per_class": {}}
    for D in DEFENSES:
        # i.i.d. attackers A0-A2
        for att in ATTACKERS[:3]:
            cnt = iid_counts(D, att, P, N_IID, "e1")
            entry = {"asr_k": {}, "p1_per_task": {t: cnt[t][0] / N_IID for t in cnt},
                     "leak1": float(np.mean([cnt[t][1] / N_IID for t in cnt])),
                     "util_under_attack": float(np.mean([cnt[t][2] / N_IID for t in cnt]))}
            for k in KS:
                entry["asr_k"][k] = boot_ci_iid(cnt, N_IID, k)
            res["iid"][f"{D.key}|{att.key}"] = entry
        # adaptive A3
        att = ATT_BY_KEY["A3"]
        fs = campaign_first_success(D, att, P, N_CAMP, "e1")
        allfs = [x for t in fs for x in fs[t]]
        entry = {"asr_k": {}, "per_task_asr25": {t: float(np.mean([x <= K_MAX for x in fs[t]])) for t in fs}}
        for k in KS:
            kk = sum(1 for x in allfs if x <= k)
            entry["asr_k"][k] = wilson(kk, len(allfs))
        entry["mean_attempts_to_success"] = float(np.mean([x for x in allfs if x < math.inf])) if any(x < math.inf for x in allfs) else None
        res["adaptive"][D.key] = entry
        # A4 compromised model
        att = ATT_BY_KEY["A4"]
        cnt = iid_counts(D, att, P, N_A4, "e1")
        res["a4"][D.key] = {"asr": wilson(sum(cnt[t][0] for t in cnt), N_A4 * len(TASKS)),
                            "per_task": {t: cnt[t][0] / N_A4 for t in cnt}}
        # benign utility
        rr = R("ben", D.key)
        comp = fpb = llm = 0
        nn = 0
        per_task_comp = {}
        for t in TASKS:
            c = 0
            for _ in range(N_BEN):
                o = run_episode(t, D, P, rr, None)
                c += o["comp"]; fpb += o["fpb"]; llm += o["llm"]; nn += 1
            per_task_comp[t.id] = c / N_BEN
            comp += c
        res["benign"][D.key] = {"completion": wilson(comp, nn), "false_block_rate": wilson(fpb, nn),
                                "extra_llm_calls_per_task": llm / nn, "per_task": per_task_comp}
        print("E1", D.key, flush=True)
    # per-class tables (ASR@1 and @25 for A2 i.i.d., A3 @25, A4)
    for D in DEFENSES:
        pc = {}
        for cls in CLASSES:
            tids = [t.id for t in TASKS if t.cls == cls]
            pc[cls] = {
                "A2@1": float(np.mean([res["iid"][f"{D.key}|A2"]["p1_per_task"][t] for t in tids])),
                "A2@25": float(np.mean([1 - (1 - res["iid"][f"{D.key}|A2"]["p1_per_task"][t]) ** 25 for t in tids])),
                "A3@25": float(np.mean([res["adaptive"][D.key]["per_task_asr25"][t] for t in tids])),
                "A4": float(np.mean([res["a4"][D.key]["per_task"][t] for t in tids])),
            }
        res["per_class"][D.key] = pc
    OUT["E1"] = res


# ----------------------------------------------------------------------------- E2
def E2():
    """Sweep base model susceptibility a0 (the 'model is the problem' axis)."""
    grid = [-4, -3, -2, -1.1, 0, 1, 2, 3, 4]
    res = {"a0": grid, "A1@1": {}, "A3@10": {}}
    for D in DEFENSES:
        r1, r3 = [], []
        for a0 in grid:
            P = replace(Params(), a0=a0)
            cnt = iid_counts(D, ATT_BY_KEY["A1"], P, 500, "e2")
            r1.append(float(np.mean([cnt[t][0] / 500 for t in cnt])))
            fs = campaign_first_success(D, ATT_BY_KEY["A3"], P, 60, "e2", k=10)
            allfs = [x for t in fs for x in fs[t]]
            r3.append(sum(1 for x in allfs if x <= 10) / len(allfs))
        res["A1@1"][D.key] = r1
        res["A3@10"][D.key] = r3
        print("E2", D.key, flush=True)
    OUT["E2"] = res


# ----------------------------------------------------------------------------- E3
def E3():
    """Policy coverage / fidelity: each rule independently present with probability c."""
    covs = [1.0, 0.9, 0.8, 0.6, 0.4, 0.2, 0.0]
    res = {"cov": covs}
    for key in ("D6", "D7", "D8"):
        D = DEF_BY_KEY[key]
        full = sorted(POLICY_RULES[D.policy])
        a3, a4 = [], []
        for c in covs:
            fn = lambda rng, c=c, full=full: frozenset(r for r in full if rng.random() < c)
            fs = campaign_first_success(D, ATT_BY_KEY["A3"], Params(), 100, "e3", rules_fn=fn)
            allfs = [x for t in fs for x in fs[t]]
            a3.append(wilson(sum(1 for x in allfs if x <= K_MAX), len(allfs)))
            cnt = iid_counts(D, ATT_BY_KEY["A4"], Params(), 100, "e3", rules_fn=fn)
            a4.append(wilson(sum(cnt[t][0] for t in cnt), 100 * len(TASKS)))
        res[key] = {"A3@25": a3, "A4": a4}
        print("E3", key, flush=True)
    OUT["E3"] = res


# ----------------------------------------------------------------------------- E4
def E4():
    """Utility cost vs. unanticipated-but-legitimate actions (omega) and benign variation (v_fmt)."""
    omegas = [0.0, 0.05, 0.1, 0.2, 0.3]
    res = {"omega": omegas}
    for D in DEFENSES:
        row = []
        for om in omegas:
            P = replace(Params(), omega=om)
            rr = R("e4", D.key, om)
            c = n = 0
            for t in TASKS:
                for _ in range(600):
                    c += run_episode(t, D, P, rr, None)["comp"]; n += 1
            row.append(c / n)
        res[D.key] = row
    OUT["E4"] = res
    print("E4", flush=True)


# ----------------------------------------------------------------------------- E5
def E5(n_draws=200):
    """Monte-Carlo over assumed model/guardrail parameters: how sensitive is each defence?"""
    rr = random.Random(SEED + 5)
    draws, asr_a3, asr_a1, util = [], {d.key: [] for d in DEFENSES}, {d.key: [] for d in DEFENSES}, {d.key: [] for d in DEFENSES}
    for i in range(n_draws):
        dp = rr.uniform(0.5, 2.5)
        P = replace(Params(), a0=rr.uniform(-2.5, 0.5), b=rr.uniform(0.5, 1.5), delta_prompt=dp,
                    delta_spot=dp + rr.uniform(0.3, 1.2), d0=rr.uniform(0.5, 3.0), d1=rr.uniform(0.5, 2.0),
                    lam=rr.uniform(0.3, 1.2), kappa=rr.uniform(0.05, 0.3), fpr=rr.uniform(0.01, 0.08))
        draws.append({k: getattr(P, k) for k in ("a0", "b", "delta_prompt", "delta_spot", "d0", "d1", "lam", "kappa", "fpr")})
        for D in DEFENSES:
            fs = campaign_first_success(D, ATT_BY_KEY["A3"], P, 10, f"e5-{i}", k=5)
            allfs = [x for t in fs for x in fs[t]]
            asr_a3[D.key].append(sum(1 for x in allfs if x <= 5) / len(allfs))
            cnt = iid_counts(D, ATT_BY_KEY["A1"], P, 40, f"e5b-{i}")
            asr_a1[D.key].append(float(np.mean([cnt[t][0] / 40 for t in cnt])))
        if i % 25 == 0:
            print("E5 draw", i, flush=True)
    res = {"draws": draws, "A3@5": asr_a3, "A1@1": asr_a1, "spearman": {}}
    names = list(draws[0].keys())
    for D in DEFENSES:
        y = asr_a3[D.key]
        res["spearman"][D.key] = {}
        for nme in names:
            x = [d[nme] for d in draws]
            if np.std(y) < 1e-12:
                res["spearman"][D.key][nme] = 0.0
            else:
                res["spearman"][D.key][nme] = float(spearmanr(x, y)[0])
    OUT["E5"] = res


# ----------------------------------------------------------------------------- E6
def E6():
    """Bypass matrix (real monitor code) + monitor latency."""
    import timeit
    rows = []
    for t in TASKS:
        variants = []
        if t.mode == "add":
            for si, step in enumerate(t.attack):
                for vi, c in enumerate(step):
                    variants.append((f"step{si}.v{vi}", c))
        else:
            for vi, c in enumerate(t.modify):
                variants.append((f"v{vi}", c))
        for vid, c in variants:
            w = World()
            if c.tool == "http_post" or "@DATA@" in str(c.args.get("body", "")):
                w.secret = False
            c2 = w.materialize(c)
            row = {"task": t.id, "name": t.name, "variant": vid, "call": f"{c2.tool}({', '.join(f'{k}={v!r}' for k, v in c2.args.items() if k in ('to','url','path','key','tag','value','cmd'))})",
                   "violation": bool(is_violation(t, c2))}
            for lvl in ("P1", "P2n", "P2h", "P3"):
                row[lvl] = bool(Monitor(lvl, t, POLICY_RULES[lvl]).check(c2, World()))
            rows.append(row)
    OUT["E6"] = {"bypass": rows}
    # latency (microseconds per decision) -- measured, not assumed
    lat = {}
    calls = [(t, c) for t in TASKS for c in t.plan] + [(t, c) for t in TASKS for s in t.attack for c in s] + \
            [(t, c) for t in TASKS for c in t.modify]
    for lvl in ("P1", "P2n", "P2h", "P3"):
        mons = [(Monitor(lvl, t, POLICY_RULES[lvl]), c) for t, c in calls]
        w = World()
        def f():
            for m, c in mons:
                m.check(c, w)
        reps = 200
        sec = min(timeit.repeat(f, number=reps, repeat=3)) / (reps * len(mons))
        lat[lvl] = sec * 1e6
    OUT["E6"]["latency_us"] = lat
    print("E6", lat, flush=True)


if __name__ == "__main__":
    import os
    t0 = time.time()
    which = sys.argv[1:] or ["E1", "E2", "E3", "E4", "E5", "E6"]
    if os.path.exists("results_partial.json"):
        OUT.update(json.load(open("results_partial.json")))
    META = {"seed": SEED, "N_IID": N_IID, "N_CAMP": N_CAMP, "N_A4": N_A4, "N_BEN": N_BEN,
            "params": {k: v for k, v in Params().__dict__.items() if k != "task_off"},
            "defenses": {d.key: d.label for d in DEFENSES},
            "attackers": {a.key: a.label for a in ATTACKERS},
            "tasks": {t.id: {"name": t.name, "cls": t.cls, "mode": t.mode} for t in TASKS}}
    for name in which:
        globals()[name]()
        OUT["meta"] = META
        json.dump(OUT, open("results_partial.json", "w"), indent=1, default=str)
        print(name, "done", round(time.time() - t0, 1), "s", flush=True)
    if all(k in OUT for k in ("E1", "E2", "E3", "E4", "E5", "E6")):
        json.dump(OUT, open("results.json", "w"), indent=1, default=str)
        print("ALL DONE", flush=True)
