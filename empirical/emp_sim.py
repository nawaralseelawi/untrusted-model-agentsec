"""Re-run the harness with MEASURED per-family obedience rates instead of the logistic law.
Real: tools, oracle, monitors, fuzzing (unchanged).  Measured: P(obey | family, guard) from the Colab run, with
Beta posterior uncertainty propagated by drawing the rate table anew for every replicate.
Still assumed (no data): spotlighting (D2/D3/D8 use the measured prompt-guardrail rates), detector TPR (fixed 0.6)."""
import json, math, random, sys
from dataclasses import dataclass, replace
import numpy as np
import agentsec_sim as S
from emp_data import K, N

@dataclass(frozen=True)
class EAtt:
    key: str; label: str; policy: str          # naive | best | search | compromised
    s: float = 0.0; adaptive: bool = False; nvar: int = 3; compromised: bool = False

ATTS = [EAtt("E0", "Naive family (L0)", "naive"),
        EAtt("E1", "Best-known family (L2)", "best"),
        EAtt("E2", "Uninformed search over 6 families", "search"),
        EAtt("E4", "Compromised model", "compromised", nvar=99, compromised=True)]
RATES = {0: np.array([K[0] / N]).ravel(), 1: np.array([K[1] / N]).ravel()}   # replaced per replicate

def p_emp(task, D, P, att, j):
    g = 0 if D.guard == "none" else 1
    r = RATES[g]
    return float(r[0] if att.policy == "naive" else r[2] if att.policy == "best" else r.mean())

S.p_hijack = p_emp        # run_episode resolves p_hijack from module globals
P0 = replace(S.Params(), d0=0.4, d1=0.0)    # detector TPR fixed at sigma(0.4)=0.6 (assumption)
KEYS = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8"]
CHECK = [1, 3, 10]

def campaign(D, att, n, rng, k=10):
    fs = []
    for t in S.TASKS:
        for _ in range(n):
            mem = set(); first = math.inf
            for j in range(1, k + 1):
                if S.run_episode(t, D, P0, rng, att, j, mem)["viol"]:
                    first = j; break
            fs.append(first)
    return fs

def main(ND=60, n=25, seed=77):
    rng_post = np.random.default_rng(seed); rng = random.Random(seed)
    res = {a.key: {d: {k: [] for k in CHECK} for d in KEYS} for a in ATTS if not a.compromised}
    a4 = {d: [] for d in KEYS}
    for draw in range(ND):
        for g in (0, 1):
            RATES[g] = rng_post.beta(K[g] + 1, N - K[g] + 1)
        for d in KEYS:
            D = S.DEF_BY_KEY[d]
            for a in ATTS:
                if a.compromised:
                    cnt = 0; tot = 0
                    for t in S.TASKS:
                        for _ in range(10):
                            cnt += S.run_episode(t, D, P0, rng, a, 1, None)["viol"]; tot += 1
                    a4[d].append(cnt / tot); continue
                fs = campaign(D, a, n, rng)
                for k in CHECK:
                    res[a.key][d][k].append(sum(1 for x in fs if x <= k) / len(fs))
        if draw % 10 == 0: print("draw", draw, flush=True)
    summ = {a: {d: {str(k): [float(np.mean(v)), float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]
                    for k, v in dd.items()} for d, dd in r.items()} for a, r in res.items()}
    summ["E4"] = {d: [float(np.mean(v)), float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] for d, v in a4.items()}
    json.dump(summ, open("emp_sim_results.json", "w"), indent=1)

if __name__ == "__main__":
    main()
