import json, numpy as np
from scipy.special import betaln
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
from emp_data import *
R = json.load(open("emp_sim_results.json")); ST = json.load(open("emp_stats.json"))
OLD = json.load(open("../results.json"))["E1"]
rng = np.random.default_rng(5)
RHO = DISPERSION - 1       # beta-binomial with m=2 samples/prompt: dispersion = 1+(m-1)rho

def asr_indep(p, k): return 1 - (1 - p) ** k
def asr_same_prompt(p, k, rho=RHO):       # attacker resubmits one fixed prompt; p_i ~ Beta(mean p, corr rho)
    a = p * (1 - rho) / rho; b = (1 - p) * (1 - rho) / rho
    return 1 - np.exp(betaln(a, b + k) - betaln(a, b))

# posterior for the best family (L2) per guard
post = {g: rng.beta(K[g][2] + 1, N - K[g][2] + 1, 20000) for g in (0, 1)}
ks = np.arange(1, 26)
rows = {}
for g in (0, 1):
    ind = np.array([asr_indep(post[g], k) for k in ks]); clu = np.array([asr_same_prompt(post[g], k) for k in ks])
    rows[g] = dict(ind=(ind.mean(1), np.percentile(ind, 2.5, 1), np.percentile(ind, 97.5, 1)),
                   clu=(clu.mean(1), np.percentile(clu, 2.5, 1), np.percentile(clu, 97.5, 1)))
def at(g, kind, k): m, lo, hi = rows[g][kind]; return f"{100*m[k-1]:.1f}% ({100*lo[k-1]:.1f}-{100*hi[k-1]:.1f})"

# Figure A: per-cell rates + the two model fits
fig, ax = plt.subplots(1, 2, figsize=(10.4, 3.6))
lv = np.arange(6)
for g, c in ((0, "#1f77b4"), (1, "#2ca02c")):
    ci = np.array(ST[f"cell_ci_G{g}"])
    ax[0].errorbar(lv + (g - .5) * .12, K[g] / N, yerr=[K[g] / N - ci[:, 2], ci[:, 3] - K[g] / N], fmt="o", color=c, capsize=2, label=f"observed, guard G{g}")
th = ST["logistic_fit"]; sg = 0.4 * lv
ax[0].plot(lv, 1 / (1 + np.exp(-(th["L0"] + th["alpha"] * sg))), "--", color="k", label="simulator's logistic law (fitted)")
ax[0].set_xlabel("Attack family (level 0-5)"); ax[0].set_ylabel("P(model obeys injection)"); ax[0].legend(fontsize=7, frameon=False)
ax[0].set_title(f"(a) Monotone law rejected (LRT p={ST['shape_LRT_logistic_vs_categorical']['p']:.0e})")
for g, c in ((0, "#1f77b4"), (1, "#2ca02c")):
    for kind, ls in (("ind", "-"), ("clu", ":")):
        m, lo, hi = rows[g][kind]; ax[1].plot(ks, m, ls, color=c, label=f"G{g}, {'fresh variants' if kind=='ind' else 'same prompt resent'}")
        if kind == "ind": ax[1].fill_between(ks, lo, hi, color=c, alpha=.15)
ax[1].set_xlabel("Attempts k"); ax[1].set_ylabel("Cumulative obedience (best family L2)"); ax[1].legend(fontsize=7, frameon=False)
ax[1].set_title("(b) Persistence with measured rates"); ax[1].set_ylim(0, 1.02)
plt.tight_layout(); plt.savefig("fig_emp_susceptibility.png", dpi=200); plt.close()

# Figure B: full-harness ASR@10 by defence under the three model-obedience attackers + compromised model
names = {"D0": "None", "D1": "Prompt", "D2": "Spotlight*", "D3": "Spot+Det*", "D4": "P1", "D5": "P2n", "D6": "P2h", "D7": "P3", "D8": "Layered*"}
keys = list(names)
fig, ax = plt.subplots(figsize=(9.2, 3.6)); w = .2
for i, (a, lab) in enumerate((("E0", "naive family"), ("E1", "best family"), ("E2", "search over families"))):
    y = np.array([R[a][d]["10"] for d in keys])
    ax.bar(np.arange(9) + (i - 1.5) * w, y[:, 0], w, yerr=np.clip([y[:, 0] - y[:, 1], y[:, 2] - y[:, 0]], 0, None), capsize=1.5, label=f"{lab}, k=10", error_kw={"lw": .7})
y = np.array([R["E4"][d] for d in keys]); ax.bar(np.arange(9) + 1.5 * w, y[:, 0], w, yerr=np.clip([y[:, 0] - y[:, 1], y[:, 2] - y[:, 0]], 0, None), capsize=1.5, label="compromised model", color="#444", error_kw={"lw": .7})
ax.set_xticks(range(9)); ax.set_xticklabels([names[k] for k in keys], rotation=30, ha="right"); ax.set_ylabel("ASR (95% posterior interval)")
ax.legend(fontsize=7, frameon=False); ax.set_title("Full harness with measured obedience rates (*spotlighting/detector not measured)")
plt.tight_layout(); plt.savefig("fig_emp_harness.png", dpi=200); plt.close()

# Table: empirical vs original logistic
tab = ["| Defence | Empirical best-family k=1 | k=3 | k=10 | Empirical search k=10 | Original logistic A3 k=10 | Compromised model (emp.) |", "|---|---|---|---|---|---|---|"]
f = lambda v: f"{100*v[0]:.1f}% ({100*v[1]:.1f}–{100*v[2]:.1f})"
for d in keys:
    tab.append(f"| {d} {names[d]} | {f(R['E1'][d]['1'])} | {f(R['E1'][d]['3'])} | {f(R['E1'][d]['10'])} | {f(R['E2'][d]['10'])} | {100*OLD['adaptive'][d]['asr_k']['10'][0]:.1f}% | {f(R['E4'][d])} |")
open("emp_table.md", "w").write("\n".join(tab))
summary = dict(best_family_G0={k: at(0, "ind", k) for k in (1, 3, 10)}, best_family_G1={k: at(1, "ind", k) for k in (1, 3, 10)},
               same_prompt_G0={k: at(0, "clu", k) for k in (1, 3, 10)}, same_prompt_G1={k: at(1, "clu", k) for k in (1, 3, 10)})
json.dump(summary, open("emp_summary.json", "w"), indent=1); print(json.dumps(summary, indent=1)); print("\n".join(tab))
