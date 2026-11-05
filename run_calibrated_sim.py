#!/usr/bin/env python3
"""Calibration -> simulation: fit the susceptibility law from a (stub or real) model, then re-run key defences with the fitted Params."""
import sys, os
import numpy as np, pandas as pd, matplotlib
matplotlib.use("Agg"); import matplotlib.pyplot as plt
from agentsec_plus import *
from calibrate_real_model import run_calibration, to_params

mode = sys.argv[1] if len(sys.argv) > 1 else "stub"
model = sys.argv[2] if len(sys.argv) > 2 else "Qwen/Qwen2.5-1.5B-Instruct"
A, util, fit, guards = run_calibration(mode, model, quick=True)
print(A.pivot_table(index="level", columns="guard", values="y").round(3)); print("benign success:", {k: round(v, 3) for k, v in util.items()}); print(fit.round(3).to_string(index=False))
Pfit = to_params(fit, util); P0 = Params()
print({k: round(getattr(Pfit, k), 3) for k in ("a0", "b", "delta_prompt", "delta_spot", "overref_prompt", "overref_spot")})
rows = []
for tag, P in [("assumed", P0), (f"calibrated ({mode})", Pfit)]:
    for key in ["D0", "D1", "D2", "D3", "D7", "H2"]:
        r = evaluate(BY_KEY[key], P, HParams(), n_iid=500, n_camp=60, n_a4=100, n_ben=500, tag="cal"); r["params"] = tag; rows.append(r)
C = pd.DataFrame(rows); C.to_csv(f"results_combined/calibrated_sim_{mode}.csv", index=False)
print(C.pivot(index="key", columns="params", values="A2_asr").round(3)); print(C.pivot(index="key", columns="params", values="A3_harm").round(2)); print(C.pivot(index="key", columns="params", values="A4_harm").round(2))
fig, axs = plt.subplots(1, 2, figsize=(11, 3.9)); sg = np.linspace(0, 2, 50); th = dict(zip(fit.param, fit.estimate))
for g in guards:
    sub = A[A.guard == g].groupby("level").y.mean()
    axs[0].plot(sub.index * .4, sub.values, "o", label=f"observed G{g}")
    z = th["a0"] + th["b"] * sg - (0 if g == 0 else th["delta_prompt" if g == 1 else "delta_spot"]); axs[0].plot(sg, 1 / (1 + np.exp(-z)), "--")
axs[0].set_xlabel("Attack strength s"); axs[0].set_ylabel("P(model obeys injection)"); axs[0].set_title(f"Calibration ({mode}): observed vs fitted"); axs[0].legend(fontsize=7)
piv = C.pivot(index="key", columns="params", values="A2_asr"); piv.plot.bar(ax=axs[1], rot=0); axs[1].set_ylabel("ASR@1 (A2)"); axs[1].set_title("Simulator: assumed vs calibrated")
plt.tight_layout(); os.makedirs("figures_combined", exist_ok=True); plt.savefig(f"figures_combined/fig8_calibration_{mode}.png")
