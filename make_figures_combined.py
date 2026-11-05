import os, numpy as np, pandas as pd, matplotlib
matplotlib.use("Agg"); import matplotlib.pyplot as plt
D = "results_combined"; F = "figures_combined"; os.makedirs(F, exist_ok=True)
plt.rcParams.update({"figure.dpi": 120, "axes.grid": True, "grid.alpha": .3, "font.size": 9})
C1 = pd.read_csv(f"{D}/C1_main.csv"); order = list(C1.key)
# fig1: harm by defence under adaptive campaign and compromised model
fig, axs = plt.subplots(1, 2, figsize=(12, 3.8)); x = np.arange(len(order))
for a, (m, t) in zip(axs, [("harm", "Severity-weighted harm (0-10)"), ("sev", "Severe-action rate (severity >= 8)")]):
    a.bar(x - .2, C1[f"A3_{m}"], .4, label="A3 adaptive, k=25"); a.bar(x + .2, C1[f"A4_{m}"], .4, label="A4 compromised model")
    a.set_xticks(x); a.set_xticklabels(order); a.set_title(t)
axs[0].legend(fontsize=8); plt.tight_layout(); plt.savefig(f"{F}/fig1_harm_by_defence.png"); plt.close()
# fig2: threshold sweep
C2 = pd.read_csv(f"{D}/C2_thresholds.csv"); fig, axs = plt.subplots(1, 3, figsize=(14, 3.8))
for a, (m, t, cm) in zip(axs, [("A4_harm", "A4 harm", "viridis_r"), ("esc", "Human escalations / benign task", "viridis_r"), ("completion", "Benign completion", "viridis")]):
    H = C2.pivot(index="human_thr", columns="taint_thr", values=m); a.imshow(H.values, cmap=cm, aspect="auto", origin="lower"); a.grid(False)
    a.set_xticks(range(H.shape[1])); a.set_xticklabels(H.columns); a.set_yticks(range(H.shape[0])); a.set_yticklabels(H.index)
    a.set_xlabel("taint_thr"); a.set_ylabel("human_thr"); a.set_title(t)
    for i in range(H.shape[0]):
        for j in range(H.shape[1]): a.text(j, i, f"{H.values[i, j]:.2f}", ha="center", va="center", color="w", fontsize=7)
plt.tight_layout(); plt.savefig(f"{F}/fig2_threshold_sweep.png"); plt.close()
# fig3: taint coverage
C3 = pd.read_csv(f"{D}/C3_taint_coverage.csv"); fig, axs = plt.subplots(1, 2, figsize=(11, 3.8))
for a, (m, t) in zip(axs, [("A4_harm", "A4 harm"), ("A4_sev", "A4 severe-action rate")]):
    for nm, g in C3.groupby("config"): a.plot(g.taint_cov, g[m], marker="o", ms=3, label=nm)
    a.set_xlabel("Taint-tracking coverage"); a.set_title(t); a.invert_xaxis()
axs[0].legend(fontsize=7); plt.tight_layout(); plt.savefig(f"{F}/fig3_taint_coverage.png"); plt.close()
# fig4: policy coverage x layering
C4 = pd.read_csv(f"{D}/C4_policy_coverage.csv"); fig, axs = plt.subplots(1, 2, figsize=(11, 3.8))
for a, (m, t) in zip(axs, [("A4_harm", "A4 harm"), ("A3_harm", "A3 harm (k=25)")]):
    for nm, g in C4.groupby("config"): a.plot(g.policy_cov, g[m], marker="o", ms=3, label=nm)
    a.set_xlabel("Policy-rule coverage c"); a.set_title(t); a.invert_xaxis()
axs[0].legend(fontsize=7); plt.tight_layout(); plt.savefig(f"{F}/fig4_policy_coverage_layering.png"); plt.close()
# fig5: approval budget
C7 = pd.read_csv(f"{D}/C7_approval_budget.csv"); C7["cap_n"] = C7.esc_cap.replace("none", 99).astype(int); fig, axs = plt.subplots(1, 3, figsize=(14, 3.6))
for a, (m, t) in zip(axs, [("A4_sev", "A4 severe-action rate"), ("A4_harm", "A4 harm"), ("completion", "Benign completion")]):
    for nm, g in C7.groupby("config"): g = g.sort_values("cap_n"); a.plot(range(len(g)), g[m], marker="o", label=nm); a.set_xticks(range(len(g))); a.set_xticklabels(["1", "2", "4", "8", "none"])
    a.set_xlabel("Approval budget per episode"); a.set_title(t)
axs[0].legend(fontsize=7); plt.tight_layout(); plt.savefig(f"{F}/fig5_approval_budget.png"); plt.close()
# fig6: pareto
fig, axs = plt.subplots(1, 2, figsize=(12, 4.2))
for a, (xm, xl) in zip(axs, [("completion", "Benign completion"), ("esc", "Human escalations per benign task")]):
    a.scatter(C1[xm], C1.A4_harm, c="C3", label="A4 compromised"); a.scatter(C1[xm], C1.A3_harm, c="C0", marker="s", label="A3 adaptive k=25")
    for r in C1.itertuples(): a.annotate(r.key, (getattr(r, xm), r.A4_harm), fontsize=7, xytext=(3, 3), textcoords="offset points")
    a.set_xlabel(xl); a.set_ylabel("Harm (lower is better)"); a.set_yscale("symlog", linthresh=.1)
axs[0].legend(fontsize=7); plt.tight_layout(); plt.savefig(f"{F}/fig6_pareto.png"); plt.close()
# fig7: susceptibility
C6 = pd.read_csv(f"{D}/C6_susceptibility.csv"); fig, ax = plt.subplots(figsize=(5.5, 3.8))
for nm, g in C6.groupby("config"): ax.plot(g.a0, g.A2_asr, marker="o", label=nm)
ax.set_xlabel("Model baseline susceptibility a0 (log-odds)"); ax.set_ylabel("ASR@1 (A2)"); ax.legend(fontsize=8); plt.tight_layout(); plt.savefig(f"{F}/fig7_susceptibility.png"); plt.close()
print("figures written:", sorted(os.listdir(F)))
