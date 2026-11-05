import numpy as np, json
from scipy.optimize import minimize
from scipy.stats import chi2, fisher_exact, beta
from emp_data import *

def nll_cells(p, k):  # binomial log-lik per cell (constant terms dropped)
    p = np.clip(p, 1e-9, 1 - 1e-9); return -(k * np.log(p) + (N - k) * np.log(1 - p)).sum()

lv = np.arange(6); s = 0.4 * lv
k0, k1 = K[0], K[1]
kall = np.concatenate([k0, k1])
# (a) saturated: every cell free
sat = nll_cells(np.concatenate([k0, k1]) / N, kall)
# (b) the simulator's law: logit p = L0 + alpha*s - beta*G1  (3 params)
def fit_logit():
    def f(th):
        z0 = th[0] + th[1] * s; z1 = z0 - th[2]
        return nll_cells(1 / (1 + np.exp(-np.concatenate([z0, z1]))), kall)
    r = minimize(f, np.zeros(3), method="BFGS"); return r.x, r.fun
th, nl = fit_logit()
dev = 2 * (nl - sat); df = 12 - 3
# (c) level-categorical, no guard effect (6 params) vs with a common guard shift (7 params)
def fit_cat(guard):
    def f(th):
        z0 = th[:6]; z1 = z0 - (th[6] if guard else 0)
        return nll_cells(1 / (1 + np.exp(-np.concatenate([z0, z1]))), kall)
    r = minimize(f, np.full(7 if guard else 6, -1.0), method="BFGS"); return r.x, r.fun
x_g, nl_g = fit_cat(True); x_n, nl_n = fit_cat(False)
lrt_guard = 2 * (nl_n - nl_g)
# (d) monotone-in-level test: logistic with only L0+alpha (no guard) vs categorical-no-guard
def fit_lin():
    def f(th):
        z0 = th[0] + th[1] * s
        return nll_cells(1 / (1 + np.exp(-np.concatenate([z0, z0]))), kall)
    r = minimize(f, np.zeros(2), method="BFGS"); return r.x, r.fun
x_l, nl_l = fit_lin(); lrt_shape = 2 * (nl_l - nl_n)
# pooled guard effect (Fisher)
a0, a1 = k0.sum(), k1.sum(); n_ = N * 6
odds, pf = fisher_exact([[a0, n_ - a0], [a1, n_ - a1]])
out = dict(
  logistic_fit=dict(L0=th[0], alpha=th[1], beta_G1=th[2], deviance_vs_saturated=dev, df=df, p_value=float(chi2.sf(dev, df))),
  guard_effect_LRT=dict(stat=lrt_guard, df=1, p=float(chi2.sf(lrt_guard, 1)), beta_hat=float(x_g[6])),
  shape_LRT_logistic_vs_categorical=dict(stat=lrt_shape, df=4, p=float(chi2.sf(lrt_shape, 4))),
  pooled=dict(G0=f"{a0}/{n_}", G1=f"{a1}/{n_}", fisher_p=float(pf), odds_ratio=float(odds)),
  best_family=dict(G0=dict(level=int(k0.argmax()), k=int(k0.max()), n=N), G1=dict(level=int(k1.argmax()), k=int(k1.max()), n=N)),
)
for g in (0, 1):
    out[f"cell_ci_G{g}"] = [[int(k), N, *beta.ppf([.025, .975], k + .5, N - k + .5).round(3)] for k in K[g]]
json.dump(out, open("emp_stats.json", "w"), indent=1)
print(json.dumps(out, indent=1))
