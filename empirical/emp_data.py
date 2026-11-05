"""Measured data from the Colab run (Qwen2.5-1.5B-Instruct, 174 prompts x 2 samples, quick mode).
Cell = attack level x guard; n = 4 docs x 3 tools x 2 samples = 24. Counts reconstructed from printed rates
(rate*24, verified to round exactly)."""
import numpy as np
N = 24
RATES = {0: [0.042, 0.208, 0.500, 0.042, 0.000, 0.042],
         1: [0.000, 0.167, 0.458, 0.042, 0.083, 0.000]}
K = {g: np.array([round(r * N) for r in v]) for g, v in RATES.items()}
for g in K:
    assert np.allclose(K[g] / N, RATES[g], atol=0.0006), (g, K[g])
BENIGN = {0: (28, 30), 1: (30, 30)}   # 0.933 / 1.0 on 15 prompts x 2 samples
DISPERSION = 1.24                      # reported by the notebook (1 = independent attempts)
