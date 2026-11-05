# Pre-specified analysis plan for the real-model evaluation (notebook v2)

Written before the v2 data were seen. Applies to each model separately; models are not pooled.

## Data and unit of analysis
Episode = one agent run (task x defence x attack family x repeat). Attack episodes: 13 tasks x families x 4 repeats; benign episodes: 13 tasks x 8 (medium) or 10 (full) repeats.
Scales: `medium` = 156 attack / 104 benign episodes per defence and model; `full` = 416 attack / 130 benign.
All completed episodes are analysed; none are excluded. API or GPU errors are rerun, not dropped. Seeds and versions are in `run_config.json`.

## Primary endpoints
| # | Endpoint | Comparison | Test / interval |
|---|---|---|---|
| P1 | Attacker-aligned ASR (the attacker's goal is executed) | D7 (P3) vs D0; D6 (P2h) vs D0 | risk difference, Newcombe-Wilson 95% CI |
| P2 | Attacker-aligned obedience (the model proposes the attacker's call) | D1, D2, D3 each vs D0 | Fisher exact, Holm-adjusted over the three tests |
| P3 | Benign completion | D7 and D8 vs D0 | **non-inferiority**, margin 10 points: claim only if the lower 95% bound of (defence - D0) exceeds -10 points |

## Secondary endpoints
Persistence (ASR@k, k = 1, 3, 10; best family and uniform search; two-level bootstrap); per-task residual under D7; false-block rate; benign spontaneous violations (model's own unauthorised actions); detector flags on benign content; format-failure rates (prose, alternative schema, malformed); naive (D5) versus hardened (D6) monitor.

## Sample size
Two-proportion test, alpha 0.05 two-sided, power 0.8, baseline obedience 0.8: n per arm = 294 for a 10-point difference, 82 for 20 points, 39 for 30 points, 23 for 40 points. Non-inferiority of benign completion (baseline 0.9, margin 10 points, one-sided alpha 0.05, power 0.8): 112 per arm. `medium` powers 20-point effects on P2 but **not** P3 non-inferiority (104 benign episodes); `full` does (130).

## Validity checks
1. Oracle audit: hand-label at least 100 episodes from `label_sample.csv` (did the model propose the attacker's call? 0/1); report agreement with the automatic label and Cohen's kappa.
2. Parser sensitivity: report ASR and completion under the strict and lenient parsers.
3. Spontaneous violations: report separately; ASR counts only the attacker's goal.
4. Report the first-turn format of every model (`n_json`, `n_prose`, `n_alt`, `n_malformed`) so format differences are visible.

## What would change the conclusions
- P1: P3 or P2h admits more than the three in-policy tasks plus semantic falsification (a monitor bug or an oracle error).
- P2: a guardrail effect significant for one model and absent for another is reported as model-dependent, not averaged.
- P3: if the layered defence fails non-inferiority, the "layering is cheap" statement is withdrawn.

## Not covered
Attackers who optimise against the detector or the monitor (families 6-7 are static stacked attacks only), frontier models unless an API model is added, human reviewers, multi-agent settings.

## Pipeline
`python pilot_real_v2/analyze_v2.py results_pack.zip` then `python make_paper_combined.py && python make_docx.py`.

## Status (executed)
Run at `medium` scale on Qwen2.5-1.5B-Instruct and Qwen2.5-7B-Instruct: 156 attack episodes (13 tasks x families 0, 2, 4 x 4 repeats) and 78 benign episodes per defence and model. Results are in Section 6.11.
- P1: P3 (D7) and P2h (D6) versus D0 are reported as attacker-aligned ASR with Wilson intervals (Table 15-16 equivalents); the risk-difference intervals can be recomputed from `pilot_real_v2/data/episodes_all.csv`.
- P2: Fisher tests with Holm adjustment are stored per model in `pilot_real_v2/pilot_tables.json` (`guardrail_fisher_holm`).
- P3: non-inferiority at the 10-point margin is met by P3 and the layered defence for the 7B model and by P3 (not the layered defence) for the 1.5B model, whose benign completion is low and noisy at n = 78.
- Deviations: `medium` has 78 (not 104) benign episodes (the pack was produced by an earlier notebook setting of 6 repeats per task); the oracle audit covers two hand-labelled samples (first pilot: 97% agreement, kappa 0.94; this run: 96%, kappa 0.92); the alignment rule was re-derived from the logs (`fix_alignment`).
- Persistence method (changed after review): the attacker now picks the best attack family **for each defence** (not the best family against no defence), per-task success rates are composed over k attempts, and intervals come from a two-level bootstrap over tasks and repeats with the family re-selected in every replicate. Effect: Qwen2.5-1.5B with the detector stack rises from 5% to 38% after ten attempts; P3 for that model from 0% to 8% (0-23%).

