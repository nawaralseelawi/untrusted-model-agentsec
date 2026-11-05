#!/usr/bin/env bash
# Reproduces every simulation result, figure and the manuscript. About 6 minutes on one CPU core at SCALE=1.
# (Real-model runs need a GPU: use notebooks/realllm_agentsec_eval_v2.ipynb in Colab.)
set -e
python test_equivalence.py                   # layers off == base harness, bit-for-bit; invariants
python run_experiments.py                    # base package experiments E1-E6 -> results.json
SCALE=${SCALE:-1} python combined_experiments.py   # C1-C7 -> results_combined/ (the shipped tables were produced at SCALE=1)
python make_figures_combined.py              # -> figures_combined/
(cd empirical && python emp_stats.py && python emp_sim.py && python emp_report.py)   # measured-susceptibility re-run (Section 6.10)
(cd pilot_real_v1 && python analyze_pilot.py)      # first-pilot tables (kept for the oracle audit)
python pilot_real_v2/analyze_v2.py pilot_real_v2/data/episodes_all.csv   # Tables 15-18 (Section 6.11)
python make_paper_combined.py                # -> paper_combined.md
python make_docx.py                          # -> paper_combined.docx   (needs pandoc and python-docx)
python make_latex.py                         # -> arxiv/main.tex + references.bib
