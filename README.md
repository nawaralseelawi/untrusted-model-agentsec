# Treating the Model as an Untrusted Component

Code, data, results and manuscript sources for:

> Mustafa S. Aljumaily, Nawar S. Alseelawi and Raghad Alshabandar. "Treating the Model as an Untrusted Component: Deterministic Policy Enforcement, Human Approval and Taint Tracking Against Prompt Injection in Tool-Using Agents, with Validation on Open-Weights Models". arXiv preprint, 2026 (arXiv identifier and link added at announcement; release `v1.0.0` corresponds to version 1 of the preprint).

Authors: Mustafa S. Aljumaily (ICT Department, Missan Oil Company, Iraq; corresponding author, mustafasadiq0@gmail.com; ORCID 0000-0002-7886-9537), Nawar S. Alseelawi (Department of Electrical Engineering, College of Engineering, University of Misan, Iraq; nawar.alseelawi@uomisan.edu.iq; ORCID 0000-0001-5739-2349) and Raghad Alshabandar (National Center for Artificial Intelligence, Baghdad, Iraq; raghadalshabandar@outlook.com; ORCID 0000-0002-1393-3761).

Question: can deterministic enforcement outside the model (reference monitors, taint tracking, bounded human approval) protect tool-using LLM agents against prompt injection better than in-prompt guardrails, and what are its limits?

The package merges two independent implementations: an executable harness (real tools, an effect-based oracle independent of every defence, naive and hardened monitors, argument-fuzzing attackers) and an abstract Monte Carlo study (severity-weighted harm, human approval with fatigue, taint-tracking failure, real-model calibration). **The language model is simulated unless the real-model calibration has been run; see the manuscript, Sections 6.10 and 8.**

## Contents

| Path | Purpose |
|---|---|
| `paper_combined.md` / `.docx` / `.pdf` | Manuscript, regenerated from the results by `make_paper_combined.py` (references verified against arXiv / publisher pages) |
| `agentsec_sim.py`, `run_experiments.py`, `results.json` | Executable harness (tools, effect-based oracle, four monitors, fuzzing attackers) and experiments E1-E6 |
| `agentsec_plus.py` | Extensions: severity-weighted harm, human approval (fatigue, spamming, budget), taint tracking with coverage failure. With the layers off it reproduces the base harness exactly |
| `combined_experiments.py` | Experiments C1-C7 -> `results_combined/` |
| `empirical/` | Re-run of the harness with **measured** per-family obedience from a real model (Section 6.10): statistics, simulation, report |
| `pilot_real_v1/` | First end-to-end real-model pilot (Qwen2.5-1.5B and 7B): raw log in `data/`, `analyze_pilot.py` regenerates its tables; kept because the first oracle-audit sample was drawn from it |
| `notebooks/realllm_agentsec_eval_v2.ipynb` | **Colab notebook to repeat the end-to-end real-model evaluation at scale** (writes `results_pack.zip`) |
| `notebooks/combined_study.ipynb` | Self-contained notebook for the simulation study (Colab / Jupyter / Anaconda) |
| `calibrate_real_model.py`, `run_calibrated_sim.py` | Earlier susceptibility calibration (superseded by the notebook above; kept for Section 6.10) |
| `test_equivalence.py` | Invariant tests |
| `make_figures_combined.py`, `make_paper_combined.py`, `make_docx.py` | Figures and manuscript regenerated from the results |
| `abstract_model/` | The separately built abstract Monte Carlo study (notebook, script, results E1-E10) |
| `SUBMISSION_CHECKLIST.md` | Items completed by the authors before submission (statements, repository, venue format) |
| `ANALYSIS_PLAN.md` | Pre-specified endpoints, sample-size justification and validity checks for the real-model evaluation |
| `pilot_real_v2/analyze_v2.py` | Turns a notebook `results_pack.zip` into tables/figure; the paper then updates itself (`python make_paper_combined.py`) |
| `pilot_real_v2/label_audit.py` | Hand-labelling helper: builds a blind label sheet and computes agreement / Cohen's kappa against the automatic oracle label |
| `refs.py`, `REFERENCES_VERIFICATION.md` | Reference engine (42 structured entries, rendered as IEEE text and as `references.bib`) and the verification status of each |
| `make_latex.py`, `arxiv/` | arXiv LaTeX package built from the same generator (pdflatex + BibTeX unsrt) |
| `pilot_real_v2/oracle_audit/` | Two-rater oracle audit: blind sheets of rater B, the code-to-row key, the scoring script and its outputs (`oracle_audit_two_raters.json`, `oracle_audit_disagreements.csv`) |
| `pilot_section.py` | Builds the real-model passages of the manuscript from the JSON tables |
| `CHANGELOG.md` | What changed since the first combined draft (read this first) |

## Real-model evaluation

Open `notebooks/realllm_agentsec_eval_v2.ipynb` in Colab (GPU), edit the model list in cell 3, run all, and keep `results_pack.zip`. `medium` takes about an hour for a 1.5B model and 2-3 hours for a 7B model on a T4. Then run `python pilot_real_v2/analyze_v2.py results_pack.zip` and `python make_paper_combined.py && python make_docx.py` (see `ANALYSIS_PLAN.md`). The notebook reports attacker-aligned obedience, attack success by defence, benign utility, persistence and a label sample for checking the oracle by hand.

## Status and known limitations

The language model is simulated except where Sections 6.10 and 6.11 report real runs. The end-to-end evaluation covers two open-weights models (Qwen2.5-1.5B and 7B; 156 attack and 78 benign episodes per defence and model, static attack families). Other limits: per-tool (not per-content) severity; human reviewer modelled with a decaying miss rate; session-level taint; 13 author-written tasks; oracle/policy coupling for P3. See Section 8 of the manuscript.

## Reproduce the paper's numbers

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python test_equivalence.py                     # invariants (3,510 identical episodes, A4 independence, monotonicity)
python run_experiments.py                      # E1-E6 -> results.json (~2 min)
SCALE=1 python combined_experiments.py         # C1-C7 -> results_combined/ (~2 min; the shipped CSVs were produced at SCALE=1)
python make_figures_combined.py                # figures_combined/
(cd abstract_model && python untrusted_model_simulation.py)   # abstract study E1-E9 -> abstract_model/results/
(cd empirical && python emp_stats.py && python emp_sim.py && python emp_report.py)   # Section 6.10
python pilot_real_v2/analyze_v2.py pilot_real_v2/data/episodes_all.csv   # Tables 15-18 from the raw real-model log
python make_paper_combined.py                  # paper_combined.md (every number read from the files above)
python make_docx.py                            # paper_combined.docx (needs pandoc + python-docx)
python make_latex.py                           # arxiv/main.tex + references.bib (pdflatex + bibtex)
```

Expected output: `results_combined/C1_main.csv` reproduces Table 2 and `results_combined/C2_thresholds.csv` to `C7_approval_budget.csv` Tables 3-12 byte-for-byte; `pilot_real_v2/pilot_tables.json` reproduces Tables 15-18; `abstract_model/results/` and `empirical/` reproduce Tables 13-14. Seeds are fixed (20261026 for the simulations, 20261027 for the real-model runs, 20261103 for the oracle-audit sheet shuffling). Runtime: about 6 minutes on one CPU core for everything except the real-model runs, which need a GPU (Colab notebook `notebooks/realllm_agentsec_eval_v2.ipynb`, 1-3 hours per model on a T4).

## Two-rater oracle audit

```bash
cd pilot_real_v2/oracle_audit
python -I score_second_rater.py ../.. KEY.csv sheet_V1_raterB.xlsx sheet_V2_raterB.xlsx
```

prints the agreement and Cohen's kappa figures of Section 6.11 (rater B vs oracle, rater B vs rater A, rater A vs oracle, Fleiss' kappa) and writes `oracle_audit_disagreements.csv`. `build_blind_sheets.py` regenerates rater B's blind sheets from the samples with the same seed.

## Data

Every task, tool, document and data item in the study is synthetic; no company or third-party data is used. The raw real-model logs (`pilot_real_v1/data/`, `pilot_real_v2/data/`) are the complete outputs of the Colab runs and are committed in full.

## Citation

```bibtex
@misc{aljumaily2026untrusted,
  title         = {Treating the Model as an Untrusted Component: Deterministic Policy Enforcement, Human Approval and Taint Tracking Against Prompt Injection in Tool-Using Agents, with Validation on Open-Weights Models},
  author        = {Aljumaily, Mustafa S. and Alseelawi, Nawar S. and Alshabandar, Raghad},
  year          = {2026},
  note          = {arXiv preprint; identifier added at announcement}
}
```

## Licence

MIT. See `LICENSE`.

## Contact

Mustafa S. Aljumaily (corresponding author), mustafasadiq0@gmail.com; Nawar S. Alseelawi, University of Misan, nawar.alseelawi@uomisan.edu.iq; Raghad Alshabandar, National Center for Artificial Intelligence, raghadalshabandar@outlook.com.
