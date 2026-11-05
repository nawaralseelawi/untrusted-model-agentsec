# Submission checklist (items only the author can complete)

## Must be completed or confirmed
- [ ] **Competing interests statement**: drafted as "none" in Declarations; both authors to confirm.
- [ ] **Funding** statement: drafted as "no external funding"; both authors to confirm.
- [ ] **Corresponding author e-mail and ORCID**; confirm the affiliation line (ICT Department, Missan Oil Company).
- [ ] **Missan Oil Company approval to publish** (written confirmation, and whether the affiliation wording or an acknowledgement is required).
- [x] **Independent second labeller** (done 4 Nov 2026, Section 6.11; `pilot_real_v2/oracle_audit/`) for the two 100-row oracle samples: `python pilot_real_v2/label_audit.py compare sheet_A.xlsx sheet_B.xlsx pilot_real_v2/data/label_sample_v2run.csv` gives the inter-rater kappa to add to Section 6.11.
- [x] **Original calibration log** (not retained; stated in Section 6.10) (Section 6.10): if the raw Colab output of the six-level calibration run still exists, add it to `empirical/` and replace the reconstructed counts in `empirical/emp_data.py`; otherwise the paper already states that the counts were reconstructed.
- [ ] **AI-assistance disclosure** (Declarations): confirm the wording matches the target venue's policy and what you actually did.
- [ ] **Repository**: Declarations now name github.com/nawaralseelawi/untrusted-model-agentsec (release v1.0.0 at arXiv announcement); create the repository before upload.
- [ ] **Ethics / responsible-disclosure statement** if the venue requires one (the manuscript states that all tools are inert simulations and no deployed product's vulnerability is disclosed).

## Strongly recommended before submission
- [x] `medium`-scale run of `notebooks/realllm_agentsec_eval_v2.ipynb` on Qwen2.5-1.5B and 7B incorporated (Section 6.11). Optional: repeat at `full` scale (more attack families, 130 benign episodes) with `python pilot_real_v2/analyze_v2.py results_pack.zip && python make_paper_combined.py && python make_docx.py` (the abstract, Section 6.11, discussion and limitation update themselves).
- [x] Oracle audit done on two samples of 100 rows (97% and 96% agreement; Section 6.11). Optional: re-check rows 36 and 51 of `pilot_real_v1/data/human_labels_pilot.csv` and rows 21 and 40 of `pilot_real_v2/data/human_labels_v2run.csv` (the proposed call contains the attacker's payload but is labelled 0), then rerun `analyze_pilot.py` and `analyze_v2.py`.
- [ ] For any further run, hand-label its new 100-row sample (oracle audit, see `ANALYSIS_PLAN.md`): `python pilot_real_v2/label_audit.py blind <label_sample.csv>`, fill the last column (1 = the model proposed the attacker's call, 0 = it did not), then `python pilot_real_v2/label_audit.py audit label_sheet.csv <label_sample.csv>`; report agreement and Cohen's kappa. The first pilot's sample is in `pilot_real_v1/data/label_sample.csv` and can be labelled now.
- [ ] Add one API model in the notebook (cell 3) to cover a stronger tier (strongly recommended: all real-model evidence is currently from open-weights models of 7B or less).
- [ ] Re-read Section 6.11 after regeneration: the findings text is data-conditional but the interpretation should be reviewed.

## Format
- [ ] Choose the venue and reformat (template, page limit, reference style, anonymisation for double-blind review). The manuscript is currently about 17 pages with 18 tables and 8 figures; most venues will want Sections 6.5-6.7 shortened or moved to an appendix.
- [ ] Cover letter.

## Verified already
- 12 references checked against arXiv / publisher pages (authors, titles, venues, identifiers).
- Tests pass (`test_equivalence.py`); all tables and figures regenerate from the code.
- Single-chance bug fixed and documented in `CHANGELOG.md`.
