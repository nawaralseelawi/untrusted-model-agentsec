# Reference verification (IEEE-style list in the manuscript, 38 entries)

Numbers in the manuscript follow first citation (`refs.py` assigns them automatically). Status of each source:

**Checked directly against the arXiv, proceedings, publisher or NIST page (authors, title, venue, year, identifiers)**
Greshake et al. (AISec 2023); Perez & Ribeiro (2022); Zverev et al. (ICLR 2025); Nasr et al. (2025); Zhan et al. (Findings of NAACL 2025); Tramèr et al. (NeurIPS 2020);
Anderson (1972); Saltzer & Schroeder (1975); Denning (1976); Hardy (1988); Alahmadi et al. (USENIX Security 2022);
NIST SP 800-82r3; NIST AI 100-2e2025; NIST SP 800-207; InjecAgent (Findings of ACL 2024); AgentDojo (NeurIPS 2024 D&B); ASB (ICLR 2025); WASP (NeurIPS 2025 D&B);
AgentDyn (arXiv; entry uses "et al." because the author list differs between versions); Liu et al. (USENIX Security 2024); Wallace et al.; Hines et al.; CaMeL; FIDES; Progent (title as on the current arXiv version);
AgentSpec (ICSE 2026); Beurer-Kellner et al.; Newcombe (1998); Holm (1979); Narisetty et al. (2026; fetched PDF, a company preprint that is not peer reviewed).

**Checked only against an independent reference list (a 2026 preprint's bibliography)**
StruQ (USENIX Security 2025); Jia et al. (arXiv 2025); Conseca (HotOS 2025); IsolateGPT (NDSS 2025); Dennis & Van Horn (1966).

**Standard classical citations, not re-checked against a publisher page**
Wilson (1927); Cohen (1960).

**Not verified**
OWASP Top 10 for Agentic Applications 2026 (carried over from the submitted version).

## To do before submission
- For arXiv-only entries (Nasr, Wallace, Hines, CaMeL, FIDES, Progent, Beurer-Kellner, AgentDyn, Jia, Narisetty) check whether a peer-reviewed version has appeared and cite that instead.
- Add page ranges/DOIs for the two NDSS/USENIX 2025 entries from the proceedings once confirmed.
- Confirm the OWASP URL and document title.
- Re-run `python make_paper_combined.py` after editing `refs.py`; numbering updates automatically.


## Second verification pass (3-5 Nov 2026)

Every entry was re-resolved against a primary source (arXiv abstract page, publisher DOI, venue proceedings page or ACL Anthology); none is fabricated. Corrections applied in `refs.py`: [3] Nasr et al. is now cited from USENIX Security 2026 (pp. 1467-1486, usenix.org presentation page); [4] pages 7116-7132 and DOI 10.18653/v1/2025.findings-naacl.395 (ACL Anthology); [19] Hines et al. from CAMLIS 2024, CEUR-WS vol. 3920, pp. 48-62; [25] current arXiv title "Progent: Securing AI agents with privilege control" (v3); [11] exact title "OWASP Top 10 for Agentic Applications for 2026", released December 2025; [16] cited as arXiv v3 (earlier versions carry a different title); DOIs and page ranges added to [1], [12], [13], [14], [15], [20], [22], [26], [27], [28], [31], [35], [36], [37], [38]. Author lists for entries cited with "et al." ([3], [8], [14], [23], [24], [25], [29]) were taken from the arXiv or NIST title pages for the BibTeX file. Added: SecAlign (ACM CCS 2025, doi 10.1145/3719027.3744836), MELON (ICML 2025, PMLR 267, pp. 80310-80329), the Task Shield (ACL 2025, doi 10.18653/v1/2025.acl-long.1435), Fleiss 1971 (Psychol. Bull. 76(5), 378-382). The related-work sentence on Jia et al. [22] was reworded: that paper attacks the fine-tuning defences StruQ and SecAlign adaptively and evaluates detectors, it does not "do the same" as Nasr et al. for fine-tuning defences in general. No peer-reviewed version was found for [16], [18], [22], [23], [24], [25], [29], [30] as of 3 Nov 2026.
