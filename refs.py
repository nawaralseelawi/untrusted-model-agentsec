"""IEEE-style numbered references. Numbers are assigned in order of first citation in the manuscript.

Every entry is stored once, as structured fields, and rendered twice: as an IEEE text entry for the
Markdown/Word manuscript (reflist) and as a BibTeX record for the LaTeX package (bibtex). Entry keys are
the \\cite keys of the LaTeX source, so BibTeX 'unsrt' reproduces the same numbering. Verification status
per entry is recorded in REFERENCES_VERIFICATION.md.

Field conventions: 'authors' is a list of IEEE-abbreviated names ("K. Greshake"); 'etal' marks an entry
cited with 'et al.' in the text while 'authors' holds the full list for BibTeX; 'kind' selects the IEEE
pattern: conf (paper in proceedings), journal, report, online.
"""

REFS = {
 "greshake": dict(kind="conf", authors=["K. Greshake", "S. Abdelnabi", "S. Mishra", "C. Endres", "T. Holz", "M. Fritz"],
    title="Not what you've signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection",
    book="Proc. 16th ACM Workshop Artif. Intell. Secur. (AISec)", address="Copenhagen, Denmark", month="Nov.", year=2023, pages="79–90",
    doi="10.1145/3605764.3623985", arxiv="2302.12173"),
 "perez": dict(kind="conf", authors=["F. Perez", "I. Ribeiro"], title="Ignore previous prompt: Attack techniques for language models",
    book="NeurIPS 2022 Workshop ML Safety", year=2022, arxiv="2211.09527"),
 "zverev": dict(kind="conf", authors=["E. Zverev", "S. Abdelnabi", "S. Tabesh", "M. Fritz", "C. H. Lampert"],
    title="Can LLMs separate instructions from data? And what do we even mean by that?",
    book="Proc. Int. Conf. Learn. Represent. (ICLR)", year=2025, arxiv="2403.06833"),
 "nasr": dict(kind="conf", authors=["M. Nasr", "N. Carlini", "C. Sitawarin", "S. V. Schulhoff", "J. Hayes", "M. Ilie", "J. Pluto", "S. Song",
    "H. Chaudhari", "I. Shumailov", "A. Thakurta", "K. Y. Xiao", "A. Terzis", "F. Tramèr"], etal=True,
    title="The attacker moves second: Stronger adaptive attacks bypass defenses against LLM jailbreaks and prompt injections",
    book="Proc. 35th USENIX Secur. Symp.", address="Baltimore, MD, USA", month="Aug.", year=2026, pages="1467–1486", arxiv="2510.09023"),
 "zhan25": dict(kind="conf", authors=["Q. Zhan", "R. Fang", "H. S. Panchal", "D. Kang"],
    title="Adaptive attacks break defenses against indirect prompt injection attacks on LLM agents",
    book="Findings Assoc. Comput. Linguistics: NAACL 2025", address="Albuquerque, NM, USA", year=2025, pages="7116–7132",
    doi="10.18653/v1/2025.findings-naacl.395"),
 "anderson": dict(kind="report", authors=["J. P. Anderson"], title="Computer security technology planning study",
    inst="USAF Electron. Syst. Div.", address="Bedford, MA, USA", number="Tech. Rep. ESD-TR-73-51", month="Oct.", year=1972),
 "saltzer": dict(kind="journal", authors=["J. H. Saltzer", "M. D. Schroeder"], title="The protection of information in computer systems",
    journal="Proc. IEEE", volume="63", number="9", pages="1278–1308", month="Sep.", year=1975, doi="10.1109/PROC.1975.9939"),
 "alahmadi": dict(kind="conf", authors=["B. A. Alahmadi", "L. Axon", "I. Martinovic"],
    title="99% false positives: A qualitative study of SOC analysts' perspectives on security alarms",
    book="Proc. 31st USENIX Secur. Symp.", address="Boston, MA, USA", year=2022, pages="2783–2800"),
 "nist80082": dict(kind="report", authors=["K. Stouffer", "M. Pease", "C. Tang", "T. Zimmerman", "V. Pillitteri", "S. Lightman", "A. Hahn",
    "S. Saravia", "A. Sherule", "M. Thompson"], etal=True, title="Guide to operational technology (OT) security",
    inst="Nat. Inst. Standards Technol.", address="Gaithersburg, MD, USA", number="NIST Spec. Publ. 800-82r3", month="Sep.", year=2023,
    doi="10.6028/NIST.SP.800-82r3"),
 "nist100": dict(kind="report", authors=["A. Vassilev", "A. Oprea", "A. Fordyce", "H. Anderson", "X. Davies", "M. Hamin"],
    title="Adversarial machine learning: A taxonomy and terminology of attacks and mitigations",
    inst="Nat. Inst. Standards Technol.", address="Gaithersburg, MD, USA", number="NIST AI 100-2e2025", month="Mar.", year=2025,
    doi="10.6028/NIST.AI.100-2e2025"),
 "owasp": dict(kind="online", org="OWASP Gen AI Security Project", title="OWASP Top 10 for agentic applications for 2026",
    month="Dec.", year=2025, url="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"),
 "injecagent": dict(kind="conf", authors=["Q. Zhan", "Z. Liang", "Z. Ying", "D. Kang"],
    title="InjecAgent: Benchmarking indirect prompt injections in tool-integrated large language model agents",
    book="Findings Assoc. Comput. Linguistics: ACL 2024", address="Bangkok, Thailand", year=2024, pages="10471–10506",
    doi="10.18653/v1/2024.findings-acl.624"),
 "agentdojo": dict(kind="conf", authors=["E. Debenedetti", "J. Zhang", "M. Balunović", "L. Beurer-Kellner", "M. Fischer", "F. Tramèr"],
    title="AgentDojo: A dynamic environment to evaluate prompt injection attacks and defenses for LLM agents",
    book="Adv. Neural Inf. Process. Syst. (NeurIPS), Datasets and Benchmarks Track", volume="37", year=2024, pages="82895–82920",
    doi="10.52202/079017-2636", arxiv="2406.13352"),
 "asb": dict(kind="conf", authors=["H. Zhang", "J. Huang", "K. Mei", "Y. Yao", "Z. Wang", "C. Zhan", "H. Wang", "Y. Zhang"], etal=True,
    title="Agent security bench (ASB): Formalizing and benchmarking attacks and defenses in LLM-based agents",
    book="Proc. Int. Conf. Learn. Represent. (ICLR)", year=2025, pages="35331–35366", arxiv="2410.02644"),
 "wasp": dict(kind="conf", authors=["I. Evtimov", "A. Zharmagambetov", "A. Grattafiori", "C. Guo", "K. Chaudhuri"],
    title="WASP: Benchmarking web agent security against prompt injection attacks",
    book="Adv. Neural Inf. Process. Syst. (NeurIPS), Datasets and Benchmarks Track", volume="38", year=2025,
    doi="10.52202/085713-0666", arxiv="2504.18575"),
 "agentdyn": dict(kind="preprint", authors=["H. Li", "R. Wen", "S. Shi", "N. Zhang", "Y. Vorobeychik", "C. Xiao"],
    title="AgentDyn: Are your agent security defenses deployable in real-world dynamic environments?", arxiv="2602.03117v3", year=2026),
 "liu24": dict(kind="conf", authors=["Y. Liu", "Y. Jia", "R. Geng", "J. Jia", "N. Z. Gong"],
    title="Formalizing and benchmarking prompt injection attacks and defenses",
    book="Proc. 33rd USENIX Secur. Symp.", address="Philadelphia, PA, USA", year=2024, pages="1831–1847"),
 "wallace": dict(kind="preprint", authors=["E. Wallace", "K. Xiao", "R. Leike", "L. Weng", "J. Heidecke", "A. Beutel"],
    title="The instruction hierarchy: Training LLMs to prioritize privileged instructions", arxiv="2404.13208", year=2024),
 "hines": dict(kind="conf", authors=["K. Hines", "G. Lopez", "M. Hall", "F. Zarfati", "Y. Zunger", "E. Kiciman"],
    title="Defending against indirect prompt injection attacks with spotlighting",
    book="Proc. Conf. Appl. Mach. Learn. Inf. Secur. (CAMLIS 2024), CEUR Workshop Proc.", volume="3920", year=2025, pages="48–62",
    arxiv="2403.14720"),
 "struq": dict(kind="conf", authors=["S. Chen", "J. Piet", "C. Sitawarin", "D. Wagner"],
    title="StruQ: Defending against prompt injection with structured queries",
    book="Proc. 34th USENIX Secur. Symp.", address="Seattle, WA, USA", month="Aug.", year=2025, pages="2383–2400", arxiv="2402.06363"),
 "secalign": dict(kind="conf", authors=["S. Chen", "A. Zharmagambetov", "S. Mahloujifar", "K. Chaudhuri", "D. Wagner", "C. Guo"],
    title="SecAlign: Defending against prompt injection with preference optimization",
    book="Proc. ACM SIGSAC Conf. Comput. Commun. Secur. (CCS)", year=2025, doi="10.1145/3719027.3744836", arxiv="2410.05451"),
 "jia25": dict(kind="preprint", authors=["Y. Jia", "Z. Shao", "Y. Liu", "J. Jia", "D. Song", "N. Z. Gong"],
    title="A critical evaluation of defenses against prompt injection attacks", arxiv="2505.18333", year=2025),
 "tramer": dict(kind="conf", authors=["F. Tramèr", "N. Carlini", "W. Brendel", "A. Madry"], title="On adaptive attacks to adversarial example defenses",
    book="Adv. Neural Inf. Process. Syst. (NeurIPS)", volume="33", year=2020, pages="1633–1645", arxiv="2002.08347"),
 "camel": dict(kind="preprint", authors=["E. Debenedetti", "I. Shumailov", "T. Fan", "J. Hayes", "N. Carlini", "D. Fabian", "C. Kern", "C. Shi",
    "A. Terzis", "F. Tramèr"], etal=True, title="Defeating prompt injections by design", arxiv="2503.18813", year=2025),
 "fides": dict(kind="preprint", authors=["M. Costa", "B. Köpf", "A. Kolluri", "A. Paverd", "M. Russinovich", "A. Salem", "S. Tople", "L. Wutschitz",
    "S. Zanella-Béguelin"], etal=True, title="Securing AI agents with information-flow control", arxiv="2505.23643", year=2025),
 "progent": dict(kind="preprint", authors=["T. Shi", "J. He", "Z. Wang", "H. Li", "L. Wu", "W. Guo", "D. Song"], etal=True,
    title="Progent: Securing AI agents with privilege control", arxiv="2504.11703", year=2025),
 "agentspec": dict(kind="conf", authors=["H. Wang", "C. M. Poskitt", "J. Sun"],
    title="AgentSpec: Customizable runtime enforcement for safe and reliable LLM agents",
    book="Proc. 48th IEEE/ACM Int. Conf. Softw. Eng. (ICSE)", address="Rio de Janeiro, Brazil", month="Apr.", year=2026, pages="2938–2950",
    doi="10.1145/3744916.3764546", arxiv="2503.18666"),
 "conseca": dict(kind="conf", authors=["L. Tsai", "E. Bagdasarian"], title="Contextual agent security: A policy for every purpose",
    book="Proc. Workshop Hot Topics Oper. Syst. (HotOS)", address="Banff, AB, Canada", year=2025, pages="8–17",
    doi="10.1145/3713082.3730378", arxiv="2501.17070"),
 "isolategpt": dict(kind="conf", authors=["Y. Wu", "F. Roesner", "T. Kohno", "N. Zhang", "U. Iqbal"],
    title="IsolateGPT: An execution isolation architecture for LLM-based agentic systems",
    book="Proc. Netw. Distrib. Syst. Secur. Symp. (NDSS)", address="San Diego, CA, USA", year=2025, doi="10.14722/ndss.2025.241131",
    arxiv="2403.04960"),
 "melon": dict(kind="conf", authors=["K. Zhu", "X. Yang", "J. Wang", "W. Guo", "W. Y. Wang"],
    title="MELON: Provable defense against indirect prompt injection attacks in AI agents",
    book="Proc. 42nd Int. Conf. Mach. Learn. (ICML), Proc. Mach. Learn. Res.", volume="267", year=2025, pages="80310–80329", arxiv="2502.05174"),
 "taskshield": dict(kind="conf", authors=["F. Jia", "T. Wu", "X. Qin", "A. Squicciarini"],
    title="The Task Shield: Enforcing task alignment to defend against indirect prompt injection in LLM agents",
    book="Proc. 63rd Annu. Meeting Assoc. Comput. Linguistics (ACL)", address="Vienna, Austria", year=2025, pages="29680–29697",
    doi="10.18653/v1/2025.acl-long.1435", arxiv="2412.16682"),
 "patterns": dict(kind="preprint", authors=["L. Beurer-Kellner", "B. Buesser", "A.-M. Creţu", "E. Debenedetti", "D. Dobos", "D. Fabian", "M. Fischer",
    "D. Froelicher", "K. Grosse", "D. Naeff", "E. Ozoani", "A. Paverd", "F. Tramèr", "V. Volhejn"], etal=True,
    title="Design patterns for securing LLM agents against prompt injections", arxiv="2506.08837", year=2025),
 "narisetty": dict(kind="preprint", authors=["P. Narisetty", "S. N. B. Kore", "U. K. R. Kattamanchi", "J. Kumarapu"],
    title="Adaptive evaluation of out-of-band defenses against prompt injection in LLM agents", arxiv="2606.26479", month="Jun.", year=2026,
    note="preprint, not peer reviewed"),
 "dennis": dict(kind="journal", authors=["J. B. Dennis", "E. C. Van Horn"], title="Programming semantics for multiprogrammed computations",
    journal="Commun. ACM", volume="9", number="3", pages="143–155", month="Mar.", year=1966, doi="10.1145/365230.365252"),
 "hardy": dict(kind="journal", authors=["N. Hardy"], title="The confused deputy (or why capabilities might have been invented)",
    journal="ACM SIGOPS Oper. Syst. Rev.", volume="22", number="4", pages="36–38", month="Oct.", year=1988, doi="10.1145/54289.871709"),
 "denning": dict(kind="journal", authors=["D. E. Denning"], title="A lattice model of secure information flow",
    journal="Commun. ACM", volume="19", number="5", pages="236–243", month="May", year=1976, doi="10.1145/360051.360056"),
 "nist207": dict(kind="report", authors=["S. Rose", "O. Borchert", "S. Mitchell", "S. Connelly"], title="Zero trust architecture",
    inst="Nat. Inst. Standards Technol.", address="Gaithersburg, MD, USA", number="NIST Spec. Publ. 800-207", month="Aug.", year=2020,
    doi="10.6028/NIST.SP.800-207"),
 "wilson": dict(kind="journal", authors=["E. B. Wilson"], title="Probable inference, the law of succession, and statistical inference",
    journal="J. Amer. Statist. Assoc.", volume="22", number="158", pages="209–212", month="Jun.", year=1927, doi="10.1080/01621459.1927.10502953"),
 "newcombe": dict(kind="journal", authors=["R. G. Newcombe"],
    title="Interval estimation for the difference between independent proportions: Comparison of eleven methods",
    journal="Statist. Med.", volume="17", number="8", pages="873–890", month="Apr.", year=1998,
    doi="10.1002/(SICI)1097-0258(19980430)17:8<873::AID-SIM779>3.0.CO;2-I"),
 "holm": dict(kind="journal", authors=["S. Holm"], title="A simple sequentially rejective multiple test procedure",
    journal="Scand. J. Statist.", volume="6", number="2", pages="65–70", year=1979),
 "cohen": dict(kind="journal", authors=["J. Cohen"], title="A coefficient of agreement for nominal scales",
    journal="Educ. Psychol. Meas.", volume="20", number="1", pages="37–46", month="Apr.", year=1960, doi="10.1177/001316446002000104"),
 "fleiss": dict(kind="journal", authors=["J. L. Fleiss"], title="Measuring nominal scale agreement among many raters",
    journal="Psychol. Bull.", volume="76", number="5", pages="378–382", year=1971, doi="10.1037/h0031619"),
}


def _names(e):
    a = e.get("authors")
    if not a: return e["org"]
    if e.get("etal"): return a[0] + " *et al.*"
    if len(a) == 1: return a[0]
    if len(a) == 2: return a[0] + " and " + a[1]
    return ", ".join(a[:-1]) + ", and " + a[-1]


def _title(e):
    t = e["title"]
    return "“" + t + ("”" if t.endswith("?") else ",”")   # IEEE: title in quotes, comma inside (none after a question mark)


def render(e):
    """IEEE text entry (Markdown italics for container titles)."""
    tail = []
    k = e["kind"]
    if k == "conf":
        s = f"in *{e['book']}*"
        if e.get("volume"): s += f", vol. {e['volume']}"
        if e.get("address"): s += f", {e['address']}"
        s += ", " + (e["month"] + " " if e.get("month") else "") + str(e["year"])
        if e.get("pages"): s += f", pp. {e['pages']}"
        tail.append(s)
    elif k == "journal":
        s = f"*{e['journal']}*, vol. {e['volume']}"
        if e.get("number"): s += f", no. {e['number']}"
        s += f", pp. {e['pages']}, " + (e["month"] + " " if e.get("month") else "") + str(e["year"])
        tail.append(s)
    elif k == "report":
        tail.append(f"{e['inst']}, {e['address']}, {e['number']}, " + (e["month"] + " " if e.get("month") else "") + str(e["year"]))
    elif k == "preprint":
        tail.append(f"arXiv:{e['arxiv']}, " + (e["month"] + " " if e.get("month") else "") + str(e["year"]) + (f" ({e['note']})" if e.get("note") else ""))
    elif k == "online":
        tail.append((e["month"] + " " if e.get("month") else "") + f"{e['year']}. [Online]. Available: {e['url']}")
    if e.get("doi"): tail.append(f"doi: {e['doi']}")
    if e.get("arxiv") and k != "preprint": tail.append(f"arXiv:{e['arxiv']}")
    return f"{_names(e)}, {_title(e)} " + ", ".join(tail) + "."


def _bib_authors(e):
    if not e.get("authors"): return None
    return " and ".join(a.replace("*", "") for a in e["authors"])


def bibtex(key, e):
    f = {}
    k = e["kind"]
    typ = {"conf": "inproceedings", "journal": "article", "report": "techreport", "preprint": "misc", "online": "misc"}[k]
    f["title"] = "{{" + e["title"].replace("%", "\\%").replace("&", "\\&") + "}}"
    if _bib_authors(e): f["author"] = _bib_authors(e)
    else: f["author"] = "{{" + e["org"] + "}}"
    f["year"] = str(e["year"])
    if e.get("month"): f["month"] = e["month"].rstrip(".").lower()
    if k == "conf":
        f["booktitle"] = e["book"]
        if e.get("volume"): f["volume"] = e["volume"]
        if e.get("address"): f["address"] = e["address"]
    elif k == "journal":
        f["journal"] = e["journal"]; f["volume"] = e["volume"]
        if e.get("number"): f["number"] = e["number"]
    elif k == "report":
        f["institution"] = e["inst"]; f["address"] = e["address"]; f["number"] = e["number"]
    elif k == "preprint":
        f["howpublished"] = f"arXiv:{e['arxiv']}"
        if e.get("note"): f["note"] = e["note"]
    elif k == "online":
        f["howpublished"] = "\\url{" + e["url"] + "}"; f["note"] = "[Online]"
    if e.get("pages"): f["pages"] = e["pages"].replace("–", "--")
    extra = []
    if e.get("doi"): f["doi"] = e["doi"]; extra.append("doi: " + e["doi"].replace("%", "\\%").replace("<", "\\textless{}").replace(">", "\\textgreater{}"))
    if e.get("arxiv") and k != "preprint": extra.append(f"arXiv:{e['arxiv']}")
    if extra: f["note"] = ", ".join(([f["note"]] if f.get("note") else []) + extra)   # 'unsrt' prints note but not doi
    body = ",\n".join(f"  {a} = {v}" if v.startswith("{{") else f"  {a} = {{{v}}}" for a, v in f.items())
    return f"@{typ}{{{key},\n{body}\n}}"


class Cite:
    def __init__(self): self.order = []
    def num(self, k):
        if k not in REFS: raise KeyError(k)
        if k not in self.order: self.order.append(k)
        return self.order.index(k) + 1
    def cite(self, *keys):
        ns = sorted({self.num(k) for k in keys}); out = []; i = 0
        while i < len(ns):                                   # IEEE: [3]-[5] for runs of three or more
            j = i
            while j + 1 < len(ns) and ns[j + 1] == ns[j] + 1: j += 1
            if j - i >= 2: out.append(f"[{ns[i]}]–[{ns[j]}]")
            else: out += [f"[{n}]" for n in ns[i:j + 1]]
            i = j + 1
        return ", ".join(out)
    def reflist(self):
        return "\n\n".join(f"[{i}] {render(REFS[k])}" for i, k in enumerate(self.order, 1))
    def bib(self):
        return "\n\n".join(bibtex(k, REFS[k]) for k in self.order) + "\n"
    def unused(self): return [k for k in REFS if k not in self.order]
