#!/usr/bin/env python3
"""Build the arXiv LaTeX package from the generated manuscript.

Steps: (1) CITE_MODE=latex make_paper_combined.py writes _paper_cite.md (citation keys kept as markers) and
references.bib (BibTeX records in order of first citation, so 'unsrt' reproduces the Markdown numbering);
(2) tables, figures and headings are rewritten for LaTeX; (3) pandoc converts the body; (4) the article
is assembled around the project template (pdflatex + BibTeX unsrt) in arxiv/ with flattened figure names.

Usage:  python make_latex.py          -> arxiv/main.tex, arxiv/references.bib, arxiv/fig*.png
        (cd arxiv && pdflatex main && bibtex main && pdflatex main && pdflatex main)
"""
import os, re, shutil, subprocess

OUT = "arxiv"
os.makedirs(OUT, exist_ok=True)
subprocess.run(["python", "make_paper_combined.py"], check=True, env=dict(os.environ, CITE_MODE="latex"))
md = open("_paper_cite.md", encoding="utf-8").read()

# ---- 1. split the front matter (title, author block, abstract, keywords) from the body
title = md.splitlines()[0].lstrip("# ").strip()
abstract = re.search(r"## Abstract\n\n(.*?)\n\n\*\*Keywords:\*\* (.*?)\n", md, re.S)
abstract_text, keywords = abstract.group(1).strip(), abstract.group(2).strip().rstrip(".")
body = md.split("## 1. Introduction", 1)[1]
body = "## 1. Introduction" + body

# ---- 2. math that the Markdown keeps as plain text
MATH = [
    ("sigma(a0 + u_task + b·s − delta)", r"$\sigma(a_0 + u_{\mathrm{task}} + b\,s - \delta)$"),
    ("h = h0 · max(0.3, 1 − 0.3·L) · 0.93^k", r"$h = h_0 \cdot \max(0.3,\; 1 - 0.3L) \cdot 0.93^{k}$"),
    ("logit p = a0 + b·s − delta", r"$\operatorname{logit} p = a_0 + b\,s - \delta$"),
    ("(rate × 24, which round exactly to integers)", r"(rate $\times$ 24, which round exactly to integers)"),
]
for a, b in MATH:
    assert a in body, a
    body = body.replace(a, b)

# ---- 3. headings: drop the manual numbers, LaTeX numbers sections 1-9 and subsections 6.1-6.11 identically
body = re.sub(r"^## (\d+)\. ", "## ", body, flags=re.M)
body = re.sub(r"^### \d+\.\d+ ", "### ", body, flags=re.M)
body = body.replace("## Declarations", "## Declarations {-}")

# ---- 4. figures: strip the "Figure N." prefix (LaTeX numbers them) and drop the duplicated Figure 8 line
body = re.sub(r"!\[Figure \d+\. ([^\]]*)\]\(([^)]*)\)", lambda m: f"![{m.group(1)}]({m.group(2)})", body)
body = re.sub(r"\n\*Figure 8\. Real-model results \(95% Wilson intervals\)\.\*\n", "\n", body)
figs = re.findall(r"!\[[^\]]*\]\(([^)]*)\)", body)
for i, f in enumerate(figs, 1):
    new = f"fig{i}.png"
    shutil.copy(f, os.path.join(OUT, new)); body = body.replace(f"]({f})", f"]({new})")

# ---- 5. tables: pull each pipe table + its "*Table N. caption*" line out, build LaTeX later
TABLES = []
def grab(m):
    block, cap = m.group(1), m.group(3)
    lines = [l for l in block.strip("\n").split("\n")]
    rows = [[c.strip() for c in l.strip().strip("|").split("|")] for l in lines]
    rows = [rows[0]] + rows[2:]
    TABLES.append((rows, cap))
    return f"\n@@TABLE:{len(TABLES)}@@\n\n@@TCAP:{len(TABLES)}@@ {cap}\n"
body = re.sub(r"\n((\|.*\n)+)\n?\*Table \d+\. (.*?)\*\n", grab, body)
assert len(TABLES) == 18, len(TABLES)

# ---- 6. pandoc for the running text
open("_body.md", "w", encoding="utf-8").write(body)
tex = subprocess.run(["pandoc", "_body.md", "-f", "markdown+pipe_tables+implicit_figures", "-t", "latex", "--wrap=none", "--shift-heading-level-by=-1"],
                     check=True, capture_output=True, text=True).stdout
abs_tex = subprocess.run(["pandoc", "-f", "markdown", "-t", "latex", "--wrap=none", "--shift-heading-level-by=-1"], input=abstract_text, check=True, capture_output=True, text=True).stdout.strip()

# citations
tex = re.sub(r"@@CITE:([\w,]+)@@", lambda m: "\\cite{" + m.group(1) + "}", tex)
abs_tex = re.sub(r"@@CITE:([\w,]+)@@", lambda m: "\\cite{" + m.group(1) + "}", abs_tex)
tex = tex.replace("\\begin{center}\\rule{0.5\\linewidth}{0.5pt}\\end{center}", "")
# figures: pandoc emits \begin{figure}\centering\includegraphics{..}\caption{..}\end{figure}; set the width
tex = re.sub(r"\\includegraphics(\[[^\]]*\])?\{", r"\\includegraphics[width=0.92\\linewidth]{", tex)
tex = tex.replace("\\begin{figure}\n", "\\begin{figure}[htbp]\n")
# allow line breaks inside long identifiers and model names
tex = re.sub(r"\\texttt\{([^}]*)\}", lambda m: "\\texttt{" + m.group(1).replace("/", "/\\allowbreak{}").replace("\\_", "\\_\\allowbreak{}") + "}", tex)
tex = tex.replace("Qwen/Qwen2.5", "Qwen/\\allowbreak{}Qwen2.5")
# keep floats inside the subsection that mentions them
tex = tex.replace("\\subsection{", "\\FloatBarrier\n\\subsection{").replace("\\section{", "\\FloatBarrier\n\\section{")
# code block
tex = tex.replace("\\begin{verbatim}", "\\begin{small}\\begin{verbatim}").replace("\\end{verbatim}", "\\end{verbatim}\\end{small}")

def cell(s):
    s = s.replace("\\", "\\textbackslash{}")
    s = re.sub(r"\*\*(.+?)\*\*", r"\\textbf{\1}", s)
    s = re.sub(r"`(.+?)`", r"\\texttt{\1}", s)
    for a, b in (("%", "\\%"), ("&", "\\&"), ("_", "\\_"), ("#", "\\#"), (">=", "$\\geq$"), ("<=", "$\\leq$"), ("–", "--"), ("×", "$\\times$"), ("±", "$\\pm$")):
        s = s.replace(a, b)
    return s

def latex_table(n, rows, cap_tex):
    ncol = len(rows[0])
    col_w = [max(len(r[i]) for r in rows if i < len(r)) for i in range(ncol)]
    total = sum(col_w)
    label_heavy = col_w[0] > 20
    if n == 1:                                   # defence list: wrap the long middle column
        spec = "l p{0.72\\linewidth} l"; size = "\\small"
    elif total > 60:                             # wide tables: fixed wrapped columns so that headers break instead of the table shrinking
        w0 = 0.26 if label_heavy else 0.11
        w = (0.95 - w0) / (ncol - 1)
        spec = f"p{{{w0:.2f}\\linewidth}}" + f" >{{\\centering\\arraybackslash}}p{{{w:.3f}\\linewidth}}" * (ncol - 1)
        size = "\\scriptsize" if ncol >= 7 else "\\footnotesize"
    else:
        spec = "l" + " c" * (ncol - 1); size = "\\small"
    head = " & ".join("\\textbf{" + cell(c) + "}" for c in rows[0]) + " \\\\"
    lines = [" & ".join(cell(c) for c in r) + " \\\\" for r in rows[1:]]
    tab = "\\begin{tabular}{" + spec + "}\n\\toprule\n" + head + "\n\\midrule\n" + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}"
    if n != 1:                                   # safety net: shrink only if still wider than the text block (adjustbox never enlarges)
        tab = "\\begin{adjustbox}{max width=\\linewidth}\n" + tab + "\n\\end{adjustbox}"
    return ("\\begin{table}[htbp]\n\\centering\n\\caption{" + cap_tex + "}\n\\label{tab:" + str(n) + "}\n" + size + "\n" + tab + "\n\\end{table}")

caps = {}
def takecap(m):
    caps[int(m.group(1))] = m.group(2).strip()
    return ""
tex = re.sub(r"@@TCAP:(\d+)@@ (.*)\n", takecap, tex)
for n, (rows, _) in enumerate(TABLES, 1):
    tex = tex.replace(f"@@TABLE:{n}@@", latex_table(n, rows, caps[n]))
assert "@@" not in tex, "unresolved placeholder"

# ---- 7. assemble around the project template
preamble = r"""% arXiv-ready source (project template, pdflatex + BibTeX unsrt). Flat package: main.tex, main.bbl, references.bib, fig1-8.png
\documentclass[11pt]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage[margin=1in]{geometry}
\usepackage{amsmath,amssymb}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{array}
\usepackage{adjustbox}
\usepackage{placeins}
\usepackage{lmodern}
\usepackage{microtype}
\usepackage{caption}
\usepackage[affil-it]{authblk}
\usepackage{url}
\usepackage{textcomp}
\usepackage[colorlinks=true,linkcolor=blue,citecolor=blue,urlcolor=blue]{hyperref}
\providecommand{\tightlist}{\setlength{\itemsep}{0pt}\setlength{\parskip}{0pt}}
\setlength{\parskip}{4pt}
\captionsetup{font=small,labelfont=bf}
\urlstyle{same}

\title{\textbf{""" + title.replace("&", "\\&") + r"""}}

\author[1,*]{Mustafa S. Aljumaily}
\author[2]{Nawar S. Alseelawi}
\author[3]{Raghad Alshabandar}
\affil[1]{ICT Department, Missan Oil Company, Missan, Iraq\\ \texttt{mustafasadiq0@gmail.com}; ORCID 0000-0002-7886-9537}
\affil[2]{Department of Electrical Engineering, College of Engineering, University of Misan, Maysan, Iraq\\ \texttt{nawar.alseelawi@uomisan.edu.iq}}
\affil[3]{National Center for Artificial Intelligence, Baghdad, Iraq\\ \texttt{raghadalshabandar@outlook.com}; ORCID 0000-0002-1393-3761}
\affil[*]{Corresponding author: \texttt{mustafasadiq0@gmail.com}}
\date{}

\begin{document}

\maketitle

\begin{abstract}
\noindent
""" + abs_tex + r"""

\medskip
\noindent\textbf{Keywords:} """ + keywords + r""".
\end{abstract}

"""
tail = r"""
\bibliographystyle{unsrt}
\bibliography{references}

\end{document}
"""
open(os.path.join(OUT, "main.tex"), "w", encoding="utf-8").write(preamble + tex + tail)
shutil.copy("references.bib", os.path.join(OUT, "references.bib"))
for f in ("_body.md", "_paper_cite.md"): os.remove(f)
print("wrote", os.path.join(OUT, "main.tex"), "with", len(TABLES), "tables and", len(figs), "figures")
