#!/usr/bin/env python3
"""Build paper_combined.docx from paper_combined.md (needs pandoc and python-docx).  Usage: python make_docx.py"""
import re, subprocess, sys
from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

SRC, OUT, REF = "paper_combined.md", "paper_combined.docx", "reference_style.docx"
FONT = "Times New Roman"

# 1. prepare markdown: split title out, size images, proportional table columns
md = open(SRC, encoding="utf-8").read()
md = re.sub(r"^# .*\n", "", md, count=1, flags=re.M)
md = re.sub(r"\*\*Mustafa S\. Aljumaily\*\*.*?\n\n---\n\n", "", md, count=1, flags=re.S)   # author block (through the rule) goes into the YAML header
md = re.sub(r"(!\[[^\]]*\]\([^)]*\))", r"\1{width=6.4in}", md)
def fix_table(block):
    lines = block.rstrip("\n").split("\n")
    rows = [[c.strip() for c in l.strip().strip("|").split("|")] for l in lines]
    ncol = len(rows[1]); w = [3] * ncol
    for r in rows[:1] + rows[2:]:
        for i, c in enumerate(r[:ncol]): w[i] = max(w[i], min(len(c), 30 if i == 0 else 14))
    sep = "|" + "|".join("-" * x for x in w) + "|"
    return "\n".join([lines[0], sep] + lines[2:]) + "\n"
md = re.sub(r"(?m)^(\|.*\n\|[-| ]+\|\n(?:\|.*\n)+)", lambda m: fix_table(m.group(1)), md)
title = open(SRC, encoding="utf-8").readline().lstrip("# ").strip()
yaml = (f'---\ntitle: "{title}"\nauthor:\n  - "Mustafa S. Aljumaily^1,\\\\*^, Nawar S. Alseelawi^2^ and Raghad Alshabandar^3^"\n'
        '  - "^1^ ICT Department, Missan Oil Company, Missan, Iraq (mustafasadiq0@gmail.com; ORCID 0000-0002-7886-9537)"\n'
        '  - "^2^ Department of Electrical Engineering, College of Engineering, University of Misan, Maysan, Iraq (nawar.alseelawi@uomisan.edu.iq; ORCID 0000-0001-5739-2349)"\n'
        '  - "^3^ National Center for Artificial Intelligence, Baghdad, Iraq (raghadalshabandar@outlook.com; ORCID 0000-0002-1393-3761)"\n'
        '  - "\\\\* Corresponding author: mustafasadiq0@gmail.com"\ndate: "November 2026"\n---\n\n')
open("_paper_tmp.md", "w", encoding="utf-8").write(yaml + md)

# 2. reference document with journal-like styles
subprocess.run(["pandoc", "-o", REF, "--print-default-data-file", "reference.docx"], check=True, stdout=open(REF, "wb"))
d = Document(REF)
sec = d.sections[0]; sec.page_width, sec.page_height = Inches(8.5), Inches(11)
for m in ("left_margin", "right_margin", "top_margin", "bottom_margin"): setattr(sec, m, Inches(1))
sec.header_distance = sec.footer_distance = Inches(0.5); sec.gutter = Inches(0)
def style(name, size, bold=None, italic=None, color=None, before=None, after=None, align=None):
    try: st = d.styles[name]
    except KeyError: return
    st.font.name = FONT; st.font.size = Pt(size)
    st.element.rPr.rFonts.set(qn("w:eastAsia"), FONT) if st.element.rPr is not None and st.element.rPr.rFonts is not None else None
    if bold is not None: st.font.bold = bold
    if italic is not None: st.font.italic = italic
    st.font.color.rgb = RGBColor(*(color or (0, 0, 0)))
    for c_ in st.element.iter(qn('w:color')):
        for a_ in (qn('w:themeColor'), qn('w:themeShade'), qn('w:themeTint')):
            c_.attrib.pop(a_, None)
    if not hasattr(st, 'paragraph_format'): return
    pf = st.paragraph_format
    if before is not None: pf.space_before = Pt(before)
    if after is not None: pf.space_after = Pt(after)
    if align is not None: pf.alignment = align
for n, sz, b, bf, af in [("Heading 1", 14, True, 14, 6), ("Heading 2", 12, True, 12, 4), ("Heading 3", 11, True, 10, 3)]: style(n, sz, bold=b, before=bf, after=af)
style("Title", 18, bold=True, after=6, align=1); style("Author", 11, after=2, align=1); style("Date", 10, italic=True, after=14, align=1)
for n in ("Normal", "Body Text", "First Paragraph", "Compact", "Block Text", "Abstract"): style(n, 10.5, after=6)
style("Image Caption", 9, italic=True, after=10, align=1); style("Table Caption", 9, italic=True, after=8)
for n in ("Source Code", "Verbatim Char"): style(n, 8.5)
d.save(REF)

# 3. convert, then tidy table text size and header shading
subprocess.run(["pandoc", "_paper_tmp.md", "-f", "markdown+pipe_tables+implicit_figures", "-o", OUT, "--reference-doc", REF, "--resource-path", "."], check=True)
TBLPR = ["tblStyle","tblpPr","tblOverlap","bidiVisual","tblStyleRowBandSize","tblStyleColBandSize","tblW","jc","tblCellSpacing","tblInd","tblBorders","shd","tblLayout","tblCellMar","tblLook","tblCaption","tblDescription"]
TCPR = ["cnfStyle","tcW","gridSpan","hMerge","vMerge","tcBorders","shd","noWrap","tcMar","textDirection","tcFitText","vAlign","hideMark"]
def put(parent, child, order):
    name = child.tag.split("}")[1]
    for old in parent.findall(qn("w:" + name)): parent.remove(old)
    later = set(order[order.index(name) + 1:])
    for i, ch in enumerate(list(parent)):
        if ch.tag.split("}")[1] in later:
            parent.insert(i, child); return
    parent.append(child)
d = Document(OUT)
for t in d.tables:
    tblPr = t._tbl.tblPr
    b = OxmlElement("w:tblBorders")
    for edge, sz in (("top", 8), ("bottom", 8), ("insideH", 4)):
        e = OxmlElement(f"w:{edge}"); e.set(qn("w:val"), "single"); e.set(qn("w:sz"), str(sz)); e.set(qn("w:space"), "0"); e.set(qn("w:color"), "808080"); b.append(e)
    put(tblPr, b, TBLPR)
    cm = OxmlElement("w:tblCellMar")
    for side, w in (("top", 30), ("left", 70), ("bottom", 30), ("right", 70)):
        e = OxmlElement(f"w:{side}"); e.set(qn("w:w"), str(w)); e.set(qn("w:type"), "dxa"); cm.append(e)
    put(tblPr, cm, TBLPR)
    for ri, row in enumerate(t.rows):
        for c in row.cells:
            for p in c.paragraphs:
                p.paragraph_format.space_after = Pt(0); p.paragraph_format.space_before = Pt(0)
                for r in p.runs:
                    r.font.size = Pt(8.5); r.font.name = FONT
                    if ri == 0: r.font.bold = True
            if ri == 0:
                sh = OxmlElement("w:shd"); sh.set(qn("w:val"), "clear"); sh.set(qn("w:color"), "auto"); sh.set(qn("w:fill"), "E7ECF2")
                put(c._tc.get_or_add_tcPr(), sh, TCPR)
d.save(OUT)
# 4) fix two pandoc-template quirks flagged by the schema validator (nsid length, zoom position)
import zipfile, shutil
tmp = OUT + ".tmp"
with zipfile.ZipFile(OUT) as zi, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zo:
    for it in zi.infolist():
        data = zi.read(it.filename)
        if it.filename == "word/numbering.xml":
            data = re.sub(rb'(<w:nsid w:val=")([0-9A-Fa-f]{1,7})(")', lambda m: m.group(1) + m.group(2).rjust(8, b"0") + m.group(3), data)
        if it.filename == "word/settings.xml":
            z = re.search(rb"<w:zoom[^>]*/>", data)
            if z:
                data = data.replace(z.group(0), b"", 1)
                data = re.sub(rb"(<w:settings[^>]*>)", lambda m: m.group(1) + z.group(0), data, count=1)
        zo.writestr(it, data)
shutil.move(tmp, OUT)
import os; os.remove("_paper_tmp.md"); print("wrote", OUT)
