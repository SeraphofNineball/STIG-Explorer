"""Generate Markdown and Word (.docx) documents from the STIG Explorer data.

Outputs (under docs/):
    STIG_Explorer_Guide.md / .docx        Overview, topic reference (3 levels), STIG inventory
    markdown/<STIG>.md                    Every rule of one STIG with all three explanation levels
    word/<STIG>.docx                      Same content as Word
    markdown|word/WIN_SERVER_*_DC.*       Domain controller view of each Windows Server STIG

    python -m stig_explorer.export_docs [--stig RHEL_9 ...] [--no-word]
"""

from __future__ import annotations

import argparse
import collections
import re
import sys
from pathlib import Path

from . import build, tags as tagmod

ROOT = build.ROOT
DOCS = ROOT / "docs"

GUIDE_OSES = [("linux", "rhel", "RHEL"), ("linux", "ubuntu", "Ubuntu"), ("windows", "windows", "Windows")]

LEVELS = [
    ("generic", "Level 3: General Audience"),
    ("admin", "Level 2: System Administrator"),
    ("pro", "Level 1: Cyber Security Professional"),
]

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _t(s: str) -> str:
    return _CTRL.sub("", s or "")


def topic_txt(topic: dict, field: str, platform: str, family: str = "") -> str:
    v = topic.get(field, "")
    if isinstance(v, dict):
        return v.get(family) or v.get(platform) or next(iter(v.values()), "")
    return v


def nist(data: dict, rule: dict, rev: str) -> list[str]:
    out: list[str] = []
    for c in rule["ccis"]:
        for idx in data["ccis"].get(c, {}).get(rev, []):
            if idx not in out:
                out.append(idx)
    return out


ROLE_LABEL = {"dc": "Domain controller only", "ms": "Member server only", "both": "All servers (DC and member)"}
SHELL_LABEL = {"powershell": "PowerShell", "cmd": "CMD", "bash": "Bash"}
SRC_LABEL = {"disa": "from DISA check text", "generated": "generated from the setting", "curated": "STIG Explorer command"}
NO_VALIDATION = "No single command can validate this rule. It is a procedural or manual check; follow the DISA check procedure."


def tag_text(data: dict, r: dict) -> str:
    defs = data.get("tag_defs", {})
    return ", ".join(f"{defs[t]['label']} ({defs[t]['name']})" for t in r.get("tags", []) if t in defs)


def sections(data: dict, key: str, dc_view: bool = False) -> list[tuple[str, str, list[dict]]]:
    """(heading, intro, rules) sections for a STIG document.

    Windows Server STIGs are split by role; the DC view holds only rules that apply to domain controllers."""
    rules = sorted((r for r in data["rules"] if r["stig"] == key), key=lambda r: r["stig_id"])
    if not any(r.get("role") for r in rules):
        return [("Rules", "", rules)]
    dc = [r for r in rules if r["role"] == "dc"]
    ms = [r for r in rules if r["role"] == "ms"]
    both = [r for r in rules if r["role"] == "both"]
    if dc_view:
        return [("Domain controller-specific rules", "These rules apply only to domain controllers (STIG IDs with -DC-).", dc),
                ("Rules common to all servers", "These rules apply to domain controllers and member servers alike.", both)]
    return [("Rules for all servers", "These rules apply to every Windows Server, whether domain controller or member server.", both),
            ("Domain controller-only rules", "Apply these in addition to the common rules on domain controllers (STIG IDs with -DC-).", dc),
            ("Member server-only rules", "Apply these in addition to the common rules on member and standalone servers (STIG IDs with -MS-).", ms)]


def setting_line(s: dict) -> tuple[str, str, str, str]:
    labels = {"registry": "Registry", "gpo": "Group Policy", "sysctl": "sysctl", "audit_rule": "Audit rule",
              "config": "Config", "dconf": "dconf", "service": "Service", "package": "Package",
              "permission": "Permission", "feature": "Feature", "command": "Command"}
    return labels.get(s["type"], s["type"]), s["target"], s["name"], s["value"]


# ===================================================================== Markdown

def _md_escape_cell(s: str) -> str:
    return _t(s).replace("|", "\\|").replace("\n", " ")


def _md_code(s: str) -> str:
    s = _t(s).rstrip()
    fence = "````" if "```" in s else "```"
    return f"{fence}text\n{s}\n{fence}"


def rule_markdown(data: dict, r: dict, heading: str = "##") -> str:
    topics = [data["topics"][t] for t in r["topics"]]
    primary = topics[0]
    plat = r["platform"]
    sev_label, sev_plain = data["meta"]["severity_plain"][r["severity"]]
    L = []
    badges = "".join(f"[{data['tag_defs'][t]['label']}] " for t in r.get("tags", []) if t in data.get("tag_defs", {}))
    L.append(f"{heading} {badges}{r['vuln_id']} · {r['stig_id']} · {r['cat']}: {_t(r['title'])}")
    L.append("")
    L.append("| Field | Value |\n|---|---|")
    L.append(f"| Rule ID | `{r['id']}` |")
    L.append(f"| Severity | {r['cat']} ({r['severity']}) |")
    L.append(f"| SRG | {r['srg']} |")
    L.append(f"| Topic | {', '.join(t['name'] for t in topics)} |")
    L.append(f"| CCI | {', '.join(r['ccis']) or 'n/a'} |")
    for rev, label in (("rev5", "NIST 800-53 Rev 5"), ("rev4", "NIST 800-53 Rev 4"), ("rev3", "NIST 800-53 Rev 3")):
        L.append(f"| {label} | {_md_escape_cell(', '.join(nist(data, r, rev)) or 'n/a')} |")
    L.append(f"| Implemented via | {', '.join(r['setting_cats'])} |")
    if r.get("role"):
        L.append(f"| Server role | {ROLE_LABEL[r['role']]} |")
    if r.get("tags"):
        L.append(f"| Tags | **{_md_escape_cell(tag_text(data, r))}** |")
    L.append("")

    # Level 3 - generic
    L.append(f"{heading}# {LEVELS[0][1]}")
    L.append("")
    L.append(f"**In plain terms:** {_t(r['plain'])}")
    L.append("")
    L.append(f"**Why it matters:** {primary['generic']}")
    L.append("")
    L.append(f"**How important is it?** {sev_label}: {sev_plain}")
    if r["glossary"]:
        L.append("")
        L.append("**Key terms:**")
        for g in r["glossary"]:
            L.append(f"- *{g['term']}*: {g['definition']}")
    L.append("")

    # Level 2 - admin
    L.append(f"{heading}# {LEVELS[1][1]}")
    L.append("")
    real = [s for s in r["settings"] if s["type"] != "command"]
    if real:
        L.append("**Settings changed:**")
        L.append("")
        L.append("| Type | Location | Setting | Required value |\n|---|---|---|---|")
        for s in real:
            a, b, c, d = setting_line(s)
            L.append(f"| {a} | {_md_escape_cell(b)} | {_md_escape_cell(c)} | {_md_escape_cell(d)} |")
        L.append("")
    else:
        L.append(f"**Settings changed:** No single machine-readable setting. This is implemented via: "
                 f"{', '.join(r['setting_cats'])}. See the fix text.")
        L.append("")
    L.append("**Command-line validation:**")
    L.append("")
    if r.get("validate"):
        for v in r["validate"]:
            L.append(f"*{SHELL_LABEL[v['shell']]}* ({SRC_LABEL[v['src']]})")
            L.append("")
            L.append(_md_code(v["cmd"]))
            if v["expect"]:
                L.append("")
                L.append(f"Expected: {_t(v['expect'])}")
            L.append("")
    else:
        L.append(NO_VALIDATION)
        L.append("")
    L.append(f"**How it works:** {topic_txt(primary, 'admin', plat, r.get('os', ''))}")
    L.append("")
    if len(topics) > 1:
        L.append(f"**Also related ({topics[1]['name']}):** {topic_txt(topics[1], 'admin', plat, r.get('os', ''))}")
        L.append("")
    L.append(f"**Operational impact:** {topic_txt(primary, 'impact', plat, r.get('os', ''))}")
    if r.get("potential_impacts"):
        L.append("")
        L.append(f"**DISA-noted potential impacts:** {_t(r['potential_impacts'])}")
    L.append("")
    L.append("**Check procedure (DISA):**")
    L.append("")
    L.append(_md_code(r["check"]))
    L.append("")
    L.append("**Fix procedure (DISA):**")
    L.append("")
    L.append(_md_code(r["fix"]))
    L.append("")

    # Level 1 - pro
    L.append(f"{heading}# {LEVELS[2][1]}")
    L.append("")
    L.append(f"**Vulnerability discussion (DISA):** {_t(r['discussion'])}")
    L.append("")
    L.append(f"**Threat & control context:** {primary['pro']}")
    L.append("")
    attack = [a for t in topics for a in t["attack"]]
    if attack:
        seen, items = set(), []
        for tid, name in attack:
            if tid not in seen:
                seen.add(tid)
                items.append(f"{tid} {name}")
        L.append(f"**MITRE ATT&CK techniques mitigated/detected:** {'; '.join(items)}")
        L.append("")
    L.append(f"**Severity rationale:** {data['meta']['severity_text'][r['severity']]}")
    L.append("")
    L.append("**Compliance mapping:**")
    L.append("")
    for c in r["ccis"]:
        info = data["ccis"].get(c, {})
        L.append(f"- **{c}**: {_t(info.get('definition', ''))}  ")
        L.append(f"  Rev 5: {', '.join(info.get('rev5', [])) or 'n/a'} · Rev 4: {', '.join(info.get('rev4', [])) or 'n/a'}"
                 f" · Rev 3: {', '.join(info.get('rev3', [])) or 'n/a'}")
    if r.get("mitigations"):
        L.append("")
        L.append(f"**Mitigations (DISA):** {_t(r['mitigations'])}")
    if r.get("severity_override"):
        L.append("")
        L.append(f"**Severity override guidance:** {_t(r['severity_override'])}")
    if r.get("documentable"):
        L.append("")
        L.append("**Documentable:** Yes. A deviation may be documented with the ISSO/AO.")
    if r.get("legacy_ids"):
        L.append("")
        L.append(f"**Legacy IDs:** {', '.join(r['legacy_ids'])}")
    L.append("")
    L.append("---")
    L.append("")
    return "\n".join(L)


def how_to_read_md() -> str:
    return (
        "## How to read this document\n\n"
        "Every rule is explained at three levels. Read the one that fits you, or all three:\n\n"
        "- **Level 3: General Audience.** Plain language and an everyday analogy, for readers with little security or IT background.\n"
        "- **Level 2: System Administrator.** The exact settings changed, where they live, how to check and fix them, and the operational impact.\n"
        "- **Level 1: Cyber Security Professional.** DISA's risk rationale, threat context and MITRE ATT&CK techniques, "
        "and the CCI to NIST SP 800-53 Rev 3 / Rev 4 / Rev 5 control mapping.\n\n"
        "Check and fix procedures, vulnerability discussions and CCI definitions are quoted from DISA's published STIG and CCI List. "
        "Topic explanations, threat context and plain-language summaries are written by STIG Explorer and should be read as "
        "guidance, not as authoritative DISA text. **The DISA STIG is always the authoritative source for compliance.**\n"
    )


def _doc_title(stig: dict, dc_view: bool) -> str:
    return f"{stig['product']} {'Domain Controller ' if dc_view else ''}STIG: Explained"


def _dc_note(dc_view: bool) -> str:
    if not dc_view:
        return ""
    return ("DISA publishes one STIG for each Windows Server version that covers both domain controllers and member "
            "servers. This document contains only the rules that apply to a **domain controller**: the DC-specific "
            "rules first, then the rules common to all servers. Member server-only rules are omitted.")


def stig_markdown(data: dict, key: str, dc_view: bool = False) -> str:
    stig = next(s for s in data["stigs"] if s["key"] == key)
    secs = sections(data, key, dc_view)
    rules = [r for _, _, rs in secs for r in rs]
    sev = collections.Counter(r["severity"] for r in rules)
    tops = collections.Counter(r["topics"][0] for r in rules)
    L = [f"# {_doc_title(stig, dc_view)}",
         "",
         f"*{stig['title']}*, {stig['label']}, benchmark date {stig['date']}. "
         f"{len(rules)} rules. Generated by STIG Explorer {data['meta']['version']} on {data['meta']['generated']}.",
         "",
         _dc_note(dc_view),
         "",
         how_to_read_md(),
         "## Summary",
         "",
         "| Severity | Rules |\n|---|---|",
         f"| CAT I (high) | {sev['high']} |",
         f"| CAT II (medium) | {sev['medium']} |",
         f"| CAT III (low) | {sev['low']} |",
         "",
         "| Topic | Rules |\n|---|---|"]
    for tid, n in tops.most_common():
        L.append(f"| {data['topics'][tid]['name']} | {n} |")
    L.append("")
    for t in data.get("tag_defs", {}).values():
        tagged = [r for r in rules if t["id"] in r.get("tags", [])]
        if tagged:
            L.append(f"**{t['label']} ({t['name']}):** {len(tagged)} rules: " + ", ".join(r["stig_id"] for r in tagged))
            L.append("")
    if len(secs) > 1:
        L.append("| Section | Rules |\n|---|---|")
        for heading, _, rs in secs:
            L.append(f"| {heading} | {len(rs)} |")
        L.append("")
    for heading, intro, rs in secs:
        L.append(f"## {heading}")
        L.append("")
        if intro:
            L.append(f"*{intro}*")
            L.append("")
        for r in rs:
            L.append(rule_markdown(data, r, heading="###"))
    return "\n".join(L)


def guide_markdown(data: dict) -> str:
    rules = data["rules"]
    L = ["# STIG Explorer: DISA STIG Configuration Guide (RHEL, Ubuntu & Windows)",
         "",
         f"Generated {data['meta']['generated']} from {data['meta']['source']}. "
         f"{len(rules)} rules across {len(data['stigs'])} STIGs.",
         "",
         "## Purpose",
         "",
         "This guide explains what the DISA Security Technical Implementation Guides (STIGs) for Red Hat Enterprise Linux, "
         "Canonical Ubuntu and Microsoft Windows desktop/server operating systems change on a system, and why. It goes with the STIG "
         "Explorer search application and the per-STIG detail documents (docs/markdown and docs/word).",
         "",
         how_to_read_md(),
         "## STIGs covered",
         "",
         "| STIG | Release | Benchmark date | Rules | CAT I | CAT II | CAT III |\n|---|---|---|---|---|---|---|"]
    for s in data["stigs"]:
        rs = [r for r in rules if r["stig"] == s["key"]]
        c = collections.Counter(r["severity"] for r in rs)
        L.append(f"| {s['product']} | {s['label']} | {s['date']} | {len(rs)} | {c['high']} | {c['medium']} | {c['low']} |")
        if any(r.get("role") for r in rs):
            d = [r for r in rs if r["role"] in ("dc", "both")]
            c = collections.Counter(r["severity"] for r in d)
            L.append(f"| ↳ {s['product']}: domain controller view | {s['label']} | {s['date']} | {len(d)} | {c['high']} | {c['medium']} | {c['low']} |")
    L += ["", "## NIST SP 800-53 revision mapping", "",
          "Each STIG rule cites one or more CCIs (Control Correlation Identifiers). DISA's CCI List maps each CCI to "
          "NIST SP 800-53 controls in Revision 3, Revision 4 and Revision 5, so the same rule can be traced to whichever "
          "revision your authorization package (RMF/eMASS) uses. Most current DoD packages use Rev 5. Rev 3 references "
          "are kept for legacy packages and crosswalks.", "",
          "| Control family | Rules mapped (Rev 5) | Rules mapped (Rev 3) |\n|---|---|---|"]
    fam5, fam3 = collections.Counter(), collections.Counter()
    for r in rules:
        f5 = {i[:2] for i in nist(data, r, "rev5")}
        f3 = {i[:2] for i in nist(data, r, "rev3")}
        fam5.update(f5)
        fam3.update(f3)
    for fam in sorted(set(fam5) | set(fam3)):
        L.append(f"| {fam}: {data['meta']['families'].get(fam, '')} | {fam5[fam]} | {fam3[fam]} |")
    L += ["", "## Topic reference (three levels)", "",
          "Rules are grouped into security topics. Each topic below is explained at all three levels. Use it as "
          "training material or to brief stakeholders on a whole category at once.", ""]
    counts = collections.Counter(r["topics"][0] for r in rules)
    for tid, t in sorted(data["topics"].items(), key=lambda kv: -counts[kv[0]]):
        L.append(f"### {t['name']}")
        L.append("")
        L.append(f"*{t['short']}* ({counts[tid]} rules across all STIGs as the primary topic.)")
        L.append("")
        L.append(f"**General audience:** {t['generic']}")
        L.append("")
        for plat, fam, label in GUIDE_OSES:
            L.append(f"**System administrator ({label}):** {topic_txt(t, 'admin', plat, fam)}")
            L.append("")
        L.append(f"**Operational impact:** {topic_txt(t, 'impact', 'linux', 'rhel')}")
        L.append("")
        L.append(f"**Cyber security professional:** {t['pro']}")
        if t["attack"]:
            L.append("")
            L.append("**ATT&CK:** " + "; ".join(f"{a} {b}" for a, b in t["attack"]))
        L.append("")
    L += ["## Severity categories", ""]
    for k in ("high", "medium", "low"):
        label, plain = data["meta"]["severity_plain"][k]
        L.append(f"- **{label}**: {data['meta']['severity_text'][k]} *In plain terms:* {plain}")
    L += ["", "## Using the STIG Explorer application", "",
          "- **Local:** open `STIG_Explorer/web/index.html` in a browser. No install or network is needed.",
          "- **Container:** `docker compose up -d` (or `podman compose up -d`) in `STIG_Explorer/`, then browse to http://localhost:8080. "
          "The container also serves a JSON search API at `/api/search?q=...`.",
          "- **Refreshing content:** `python -m stig_explorer.build --fetch --docs` downloads the newest DISA releases and "
          "regenerates the data and these documents.", ""]
    return "\n".join(L)


# ========================================================================= Word

def _docx():
    try:
        import docx  # noqa: F401
        return True
    except ImportError:
        return False


class WordWriter:
    def __init__(self, title: str):
        from docx import Document
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.shared import Pt, RGBColor
        self.Pt, self.RGB = Pt, RGBColor
        self.doc = Document()
        st = self.doc.styles["Normal"]
        st.font.name = "Calibri"
        st.font.size = Pt(10.5)
        sec = self.doc.sections[0]
        from docx.shared import Inches
        for side in ("left_margin", "right_margin"):
            setattr(sec, side, Inches(0.8))
        h = self.doc.add_heading(title, 0)
        h.alignment = WD_ALIGN_PARAGRAPH.LEFT

    def toc(self):
        from docx.oxml import OxmlElement
        from docx.oxml.ns import qn
        p = self.doc.add_paragraph()
        r = p.add_run()
        b = OxmlElement("w:fldChar"); b.set(qn("w:fldCharType"), "begin")
        i = OxmlElement("w:instrText"); i.set(qn("xml:space"), "preserve"); i.text = 'TOC \\o "1-2" \\h \\z \\u'
        s = OxmlElement("w:fldChar"); s.set(qn("w:fldCharType"), "separate")
        t = OxmlElement("w:t"); t.text = "Right-click and choose Update Field to build the table of contents."
        e = OxmlElement("w:fldChar"); e.set(qn("w:fldCharType"), "end")
        for el in (b, i, s, t, e):
            r._r.append(el)

    def h(self, text: str, level: int):
        self.doc.add_heading(_t(text), level)

    def p(self, text: str = "", label: str | None = None, italic: bool = False):
        para = self.doc.add_paragraph()
        if label:
            para.add_run(label + " ").bold = True
        run = para.add_run(_t(text))
        run.italic = italic
        return para

    def bullet(self, text: str, label: str | None = None):
        para = self.doc.add_paragraph(style="List Bullet")
        if label:
            para.add_run(label + " ").bold = True
        para.add_run(_t(text))

    def code(self, text: str):
        from docx.oxml import OxmlElement
        from docx.oxml.ns import qn
        para = self.doc.add_paragraph()
        pPr = para._p.get_or_add_pPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), "F2F2F2")
        pPr.append(shd)
        run = para.add_run(_t(text).rstrip())
        run.font.name = "Consolas"
        run.font.size = self.Pt(8.5)
        rPr = run._r.get_or_add_rPr()
        rf = rPr.find(qn("w:rFonts"))
        if rf is not None:
            rf.set(qn("w:eastAsia"), "Consolas")

    def table(self, header: list[str], rows: list[list[str]], widths: list[float] | None = None):
        t = self.doc.add_table(rows=1, cols=len(header))
        t.style = "Light Grid Accent 1"
        for i, hd in enumerate(header):
            cell = t.rows[0].cells[i]
            cell.text = ""
            cell.paragraphs[0].add_run(hd).bold = True
        for row in rows:
            cells = t.add_row().cells
            for i, v in enumerate(row):
                cells[i].text = _t(str(v))
                for para in cells[i].paragraphs:
                    for run in para.runs:
                        run.font.size = self.Pt(9)
        self.doc.add_paragraph()

    def page_break(self):
        self.doc.add_page_break()

    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.doc.save(str(path))


def _how_to_read_word(w: WordWriter):
    w.h("How to read this document", 1)
    w.p("Every rule is explained at three levels. Read the one that fits you, or all three:")
    w.bullet("Plain language and an everyday analogy, for readers with little security or IT background.", "Level 3: General Audience.")
    w.bullet("The exact settings changed, where they live, how to check and fix them, and the operational impact.", "Level 2: System Administrator.")
    w.bullet("DISA's risk rationale, threat context and MITRE ATT&CK techniques, and the CCI to NIST SP 800-53 Rev 3/4/5 mapping.", "Level 1: Cyber Security Professional.")
    w.p("Check/fix procedures, vulnerability discussions and CCI definitions are quoted from DISA. Topic explanations, threat "
        "context and plain-language summaries are written by STIG Explorer as guidance. The DISA STIG is always the "
        "authoritative source for compliance.", italic=True)


def rule_word(w: WordWriter, data: dict, r: dict):
    topics = [data["topics"][t] for t in r["topics"]]
    primary = topics[0]
    plat = r["platform"]
    sev_label, sev_plain = data["meta"]["severity_plain"][r["severity"]]
    badges = "".join(f"[{data['tag_defs'][t]['label']}] " for t in r.get("tags", []) if t in data.get("tag_defs", {}))
    w.h(f"{badges}{r['vuln_id']} · {r['stig_id']} · {r['cat']}: {r['title']}", 2)
    rows = [["Rule ID", r["id"]], ["Severity", f"{r['cat']} ({r['severity']})"], ["SRG", r["srg"]],
            ["Topic", ", ".join(t["name"] for t in topics)], ["CCI", ", ".join(r["ccis"]) or "n/a"],
            ["NIST 800-53 Rev 5", ", ".join(nist(data, r, "rev5")) or "n/a"],
            ["NIST 800-53 Rev 4", ", ".join(nist(data, r, "rev4")) or "n/a"],
            ["NIST 800-53 Rev 3", ", ".join(nist(data, r, "rev3")) or "n/a"],
            ["Implemented via", ", ".join(r["setting_cats"])]]
    if r.get("role"):
        rows.append(["Server role", ROLE_LABEL[r["role"]]])
    if r.get("tags"):
        rows.append(["Tags", tag_text(data, r)])
    w.table(["Field", "Value"], rows)

    w.h(LEVELS[0][1], 3)
    w.p(r["plain"], "In plain terms:")
    w.p(primary["generic"], "Why it matters:")
    w.p(sev_plain, f"How important is it? {sev_label}:")
    for g in r["glossary"]:
        w.bullet(g["definition"], g["term"] + ":")

    w.h(LEVELS[1][1], 3)
    real = [s for s in r["settings"] if s["type"] != "command"]
    if real:
        w.p("", "Settings changed:")
        w.table(["Type", "Location", "Setting", "Required value"], [list(setting_line(s)) for s in real])
    else:
        w.p(f"No single machine-readable setting. This is implemented via: {', '.join(r['setting_cats'])}. See the fix text.",
            "Settings changed:")
    w.p("", "Command-line validation:")
    if r.get("validate"):
        for v in r["validate"]:
            w.p(f"({SRC_LABEL[v['src']]})", f"{SHELL_LABEL[v['shell']]}", italic=True)
            w.code(v["cmd"])
            if v["expect"]:
                w.p(v["expect"], "Expected:")
    else:
        w.p(NO_VALIDATION, italic=True)
    w.p(topic_txt(primary, "admin", plat, r.get('os', '')), "How it works:")
    if len(topics) > 1:
        w.p(topic_txt(topics[1], "admin", plat, r.get('os', '')), f"Also related ({topics[1]['name']}):")
    w.p(topic_txt(primary, "impact", plat, r.get('os', '')), "Operational impact:")
    if r.get("potential_impacts"):
        w.p(r["potential_impacts"], "DISA-noted potential impacts:")
    w.p("", "Check procedure (DISA):")
    w.code(r["check"])
    w.p("", "Fix procedure (DISA):")
    w.code(r["fix"])

    w.h(LEVELS[2][1], 3)
    w.p(r["discussion"], "Vulnerability discussion (DISA):")
    w.p(primary["pro"], "Threat & control context:")
    seen, items = set(), []
    for t in topics:
        for tid, name in t["attack"]:
            if tid not in seen:
                seen.add(tid)
                items.append(f"{tid} {name}")
    if items:
        w.p("; ".join(items), "MITRE ATT&CK techniques:")
    w.p(data["meta"]["severity_text"][r["severity"]], "Severity rationale:")
    for c in r["ccis"]:
        info = data["ccis"].get(c, {})
        w.bullet(f"{info.get('definition', '')} | Rev 5: {', '.join(info.get('rev5', [])) or 'n/a'} | "
                 f"Rev 4: {', '.join(info.get('rev4', [])) or 'n/a'} | Rev 3: {', '.join(info.get('rev3', [])) or 'n/a'}", c + ":")
    if r.get("mitigations"):
        w.p(r["mitigations"], "Mitigations (DISA):")
    if r.get("severity_override"):
        w.p(r["severity_override"], "Severity override guidance:")
    if r.get("documentable"):
        w.p("Yes. A deviation may be documented with the ISSO/AO.", "Documentable:")


def stig_word(data: dict, key: str, path: Path, dc_view: bool = False):
    stig = next(s for s in data["stigs"] if s["key"] == key)
    secs = sections(data, key, dc_view)
    rules = [r for _, _, rs in secs for r in rs]
    w = WordWriter(_doc_title(stig, dc_view))
    w.p(f"{stig['title']}, {stig['label']}, benchmark date {stig['date']}. {len(rules)} rules. "
        f"Generated by STIG Explorer {data['meta']['version']} on {data['meta']['generated']}.", italic=True)
    if dc_view:
        w.p(_dc_note(True).replace("**", ""))
    w.toc()
    w.page_break()
    _how_to_read_word(w)
    sev = collections.Counter(r["severity"] for r in rules)
    w.h("Summary", 1)
    w.table(["Severity", "Rules"], [["CAT I (high)", sev["high"]], ["CAT II (medium)", sev["medium"]],
                                    ["CAT III (low)", sev["low"]]])
    tops = collections.Counter(r["topics"][0] for r in rules)
    w.table(["Topic", "Rules"], [[data["topics"][t]["name"], n] for t, n in tops.most_common()])
    for t in data.get("tag_defs", {}).values():
        tagged = [r for r in rules if t["id"] in r.get("tags", [])]
        if tagged:
            w.p(", ".join(r["stig_id"] for r in tagged), f"{t['label']} ({t['name']}), {len(tagged)} rules:")
    if len(secs) > 1:
        w.table(["Section", "Rules"], [[h, len(rs)] for h, _, rs in secs])
    for heading, intro, rs in secs:
        w.page_break()
        w.h(heading, 1)
        if intro:
            w.p(intro, italic=True)
        for r in rs:
            rule_word(w, data, r)
    w.save(path)


def guide_word(data: dict, path: Path):
    rules = data["rules"]
    w = WordWriter("STIG Explorer: DISA STIG Configuration Guide (RHEL, Ubuntu & Windows)")
    w.p(f"Generated {data['meta']['generated']} from {data['meta']['source']}. {len(rules)} rules across "
        f"{len(data['stigs'])} STIGs.", italic=True)
    w.toc()
    w.page_break()
    w.h("Purpose", 1)
    w.p("This guide explains what the DISA STIGs for Red Hat Enterprise Linux, Canonical Ubuntu and Microsoft Windows desktop/server "
        "operating systems change on a system, and why. It goes with the STIG Explorer search application and the "
        "per-STIG detail documents.")
    _how_to_read_word(w)
    w.h("STIGs covered", 1)
    rows = []
    for s in data["stigs"]:
        rs = [r for r in rules if r["stig"] == s["key"]]
        c = collections.Counter(r["severity"] for r in rs)
        rows.append([s["product"], s["label"], s["date"], len(rs), c["high"], c["medium"], c["low"]])
        if any(r.get("role") for r in rs):
            d = [r for r in rs if r["role"] in ("dc", "both")]
            c = collections.Counter(r["severity"] for r in d)
            rows.append([f"  {s['product']}: domain controller view", s["label"], s["date"], len(d), c["high"], c["medium"], c["low"]])
    w.table(["STIG", "Release", "Benchmark date", "Rules", "CAT I", "CAT II", "CAT III"], rows)
    w.h("NIST SP 800-53 revision mapping", 1)
    w.p("Each STIG rule cites one or more CCIs. DISA's CCI List maps each CCI to NIST SP 800-53 controls in Revision 3, "
        "Revision 4 and Revision 5, so every rule can be traced to whichever revision your authorization package uses.")
    fam5, fam3 = collections.Counter(), collections.Counter()
    for r in rules:
        fam5.update({i[:2] for i in nist(data, r, "rev5")})
        fam3.update({i[:2] for i in nist(data, r, "rev3")})
    w.table(["Control family", "Rules mapped (Rev 5)", "Rules mapped (Rev 3)"],
            [[f"{f}: {data['meta']['families'].get(f, '')}", fam5[f], fam3[f]] for f in sorted(set(fam5) | set(fam3))])
    w.page_break()
    w.h("Topic reference (three levels)", 1)
    counts = collections.Counter(r["topics"][0] for r in rules)
    for tid, t in sorted(data["topics"].items(), key=lambda kv: -counts[kv[0]]):
        w.h(t["name"], 2)
        w.p(f"{t['short']} ({counts[tid]} rules as the primary topic.)", italic=True)
        w.p(t["generic"], "General audience:")
        for plat, fam, label in GUIDE_OSES:
            w.p(topic_txt(t, "admin", plat, fam), f"System administrator ({label}):")
        w.p(topic_txt(t, "impact", "linux", "rhel"), "Operational impact:")
        w.p(t["pro"], "Cyber security professional:")
        if t["attack"]:
            w.p("; ".join(f"{a} {b}" for a, b in t["attack"]), "ATT&CK:")
    w.h("Severity categories", 1)
    for k in ("high", "medium", "low"):
        label, plain = data["meta"]["severity_plain"][k]
        w.bullet(f"{data['meta']['severity_text'][k]} In plain terms: {plain}", label + ":")
    w.h("Using the STIG Explorer application", 1)
    w.bullet("Open STIG_Explorer/web/index.html in a browser. No install or network is needed.", "Local:")
    w.bullet("Run 'docker compose up -d' (or 'podman compose up -d') in STIG_Explorer/, then browse to http://localhost:8080.", "Container:")
    w.bullet("Run 'python -m stig_explorer.build --fetch --docs' to download the newest DISA releases and regenerate everything.", "Refresh:")
    w.save(path)


# ======================================================================= Driver

def export_all(data: dict | None = None, stigs: list[str] | None = None, word: bool = True) -> None:
    data = data or build.load()
    tagmod.apply(data)
    keys = stigs or [s["key"] for s in data["stigs"]]
    (DOCS / "markdown").mkdir(parents=True, exist_ok=True)
    gpath = DOCS / "STIG_Explorer_Guide.md"
    gpath.write_text(guide_markdown(data), encoding="utf-8")
    print(f"  wrote {gpath.relative_to(ROOT)}")
    views = [(k, False) for k in keys] + [(k, True) for k in keys if "SERVER" in k]
    for k, dc in views:
        p = DOCS / "markdown" / f"{k}{'_DC' if dc else ''}.md"
        p.write_text(stig_markdown(data, k, dc), encoding="utf-8")
        print(f"  wrote {p.relative_to(ROOT)} ({p.stat().st_size / 1e6:.1f} MB)")
    if not word:
        return
    if not _docx():
        print("  ! python-docx not installed; skipping Word output (pip install python-docx)")
        return
    guide_word(data, DOCS / "STIG_Explorer_Guide.docx")
    print(f"  wrote docs/STIG_Explorer_Guide.docx")
    for k, dc in views:
        p = DOCS / "word" / f"{k}{'_DC' if dc else ''}.docx"
        stig_word(data, k, p, dc)
        print(f"  wrote {p.relative_to(ROOT)} ({p.stat().st_size / 1e6:.1f} MB)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Export STIG Explorer content to Markdown and Word.")
    ap.add_argument("--stig", action="append", help="Only this STIG key (e.g. RHEL_9). Repeatable.")
    ap.add_argument("--no-word", action="store_true", help="Markdown only")
    args = ap.parse_args(argv)
    export_all(stigs=args.stig, word=not args.no_word)
    return 0


if __name__ == "__main__":
    sys.exit(main())
