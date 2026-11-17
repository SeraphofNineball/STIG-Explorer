"""Custom rule tags (e.g. FMCC) from editable CSV tag files.

Each file in tags/ defines one tag. Lines starting with "#" carry metadata:

    # label: FMCC
    # name: Federally Mandated Critical Control
    # color: #b71c1c
    # description: Free text shown in the app.

followed by CSV rows "id,note". An id can be any of:

    V-257777                 vulnerability ID
    SV-257777r1268251_rule   rule ID (revision suffix optional)
    RHEL-09-211010           STIG ID (also WN22-SO-000150, UBTU-22-611035, ...)
    CCI-000366               every rule that cites this CCI
    SRG-OS-000480-GPOS-00227 every rule under this SRG requirement
    AC-7, IA-5(1)            every rule mapped to this NIST SP 800-53 control
                             (Rev 5 by default; prefix rev3: or rev4: for other revisions)

    python -m stig_explorer.tags          # compile tags/*.csv -> web/data/tags.js

The compiled file is loaded by the web app (also from file://), the server and the
document export, so tag changes don't require re-downloading or re-parsing the STIGs.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

from . import build

TAG_DIR = build.ROOT / "tags"
OUT = build.ROOT / "web" / "data" / "tags.js"
JS_PREFIX = "window.STIG_TAGS = "

_V = re.compile(r"^V-\d+$", re.I)
_SV = re.compile(r"^SV-\d+(r\d+_rule)?$", re.I)
_CCI = re.compile(r"^CCI-\d{6}$", re.I)
_SRG = re.compile(r"^SRG-[A-Z]+-\d+(-[A-Z]+-\d+)?$", re.I)
_STIG = re.compile(r"^[A-Z0-9]+-[A-Z0-9]+-\d{5,6}$", re.I)
_NIST = re.compile(r"^(?:(rev[345]):)?([A-Z]{2}-\d+(?:\s*\(\d+\))*)(?:\s+[a-z.()\d ]+)?$", re.I)
_HEX = re.compile(r"^#[0-9a-f]{6}$", re.I)


def _norm_ctl(s: str) -> str:
    return re.sub(r"\s+", "", s.upper())


def parse_file(path: Path) -> tuple[dict, list[tuple[str, str, int]]]:
    meta = {"id": re.sub(r"[^a-z0-9_-]+", "-", path.stem.lower()).strip("-"),
            "label": path.stem.upper(), "name": path.stem, "color": "#b71c1c", "description": ""}
    rows: list[tuple[str, str, int]] = []
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    body = []
    for n, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith("#"):
            m = re.match(r"#\s*(label|name|color|description)\s*:\s*(.*)$", s, re.I)
            if m:
                meta[m.group(1).lower()] = m.group(2).strip()
            continue
        if s:
            body.append((n, line))
    for n, row in ((n, r) for n, line in body for r in csv.reader([line])):
        if not row or not row[0].strip():
            continue
        ident = row[0].strip()
        if ident.lower() in ("id", "identifier", "rule"):
            continue  # header row
        rows.append((ident, ",".join(c.strip() for c in row[1:]).strip(), n))
    if not _HEX.match(meta["color"]):
        meta["color"] = "#b71c1c"
    return meta, rows


def _matcher(data: dict):
    by_v, by_sv, by_stig, by_cci, by_srg = {}, {}, {}, {}, {}
    nist = {rev: [] for rev in ("rev3", "rev4", "rev5")}
    for r in data["rules"]:
        by_v.setdefault(r["vuln_id"].upper(), []).append(r["id"])
        by_sv.setdefault(re.sub(r"r\d+_rule$", "", r["id"], flags=re.I).upper(), []).append(r["id"])
        by_stig.setdefault(r["stig_id"].upper(), []).append(r["id"])
        by_srg.setdefault(r["srg"].upper(), []).append(r["id"])
        for c in r["ccis"]:
            by_cci.setdefault(c.upper(), []).append(r["id"])
            for rev in nist:
                for idx in data["ccis"].get(c, {}).get(rev, []):
                    nist[rev].append((_norm_ctl(idx), r["id"]))

    def match(ident: str) -> tuple[str, list[str]]:
        u = ident.strip().upper()
        if _V.match(u):
            return "vulnerability ID", by_v.get(u, [])
        if _SV.match(u):
            return "rule ID", by_sv.get(re.sub(r"R\d+_RULE$", "", u), [])
        if _CCI.match(u):
            return "CCI", by_cci.get(u, [])
        if _SRG.match(u):
            return "SRG", by_srg.get(u, [])
        m = _NIST.match(ident.strip())
        if m and not _STIG.match(u):
            rev = (m.group(1) or "rev5").lower()
            q = _norm_ctl(m.group(2))
            hits = {rid for idx, rid in nist[rev]
                    if idx.startswith(q) and not idx[len(q):len(q) + 1].isdigit()}
            return f"NIST 800-53 {rev}", sorted(hits)
        if _STIG.match(u):
            return "STIG ID", by_stig.get(u, [])
        return "unrecognised", []

    return match


def compile_tags(data: dict | None = None, tag_dir: Path = TAG_DIR, out: Path = OUT, quiet: bool = False) -> dict:
    data = data or build.load()
    match = _matcher(data)
    tags, rules = [], {}
    for path in sorted(tag_dir.glob("*.csv")) if tag_dir.exists() else []:
        meta, rows = parse_file(path)
        tagged: set[str] = set()
        unmatched = []
        for ident, note, line in rows:
            kind, hits = match(ident)
            if not hits:
                unmatched.append((line, ident, kind))
                continue
            for rid in hits:
                tagged.add(rid)
                entry = rules.setdefault(rid, {})
                notes = entry.setdefault(meta["id"], [])
                if note and note not in notes:
                    notes.append(note)
        meta["count"] = len(tagged)
        meta["source"] = path.name
        tags.append(meta)
        if not quiet:
            print(f"  tag {meta['label']:<10} {path.name}: {len(rows)} entries -> {len(tagged)} rules")
            for line, ident, kind in unmatched:
                why = "not a recognised ID format" if kind == "unrecognised" else f"no rules match this {kind}"
                print(f"    ! line {line}: {ident!r}: {why}")
    payload = {"tags": tags, "rules": {rid: [[t, n] for t, n in v.items()] for rid, v in rules.items()}}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(JS_PREFIX + json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + ";\n", encoding="utf-8")
    if not quiet:
        shown = out.relative_to(build.ROOT) if out.is_relative_to(build.ROOT) else out
        print(f"  wrote {shown} ({len(tags)} tags, {len(rules)} tagged rules)")
    return payload


def load(path: Path = OUT) -> dict:
    if not path.exists():
        return {"tags": [], "rules": {}}
    text = path.read_text(encoding="utf-8")
    if text.startswith(JS_PREFIX):
        text = text[len(JS_PREFIX):].rstrip().rstrip(";")
    return json.loads(text)


def apply(data: dict, tagdata: dict | None = None) -> dict:
    """Attach r['tags'] = [tag ids] to each rule (used by the server and the document export)."""
    tagdata = tagdata if tagdata is not None else load()
    for r in data["rules"]:
        r["tags"] = [t for t, _ in tagdata["rules"].get(r["id"], [])]
    data["tag_defs"] = {t["id"]: t for t in tagdata["tags"]}
    return data


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compile tag files (tags/*.csv) into web/data/tags.js.")
    ap.add_argument("--dir", type=Path, default=TAG_DIR)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    if not build.OUT.exists():
        print(f"Data file {build.OUT} not found. Run: python -m stig_explorer.build", file=sys.stderr)
        return 1
    compile_tags(tag_dir=args.dir, out=args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
