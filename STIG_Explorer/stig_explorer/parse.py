"""Parsers for DISA XCCDF STIG benchmarks and the DISA CCI list.

Accepts .xml files, .zip files, and zips nested inside zips (the quarterly
SRG-STIG library is a zip of zips), so users can drop whatever DISA gives
them into data/raw/.
"""

from __future__ import annotations

import html
import io
import re
import zipfile
from pathlib import Path
from typing import Iterator
import xml.etree.ElementTree as ET

XCCDF_NS = {"x": "http://checklists.nist.gov/xccdf/1.1"}
CCI_NS = {"c": "http://iase.disa.mil/cci"}

SEVERITY_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}

# Fields embedded (HTML-escaped) inside the XCCDF <description> element.
DESC_FIELDS = [
    "VulnDiscussion", "FalsePositives", "FalseNegatives", "Documentable",
    "Mitigations", "SeverityOverrideGuidance", "PotentialImpacts",
    "ThirdPartyTools", "MitigationControl", "Responsibility", "IAControls",
]


# --------------------------------------------------------------------------
# Input discovery
# --------------------------------------------------------------------------

def iter_xml_blobs(path: Path) -> Iterator[tuple[str, bytes]]:
    """Yield (name, bytes) for every XML file under path, descending into zips."""
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file() and child.suffix.lower() in (".xml", ".zip"):
                yield from iter_xml_blobs(child)
        return
    if path.suffix.lower() == ".xml":
        yield path.name, path.read_bytes()
    elif path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as zf:
            yield from _iter_zip(zf)


def _iter_zip(zf: zipfile.ZipFile) -> Iterator[tuple[str, bytes]]:
    for info in zf.infolist():
        name = info.filename
        low = name.lower()
        if info.is_dir():
            continue
        if low.endswith(".xml"):
            yield Path(name).name, zf.read(info)
        elif low.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(zf.read(info))) as inner:
                yield from _iter_zip(inner)


def classify_xml(data: bytes) -> str:
    head = data[:4096].decode("utf-8", "ignore")
    if "<cci_list" in head:
        return "cci"
    if "<Benchmark" in head and "checklists.nist.gov/xccdf" in head:
        return "xccdf"
    return "other"


# --------------------------------------------------------------------------
# CCI list
# --------------------------------------------------------------------------

def parse_cci_list(data: bytes) -> dict[str, dict]:
    """Return {CCI-ID: {definition, rev3: [...], rev4: [...], rev5: [...]}}."""
    root = ET.fromstring(data)
    out: dict[str, dict] = {}
    for item in root.iterfind(".//c:cci_item", CCI_NS):
        refs = {"rev3": [], "rev4": [], "rev5": []}
        for ref in item.iterfind(".//c:reference", CCI_NS):
            title = ref.get("title", "")
            index = (ref.get("index") or "").strip()
            if not index:
                continue
            if title == "NIST SP 800-53":
                refs["rev3"].append(index)
            elif title == "NIST SP 800-53 Revision 4":
                refs["rev4"].append(index)
            elif title == "NIST SP 800-53 Revision 5":
                refs["rev5"].append(index)
        out[item.get("id")] = {
            "definition": (item.findtext("c:definition", "", CCI_NS) or "").strip(),
            **refs,
        }
    return out


def control_family(index: str) -> str:
    """'AC-2 (4)' -> 'AC'."""
    m = re.match(r"([A-Z]{2})-", index)
    return m.group(1) if m else ""


def base_control(index: str) -> str:
    """'AC-17 (2)' -> 'AC-17 (2)'; 'CM-6 b' -> 'CM-6'; 'AU-12 c' -> 'AU-12'."""
    m = re.match(r"([A-Z]{2}-\d+)(\s*\(\d+\))?", index)
    if not m:
        return index
    return m.group(1) + (" " + m.group(2).strip() if m.group(2) else "")


# --------------------------------------------------------------------------
# XCCDF benchmarks
# --------------------------------------------------------------------------

def _clean(text: str | None) -> str:
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace(" ", " ")
    # Normalise trailing whitespace per line, keep layout for commands.
    lines = [ln.rstrip() for ln in text.split("\n")]
    return "\n".join(lines).strip()


def _desc_fields(raw: str) -> dict[str, str]:
    raw = html.unescape(raw or "")
    fields = {}
    for name in DESC_FIELDS:
        m = re.search(rf"<{name}>(.*?)</{name}>", raw, re.S)
        fields[name] = _clean(m.group(1)) if m else ""
    return fields


def stig_key(benchmark_id: str, title: str) -> str:
    """A short stable key such as RHEL_9 or WIN_SERVER_2022."""
    t = title
    m = re.search(r"Red Hat Enterprise Linux (\d+)", t)
    if m:
        return f"RHEL_{m.group(1)}"
    m = re.search(r"Windows Server (\d{4})", t)
    if m:
        return f"WIN_SERVER_{m.group(1)}"
    m = re.search(r"Windows (\d+)\b", t)
    if m:
        return f"WIN_{m.group(1)}"
    return re.sub(r"[^A-Za-z0-9]+", "_", benchmark_id).strip("_").upper()


def product_name(title: str) -> str:
    return re.sub(r"\s*Security Technical Implementation Guide\s*$", "", title).strip()


def platform_of(title: str) -> str:
    if "Red Hat" in title or "Linux" in title:
        return "linux"
    if "Windows" in title:
        return "windows"
    return "other"


def parse_benchmark(data: bytes, source_name: str = "") -> dict:
    root = ET.fromstring(data)
    title = _clean(root.findtext("x:title", "", XCCDF_NS))
    release_info = _clean(root.findtext("x:plain-text[@id='release-info']", "", XCCDF_NS))
    version = _clean(root.findtext("x:version", "", XCCDF_NS))
    rel = re.search(r"Release:\s*(\d+)", release_info)
    date = re.search(r"Benchmark Date:\s*(.+)$", release_info)
    key = stig_key(root.get("id", ""), title)

    rules = []
    for group in root.iterfind("x:Group", XCCDF_NS):
        rule = group.find("x:Rule", XCCDF_NS)
        if rule is None:
            continue
        fields = _desc_fields(rule.findtext("x:description", "", XCCDF_NS))
        severity = (rule.get("severity") or "medium").lower()
        ccis = [i.text.strip() for i in rule.iterfind("x:ident", XCCDF_NS)
                if i.text and i.text.strip().startswith("CCI-")]
        legacy = [i.text.strip() for i in rule.iterfind("x:ident", XCCDF_NS)
                  if i.text and not i.text.strip().startswith("CCI-")]
        rules.append({
            "id": rule.get("id", ""),
            "vuln_id": group.get("id", ""),
            "stig_id": _clean(rule.findtext("x:version", "", XCCDF_NS)),
            "srg": _clean(group.findtext("x:title", "", XCCDF_NS)),
            "title": " ".join(_clean(rule.findtext("x:title", "", XCCDF_NS)).split()),
            "severity": severity,
            "cat": SEVERITY_CAT.get(severity, ""),
            "discussion": fields["VulnDiscussion"],
            "mitigations": fields["Mitigations"],
            "potential_impacts": fields["PotentialImpacts"],
            "severity_override": fields["SeverityOverrideGuidance"],
            "third_party_tools": fields["ThirdPartyTools"],
            "documentable": fields["Documentable"].lower() == "true",
            "check": _clean(rule.findtext(".//x:check-content", "", XCCDF_NS)),
            "fix": _clean(rule.findtext("x:fixtext", "", XCCDF_NS)),
            "ccis": ccis,
            "legacy_ids": legacy,
        })

    return {
        "key": key,
        "benchmark_id": root.get("id", ""),
        "title": title,
        "product": product_name(title),
        "platform": platform_of(title),
        "version": version,
        "release": rel.group(1) if rel else "",
        "label": f"V{version}R{rel.group(1)}" if rel else f"V{version}",
        "date": date.group(1).strip() if date else "",
        "status_date": root.find("x:status", XCCDF_NS).get("date", "") if root.find("x:status", XCCDF_NS) is not None else "",
        "source": source_name,
        "rules": rules,
    }


def _release_tuple(b: dict) -> tuple[int, int]:
    try:
        return int(b["version"]), int(b["release"] or 0)
    except ValueError:
        return 0, 0


def load_inputs(raw_dir: Path) -> tuple[list[dict], dict[str, dict]]:
    """Parse everything under raw_dir. Keeps only the newest release per STIG."""
    benchmarks: dict[str, dict] = {}
    cci: dict[str, dict] = {}
    for name, blob in iter_xml_blobs(raw_dir):
        kind = classify_xml(blob)
        if kind == "cci":
            cci = parse_cci_list(blob)
        elif kind == "xccdf":
            try:
                b = parse_benchmark(blob, name)
            except ET.ParseError as exc:
                print(f"  ! skipping {name}: {exc}")
                continue
            if b["platform"] not in ("linux", "windows"):
                continue
            prev = benchmarks.get(b["key"])
            if prev is None or _release_tuple(b) > _release_tuple(prev):
                benchmarks[b["key"]] = b
    return sorted(benchmarks.values(), key=lambda b: (b["platform"], b["key"])), cci
