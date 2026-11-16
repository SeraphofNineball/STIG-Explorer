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


# Limits are intentionally conservative. Adjust only after reviewing trusted
# source sizes; compressed archive metadata is untrusted until verified.
MAX_XML_BYTES = 32 * 1024 * 1024
MAX_NESTED_ZIP_BYTES = 64 * 1024 * 1024
MAX_TOTAL_UNPACKED_BYTES = 256 * 1024 * 1024
MAX_XML_FILES = 10_000
MAX_ZIP_ENTRIES = 10_000
MAX_NESTED_ZIP_DEPTH = 4
MAX_COMPRESSION_RATIO = 300


class _InputBudget:
    def __init__(self) -> None:
        self.bytes = 0
        self.files = 0

    def add(self, count: int) -> None:
        self.bytes += count
        self.files += 1
        if self.bytes > MAX_TOTAL_UNPACKED_BYTES or self.files > MAX_XML_FILES:
            raise ValueError("Input archive exceeds cumulative size or file-count limit")


def _read_limited(stream, declared: int, limit: int, budget: _InputBudget) -> bytes:
    if declared > limit:
        raise ValueError(f"Archive member exceeds {limit} byte limit")
    data = stream.read(limit + 1)
    if len(data) > limit or len(data) != declared:
        raise ValueError("Archive member exceeds limit or has inconsistent size")
    budget.add(len(data))
    return data


# --------------------------------------------------------------------------
# Input discovery
# --------------------------------------------------------------------------

def iter_xml_blobs(path: Path, _budget: _InputBudget | None = None) -> Iterator[tuple[str, bytes]]:
    """Yield bounded XML blobs, descending into archives with a shared budget."""
    budget = _budget or _InputBudget()
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file() and child.suffix.lower() in (".xml", ".zip"):
                yield from iter_xml_blobs(child, budget)
        return
    if path.suffix.lower() == ".xml":
        with path.open("rb") as source:
            data = _read_limited(source, path.stat().st_size, MAX_XML_BYTES, budget)
        yield path.name, data
    elif path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as zf:
            yield from _iter_zip(zf, budget, depth=0)


def _iter_zip(zf: zipfile.ZipFile, budget: _InputBudget | None = None, depth: int = 0) -> Iterator[tuple[str, bytes]]:
    budget = budget or _InputBudget()
    if depth > MAX_NESTED_ZIP_DEPTH:
        raise ValueError("Nested ZIP depth limit exceeded")
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise ValueError("ZIP contains too many entries")
    for info in infos:
        low = info.filename.lower()
        if info.is_dir() or not low.endswith((".xml", ".zip")):
            continue
        limit = MAX_XML_BYTES if low.endswith(".xml") else MAX_NESTED_ZIP_BYTES
        if info.file_size > limit:
            raise ValueError(f"Unsafe ZIP entry size: {info.filename}")
        if info.file_size and (not info.compress_size or
                info.file_size / info.compress_size > MAX_COMPRESSION_RATIO):
            raise ValueError(f"Unsafe ZIP compression ratio: {info.filename}")
        with zf.open(info) as stream:
            data = _read_limited(stream, info.file_size, limit, budget)
        if low.endswith(".xml"):
            yield Path(info.filename).name, data
        else:
            with zipfile.ZipFile(io.BytesIO(data)) as inner:
                yield from _iter_zip(inner, budget, depth + 1)


def _check_xml(data: bytes) -> None:
    if len(data) > MAX_XML_BYTES:
        raise ValueError("XML input exceeds maximum size")
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("DTD and entity declarations are not permitted in STIG XML inputs")


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
    _check_xml(data)
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
    m = re.search(r"Ubuntu (\d+)\.(\d+)", t)
    if m:
        return f"UBUNTU_{m.group(1)}_{m.group(2)}"
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


def family_of(title: str) -> str:
    """OS family used for family-specific admin guidance: rhel | ubuntu | windows."""
    if "Ubuntu" in title:
        return "ubuntu"
    if "Red Hat" in title:
        return "rhel"
    if "Windows" in title:
        return "windows"
    return "other"


def platform_of(title: str) -> str:
    if "Red Hat" in title or "Linux" in title or "Ubuntu" in title:
        return "linux"
    if "Windows" in title:
        return "windows"
    return "other"


def parse_benchmark(data: bytes, source_name: str = "") -> dict:
    _check_xml(data)
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
        if severity not in SEVERITY_CAT:
            raise ValueError(f"Unrecognized STIG severity in {source_name}: {severity[:80]}")
        for field, value in (("Group", group.get("id", "")), ("Rule", rule.get("id", ""))):
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", value):
                raise ValueError(f"Invalid {field} ID in {source_name}")
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
        "family": family_of(title),
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
    def natural(b: dict) -> tuple:
        return (b["platform"], [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", b["key"])])
    return sorted(benchmarks.values(), key=natural), cci
