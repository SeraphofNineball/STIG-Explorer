"""Build the STIG Explorer data file from DISA source files.

    python -m stig_explorer.build              # parse data/raw/ -> web/data/stig_data.js
    python -m stig_explorer.build --fetch      # download latest STIGs first
    python -m stig_explorer.build --docs       # also regenerate Markdown/Word docs

The output is a single JS file (window.STIG_DATA = {...}) so the web UI works
when opened straight from disk (file://) as well as when served by the
container. The server parses the same file.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

from . import __version__, explain, parse, settings, topics

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
OUT = ROOT / "web" / "data" / "stig_data.js"
JS_PREFIX = "window.STIG_DATA = "


def _equivalence_groups(rules: list[dict]) -> None:
    """Assign rule['eq'] so the same requirement can be compared across STIGs."""
    parent: dict[int, int] = {}

    def find(i: int) -> int:
        while parent.setdefault(i, i) != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        parent[find(a)] = find(b)

    first_by_key: dict[str, int] = {}
    for i, r in enumerate(rules):
        keys = [f"t:{r['platform']}:{explain.normalize_title(r['title'])}"]
        for s in r["settings"]:
            if s["type"] == "registry":
                keys.append(f"r:{s['target'].lower()}:{s['name'].lower()}")
            elif s["type"] == "sysctl":
                keys.append(f"k:{s['name']}")
            elif s["type"] == "gpo" and "User Rights" not in s["target"]:
                keys.append(f"g:{s['name'].lower()}:{s['value'].lower()}")
            else:
                continue
            break
        for k in keys:
            if k in first_by_key:
                union(i, first_by_key[k])
            else:
                first_by_key[k] = i
                find(i)

    groups: dict[int, list[int]] = {}
    for i in range(len(rules)):
        groups.setdefault(find(i), []).append(i)
    for gid, members in enumerate(sorted(groups.values(), key=lambda m: m[0])):
        for i in members:
            rules[i]["eq"] = gid if len({rules[j]["stig"] for j in members}) > 1 else None


def build(raw_dir: Path = RAW, out: Path = OUT) -> dict:
    benchmarks, cci = parse.load_inputs(raw_dir)
    if not benchmarks:
        raise SystemExit(f"No RHEL/Windows XCCDF benchmarks found under {raw_dir}. "
                         "Run with --fetch or place DISA STIG zips there.")
    if not cci:
        print("  ! U_CCI_List.xml not found - NIST 800-53 mappings will be empty.")

    all_rules: list[dict] = []
    stigs = []
    for b in benchmarks:
        for r in b["rules"]:
            r["stig"] = b["key"]
            r["platform"] = b["platform"]
            r["settings"] = settings.extract(r, b["platform"])
            r["setting_cats"] = settings.setting_categories(r["settings"], r["fix"])
            explain.enrich(r, b["platform"])
            all_rules.append(r)
        stigs.append({k: b[k] for k in ("key", "title", "product", "platform", "version",
                                         "release", "label", "date", "source")}
                     | {"count": len(b["rules"])})
        print(f"  {b['key']:<18} {b['label']:<7} {len(b['rules']):>4} rules  ({b['date']})")

    _equivalence_groups(all_rules)

    used_ccis = sorted({c for r in all_rules for c in r["ccis"]})
    cci_out = {c: cci.get(c, {"definition": "", "rev3": [], "rev4": [], "rev5": []}) for c in used_ccis}

    for r in all_rules:
        fams = set()
        for c in r["ccis"]:
            for rev in ("rev3", "rev4", "rev5"):
                for idx in cci_out[c][rev]:
                    if f := parse.control_family(idx):
                        fams.add(f)
        r["families"] = sorted(fams)

    used_topics = {t for r in all_rules for t in r["topics"]}
    topic_out = {
        t["id"]: {k: t[k] for k in ("name", "short", "attack", "pro", "admin", "impact", "generic")}
        for t in topics.TOPICS if t["id"] in used_topics
    }

    data = {
        "meta": {
            "tool": "STIG Explorer",
            "version": __version__,
            "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "source": "DISA STIG XCCDF benchmarks (public.cyber.mil) and DISA CCI List",
            "cci_count": len(cci),
            "rule_count": len(all_rules),
            "severity_text": explain.SEVERITY_PRO,
            "severity_plain": {k: list(v) for k, v in explain.SEVERITY_PLAIN.items()},
            "setting_types": settings.TYPE_LABELS,
            "families": FAMILY_NAMES,
        },
        "stigs": stigs,
        "topics": topic_out,
        "ccis": cci_out,
        "rules": [_slim(r) for r in all_rules],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    out.write_text(JS_PREFIX + payload + ";\n", encoding="utf-8")
    print(f"  wrote {out.relative_to(ROOT)} ({out.stat().st_size / 1e6:.1f} MB, {len(all_rules)} rules)")
    return data


def _slim(r: dict) -> dict:
    keep = ["id", "vuln_id", "stig_id", "stig", "platform", "srg", "title", "severity", "cat",
            "discussion", "mitigations", "potential_impacts", "severity_override", "third_party_tools",
            "documentable", "check", "fix", "ccis", "legacy_ids", "settings", "setting_cats",
            "topics", "plain", "glossary", "check_cmds", "families", "eq"]
    out = {k: r[k] for k in keep}
    for s in out["settings"]:
        s.pop("line", None)
    # Drop empty optional strings to keep the file small.
    for k in ("mitigations", "potential_impacts", "severity_override", "third_party_tools"):
        if not out[k]:
            del out[k]
    if not out["legacy_ids"]:
        del out["legacy_ids"]
    return out


def load(path: Path = OUT) -> dict:
    text = path.read_text(encoding="utf-8")
    if text.startswith(JS_PREFIX):
        text = text[len(JS_PREFIX):].rstrip().rstrip(";")
    return json.loads(text)


FAMILY_NAMES = {
    "AC": "Access Control", "AT": "Awareness and Training", "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring", "CM": "Configuration Management",
    "CP": "Contingency Planning", "IA": "Identification and Authentication", "IR": "Incident Response",
    "MA": "Maintenance", "MP": "Media Protection", "PE": "Physical and Environmental Protection",
    "PL": "Planning", "PM": "Program Management", "PS": "Personnel Security",
    "PT": "PII Processing and Transparency", "RA": "Risk Assessment",
    "SA": "System and Services Acquisition", "SC": "System and Communications Protection",
    "SI": "System and Information Integrity", "SR": "Supply Chain Risk Management",
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the STIG Explorer data file.")
    ap.add_argument("--raw", type=Path, default=RAW, help="Folder of DISA zips/XML (default: data/raw)")
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--fetch", action="store_true", help="Download the latest STIGs + CCI list first")
    ap.add_argument("--docs", action="store_true", help="Also regenerate Markdown and Word documents")
    args = ap.parse_args(argv)

    if args.fetch:
        from . import fetch
        print("Fetching latest STIGs from DISA ...")
        fetch.fetch_all(args.raw)
    print(f"Parsing {args.raw} ...")
    data = build(args.raw, args.out)
    if args.docs:
        from . import export_docs
        export_docs.export_all(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
