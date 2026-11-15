# STIG Explorer

A searchable database and web application for the **DISA STIGs for Red Hat Enterprise Linux and Microsoft Windows
desktop/server operating systems**. For every rule it shows what settings the rule changes and explains the rule at
three levels:

| Level | Audience | What it contains |
|---|---|---|
| **L1: Cyber Security Professional** | ISSOs, ISSMs, assessors, security engineers | DISA vulnerability discussion, threat & control context, MITRE ATT&CK techniques, CAT rationale, CCI → **NIST SP 800-53 Rev 3 / Rev 4 / Rev 5** mapping, documentable/mitigation notes |
| **L2: System Administrator** | Sysadmins and engineers | Exact settings changed (registry values, GPO paths, config-file lines, sysctl, dconf, services, packages, permissions, audit rules, Windows features), how it works, operational impact, quick verification commands, DISA check & fix text |
| **L3: General Audience** | Anyone with limited security or IT background | Plain-language restatement of the rule, why it matters (with an everyday analogy), how important it is, key terms |

**Current content:** 3,142 rules from 10 STIGs: RHEL 7 (final release V3R15; DISA has sunset it), 8, 9 and 10; Windows 10 and 11; Windows Server 2016, 2019, 2022 and 2025.

## Quick start

### Option 1: open it locally (no install)
Open `web/index.html` in any modern browser. Everything runs client-side from `web/data/stig_data.js`.

### Option 2: Docker / Podman
```bash
cd STIG_Explorer
docker compose up -d --build        # or: podman compose up -d --build
# browse to http://localhost:8080
```
Plain Docker without compose:
```bash
docker build -t stig-explorer .
docker run -d --name stig-explorer -p 127.0.0.1:8080:8080 --read-only --cap-drop ALL stig-explorer
```
The container runs as a non-root user on a read-only filesystem with all Linux capabilities dropped. By default it is
published on `127.0.0.1` only. Edit `docker-compose.yml` to expose it on the network.
(With Podman, add `--format docker` to `podman build` if you want the HEALTHCHECK to be kept.)

### Option 3: Python server (no container)
```bash
python3 -m stig_explorer.server --port 8080      # standard library only
```

## Documents (Word / Markdown)

Generated documents are in `docs/`:

| File | Contents |
|---|---|
| `docs/STIG_Explorer_Guide.md` / `.docx` | Overview, STIG inventory, NIST 800-53 Rev 3/5 family coverage, and a **topic reference that explains every security topic at all three levels** (good for training or briefings) |
| `docs/markdown/<STIG>.md` | Every rule in that STIG with all three levels, settings tables and DISA check/fix text |
| `docs/word/<STIG>.docx` | The same content as Word (open it and use *Update Field* to build the table of contents) |

## Updating to new DISA releases

DISA publishes STIG updates quarterly. To pull the newest releases and regenerate everything:
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt                    # only needed for Word output
python -m stig_explorer.build --fetch --docs       # download → parse → data file → .md/.docx
docker compose up -d --build                       # rebuild the container with the new data
```
`--fetch` probes `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/` for the newest `V#R#` of each product plus
`U_CCI_List.zip`. If that is unavailable (for example on an offline network), download the STIG zips and the CCI list from
<https://public.cyber.mil/stigs/downloads/> by hand, drop them (or the quarterly SRG-STIG library zip) into `data/raw/`, and run
`python -m stig_explorer.build --docs`. Nested zips are handled, and only the newest release of each STIG is kept.

To add another product, add its zip prefix to `PRODUCTS` in `stig_explorer/fetch.py` (RHEL and Windows XCCDF are recognised
automatically).

## Using the app

- **Search** matches all words (AND). Use `"quoted phrases"` and `-exclude`. Any identifier works: `V-257777`,
  `RHEL-09-211010`, `WN22-SO-000150`, `CCI-000366`, `AC-7`, as do setting names: `RestrictAnonymous`, `sshd_config`,
  `net.ipv4`, `faillock`.
- **Filters:** STIG, severity (CAT I/II/III), topic, NIST revision (Rev 5/4/3) with control family or a specific control
  (`IA-5(1)`), implementation type (registry, GPO, config file, package and so on) and documentable rules.
- **Explain for** (top bar) switches between General / SysAdmin / Cyber Pro / All. Your choice is remembered.
- **Related rules in other STIGs** shows the same requirement on other OS versions.
- **Topics** shows each security topic at the chosen level. **Export CSV** exports the filtered rule set.
- **Links:** `index.html#rule=V-257984&level=admin`, `#q=faillock`, `#view=topics`.

## JSON API (server/container only)

| Endpoint | Description |
|---|---|
| `GET /api/health` | Status, rule count, data build time |
| `GET /api/stigs` | STIGs loaded, with release and benchmark date |
| `GET /api/topics` | Topic knowledge base |
| `GET /api/search?q=&stig=RHEL_9,WIN_11&severity=high&topic=ssh&nist=AC-7&rev=rev5&limit=50&offset=0` | Full-text search (SQLite FTS5, BM25-ranked) with filters |
| `GET /api/rule/<SV-rule-id \| V-id \| STIG-id>` | Full rule with topic and CCI details |

## How the explanations are produced

- **Quoted from DISA:** title, severity, vulnerability discussion, check and fix text, CCIs, and CCI definitions with their
  NIST 800-53 Rev 3/4/5 references (DISA CCI List).
- **Extracted automatically:** the *Settings changed* table is parsed from the check/fix text (registry blocks, `Computer
  Configuration >> …` policy paths, user-rights account lists, config-file lines, `sysctl`, `dconf`, `systemctl`,
  `dnf`, `chmod`/`chown` and audit rules). Rules that are procedural (documentation, ISSO approval) are tagged as such.
- **Written for this tool:** each rule is mapped to one or two of ~40 security topics (`stig_explorer/topics.py`). Each
  topic has hand-written professional, sysadmin (RHEL- and Windows-specific) and plain-language explanations, operational
  impact notes and relevant MITRE ATT&CK techniques. A plain-language restatement of the rule title and a glossary of key
  terms are generated per rule.

The DISA STIG is always the authoritative source for compliance. Topic text is guidance. Check findings against the
official STIG and your AO's direction.

## Project layout

```
STIG_Explorer/
├── stig_explorer/
│   ├── fetch.py        # download latest STIGs + CCI list from DISA
│   ├── parse.py        # XCCDF + CCI list parsers (handles nested zips)
│   ├── settings.py     # extract the settings each rule changes
│   ├── topics.py       # topic knowledge base (3 levels) + glossary + classifier
│   ├── explain.py      # per-rule plain-language text, check commands
│   ├── build.py        # orchestrates → web/data/stig_data.js
│   ├── export_docs.py  # Markdown + Word documents
│   └── server.py       # stdlib web server + JSON API (SQLite FTS5)
├── web/                # index.html, app.js, style.css, data/stig_data.js
├── docs/               # generated guide and per-STIG .md/.docx
├── data/raw/           # DISA source zips (git-ignored)
├── tests/              # python -m unittest discover -s tests
├── Dockerfile
└── docker-compose.yml
```

## Requirements

- Python 3.10+ (standard library only for build, server and fetch)
- `python-docx` for Word output only
- Docker or Podman for the container option
