# STIG Explorer

STIG Explorer is a searchable database and web application for the **DISA Security Technical Implementation Guides
(STIGs)** for Red Hat Enterprise Linux, Canonical Ubuntu and Microsoft Windows desktop and server operating systems. For
every rule it shows **exactly what setting the rule changes**, **how to check it from the command line**, and **why it
matters**, explained at three levels so the same rule can be read by an assessor, an administrator or a non-technical
stakeholder.

It runs entirely offline from a single HTML page, or as a hardened Docker/Podman container with a JSON API. It also
generates Word and Markdown documents.

**Features at a glance**

- **3,877 rules from 14 STIGs**: RHEL 7, 8, 9 and 10; Ubuntu 18.04, 20.04, 22.04 and 24.04 LTS; Windows 10 and 11;
  Windows Server 2016, 2019, 2022 and 2025
- **Three explanation levels** for every rule: Cyber Security Professional, System Administrator and General Audience
- **Settings changed**: registry values, Group Policy paths, config-file lines, kernel parameters, services, packages,
  permissions and audit rules, extracted from DISA's text
- **Command-line validation** with a Copy button per command: PowerShell, CMD and Bash commands, each with its
  expected result
- **Validation script export**: download `.ps1` or `.sh` scripts that run only narrowly approved, read-only checks; other commands require manual review
- **NIST SP 800-53 Rev 3, Rev 4 and Rev 5** mapping for every rule, through DISA's CCI List
- **Domain controller views** for every Windows Server STIG, in the app and in the documents
- **Custom tags** such as **FMCC** (Federally Mandated Critical Controls), maintained in a CSV file
- **Full-text search, filters, cross-STIG comparison** and CSV export
- **Word and Markdown documents**: a training-style guide plus one document per STIG
- **One command to refresh** from DISA's latest quarterly releases

> The DISA STIG is always the authoritative source for compliance. Check and fix text, vulnerability discussions and
> CCI definitions are quoted from DISA. Topic explanations, threat context, plain-language summaries and generated
> commands are STIG Explorer guidance. Validate findings against the official STIG and your AO's direction.

---

## Contents

1. [What's included](#whats-included)
2. [Quick start](#quick-start)
3. [Using the app](#using-the-app)
4. [Command-line validation](#command-line-validation)
5. [Validation scripts](#validation-scripts)
6. [Domain controllers](#domain-controllers)
7. [Custom tags (FMCC)](#custom-tags-fmcc)
8. [Word and Markdown documents](#word-and-markdown-documents)
9. [Keeping content current](#keeping-content-current)
10. [Command reference](#command-reference)
11. [JSON API](#json-api)
12. [Container deployment and security](#container-deployment-and-security)
13. [How the content is produced](#how-the-content-is-produced)
14. [Project layout and development](#project-layout-and-development)
15. [Troubleshooting](#troubleshooting)
16. [Requirements and limitations](#requirements-and-limitations)

---

## What's included

| Platform | STIG | Release | Benchmark date | Rules |
|---|---|---|---|---|
| Red Hat Enterprise Linux | RHEL 7 *(sunset by DISA; final release)* | V3R15 | 24 Jul 2024 | 244 |
| | RHEL 8 | V2R9 | 30 Sep 2026 | 371 |
| | RHEL 9 | V2R10 | 30 Sep 2026 | 445 |
| | RHEL 10 | V1R3 | 30 Sep 2026 | 435 |
| Canonical Ubuntu | Ubuntu 18.04 LTS *(sunset by DISA; final release)* | V2R15 | 24 Jul 2024 | 176 |
| | Ubuntu 20.04 LTS | V2R4 | 01 Oct 2025 | 173 |
| | Ubuntu 22.04 LTS | V2R10 | 30 Sep 2026 | 191 |
| | Ubuntu 24.04 LTS | V1R7 | 30 Sep 2026 | 195 |
| Microsoft Windows | Windows 10 | V3R6 | 05 Jan 2026 | 267 |
| | Windows 11 | V2R11 | 30 Sep 2026 | 257 |
| Microsoft Windows Server | Windows Server 2016 *(+ domain controller view)* | V2R10 | 15 Jan 2025 | 273 |
| | Windows Server 2019 *(+ domain controller view)* | V3R9 | 01 Jul 2026 | 282 |
| | Windows Server 2022 *(+ domain controller view)* | V2R11 | 30 Sep 2026 | 277 |
| | Windows Server 2025 *(+ domain controller view)* | V1R4 | 30 Sep 2026 | 291 |

Severity breakdown: 367 CAT I, 3,292 CAT II, 218 CAT III.

**Not included: Windows Server 2012/2012 R2.** DISA has removed the 2012 Domain Controller and Member Server STIGs
from its download server. If you have the zips archived (`U_MS_Windows_2012_and_2012_R2_DC_*` / `_MS_*`), drop them
into `data/raw/` and rebuild. They should parse like the other Windows STIGs, but this is untested.

Releases are refreshed with one command. See [Keeping content current](#keeping-content-current).

---

## Quick start

### Option 1: open it locally (no install, works offline)

Open `web/index.html` in any modern browser. Everything runs client-side from `web/data/stig_data.js` and
`web/data/tags.js`; no server, internet access or installation is needed. This is the simplest way to use it on an
isolated or classified network.

### Option 2: Docker or Podman

```bash
cd STIG_Explorer
docker compose up -d --build        # or: podman compose up -d --build
# browse to http://localhost:8080
```

Without compose:

```bash
docker build -t stig-explorer .
docker run -d --name stig-explorer -p 127.0.0.1:8080:8080 --read-only --cap-drop ALL stig-explorer
```

The container adds the [JSON API](#json-api). It is published on `127.0.0.1` only by default; see
[Container deployment and security](#container-deployment-and-security) to expose it on a network.

### Option 3: Python server (no container)

```bash
cd STIG_Explorer
python3 -m stig_explorer.server --port 8080      # standard library only
```

---

## Using the app

The screen has three panes: **filters** on the left, **results** in the middle and the **rule detail** on the right. On
narrow screens the panes stack, with a **Filters** button and a **Back to results** button. The top bar holds the views
(**Rules**, **Topics**, **About**), the **Explain for** level switch and the light/dark theme toggle.

### Explanation levels

**Explain for** in the top bar chooses what the rule detail shows. Your choice is remembered.

| Level | For | Contents |
|---|---|---|
| **General** (L3) | Anyone with limited security or IT background | Plain-language restatement of the rule ("This computer must…"), why it matters with an everyday analogy, how important it is (CAT I/II/III in plain words), and definitions of key terms |
| **SysAdmin** (L2) | System administrators and engineers | **Settings changed** table, **command-line validation**, remediation commands, how the mechanism works (written separately for RHEL, Ubuntu and Windows), operational impact, DISA-noted potential impacts, and the full DISA check and fix procedures with Copy buttons |
| **Cyber Pro** (L1) | ISSOs, ISSMs, assessors, security engineers | DISA vulnerability discussion, threat and control context, relevant MITRE ATT&CK techniques, CAT definition, CCI to NIST SP 800-53 Rev 5 / Rev 4 / Rev 3 mapping with CCI definitions, SRG, documentable flag, DISA mitigations and severity-override guidance |
| **All** | Briefings and full reviews | All three levels, one after another |

### Searching

Type in the search box; results update as you type.

- All words must match (AND). Use `"quoted phrases"` for exact phrases and `-word` to exclude.
- Any identifier works: `V-257777`, `RHEL-09-211010`, `WN22-SO-000150`, `UBTU-22-611035`, `SV-257777r…_rule`,
  `CCI-000366`, `SRG-OS-000480-GPOS-00227`, `AC-7`.
- Setting names and values work too: `RestrictAnonymous`, `LmCompatibilityLevel`, `sshd_config`, `PermitRootLogin`,
  `net.ipv4`, `faillock`, `pwquality`, `auditpol`.
- Search also covers topic names, server roles (`domain controller`), tags (`fmcc`), validation commands and the full
  DISA text.

Exact ID matches rank first, then title matches, then setting matches. **Sort** offers STIG/ID, severity or topic order.
Results load 120 at a time; use **Show more** for the rest.

### Filters

| Filter | What it does |
|---|---|
| **STIG** | Tick STIGs individually, or use **only** next to Red Hat, Ubuntu or Windows to select a whole family. Your selection is remembered. |
| **Domain controller views** | One click shows every rule that applies to a domain controller for that Windows Server version. See [Domain controllers](#domain-controllers). |
| **Severity** | CAT I (high), CAT II (medium), CAT III (low) |
| **Topic** | One of 42 security topics, such as Account Lockout, SSH Remote Administration, Windows User Rights Assignment or Data-at-Rest Encryption |
| **NIST SP 800-53** | Choose **Rev 5**, **Rev 4** or **Rev 3**, then a control family (`AC`, `AU`, `IA`…) or a specific control (`AC-7`, `IA-5(1)`). `AC-1` matches `AC-1 a` but not `AC-12`. |
| **Implemented via** | How the rule is applied: registry value, Group Policy, config file, kernel parameter, service, package, permission, audit rule, Windows feature, procedural/documentation, and so on |
| **Windows Server role** | Domain controller (all that apply), domain controller-specific only, member server (all that apply), member server-specific only |
| **Tags** | Custom tags such as FMCC. Appears once a tag file exists; see [Custom tags](#custom-tags-fmcc). |
| **Documentable only** | Rules DISA marks as documentable (a deviation can be documented with the ISSO/AO) |

**Reset** clears every filter. The bar above the results shows how many rules match, with a CAT I/II/III breakdown.

### Rule detail

Selecting a rule shows:

- **Header:** severity, STIG and release, V-ID, STIG ID and rule ID, server role, any tag badges (with your tag note),
  topic chips (select one to filter by that topic), CCIs and the NIST 800-53 Rev 5 controls.
- **Actions:** **Copy link** (a direct link to this rule), **Copy as Markdown** (the rule summarised for a ticket,
  email or wiki, including its validation commands) and **Print** (prints just the rule).
- **The explanation levels** chosen in the top bar.
- **Related rules in other STIGs:** the same requirement or setting on other OS versions, for example the same
  registry value across Windows 10, 11 and Server 2016 to 2025. Select one to jump to it.

### Topics and About

- **Topics** shows all 42 security topics as cards, explained at the selected level. At SysAdmin level each card shows
  the RHEL, Ubuntu and Windows guidance side by side. **View rules →** filters the results to that topic.
- **About** lists the loaded STIGs with release, benchmark date and severity counts, plus search tips.

### Exports

- **Export CSV** saves the filtered rules: STIG, release, IDs, severity, title, plain-language summary, topic, SRG,
  server role, CCIs, NIST Rev 5/4/3, settings, validation commands, check and fix text, and tags. It opens directly
  in Excel.
- **Export script ▾** builds a validation script for the filtered rules. See [Validation scripts](#validation-scripts).

### Links, preferences and keyboard

- **Links** open a rule, search or view directly, and work for both the local file and the server:
  - `index.html#rule=V-257984` (a V-ID, STIG ID or rule ID all work)
  - `index.html#rule=WN22-SO-000150&level=admin` (`level` = `generic`, `admin`, `pro` or `all`)
  - `index.html#q=faillock`
  - `index.html#view=topics&level=pro` (`view` = `rules`, `topics` or `about`)
- **Remembered in your browser:** explanation level, STIG selection and light/dark theme. This is stored per browser
  only, and the app works normally if browser storage is blocked.
- **Keyboard:** in the results list, ↑/↓ move between rules and Enter opens one.
- **Theme:** follows your system light/dark setting; ◐ overrides it.

---

## Command-line validation

Every rule's **SysAdmin** level has a **Command-line validation** section. It lists commands that show the current value
of the setting, so you don't have to browse the Group Policy editor or dig through configuration files. Each command
has a shell label (**PowerShell**, **CMD** or **Bash**), a source label, its own **Copy** button and an **Expected**
result.

3,799 of the 3,877 rules have at least one command. The remaining 78 are procedural (documentation, approvals,
physical checks) and say so.

| Setting type | Commands |
|---|---|
| Registry-backed policy (Windows) | `Get-ItemProperty -Path 'HKLM:\…' -Name '…'` and `reg query "HKLM\…" /v "…"` |
| User Rights Assignment | `secedit /export … /areas USER_RIGHTS`, filtered to the exact privilege constant (e.g. `SeDebugPrivilege`); the expected text explains the SIDs in the output (`*S-1-5-32-544` = Administrators, and so on) |
| Account, lockout and Kerberos policy | `secedit /export … /areas SECURITYPOLICY` filtered to the key (e.g. `LockoutBadCount`), plus `net accounts` |
| Advanced Audit Policy | `auditpol /get /subcategory:"Logon"` |
| Windows features | `Get-WindowsFeature` (Server) or `Get-WindowsOptionalFeature -Online` (client) |
| Other Windows checks | Hand-written commands for TPM (`Get-Tpm`), Secure Boot (`Confirm-SecureBootUEFI`), UEFI, BitLocker (`manage-bde -status`), group membership, local accounts, file and event-log ACLs (`icacls`), certificate stores (DoD Root CA, cross-certificates), Defender status, firewall profiles, OpenSSH on Server 2025, and Active Directory object auditing and permissions (`Get-Acl "AD:…"`) for domain controllers |
| Linux kernel parameters | `sysctl <key>`, plus a `grep` of every sysctl configuration location to catch conflicting values |
| SSH | `sshd -T`, the effective configuration sshd is actually using |
| Config files | `grep` for the key in the exact file or drop-in directory |
| Audit rules | `auditctl -l` filtered to the watched path or syscall, and `auditctl -s` for immutability |
| Services and packages | `systemctl is-enabled / is-active`, `rpm -q` (RHEL), `dpkg -l` (Ubuntu) |
| File permissions | `stat -c '%a %U %G %n' <path>` |

Commands quoted in DISA's own check text are included too, labelled **From DISA check text**. Others are labelled
**Generated from the setting** or **STIG Explorer command**.

**Safety:** DISA's original check text is authoritative, but extracted commands are *not* inherently safe to execute.
The Copy button shows the original command and may include checks that change files, expose credential material or take a
long time. **Review before manually running or copying anything.** An alert identifies commands excluded from automated
exports. The exporter selects only a conservative set of approved read-only command forms (e.g. `sysctl key`, `rpm -q
package`, `systemctl is-enabled service`, specific `Get-ItemProperty` queries, and `auditpol /get`). Everything else,
including all checks reading `/etc/shadow`, is **manual-only**. The three full password-hash-reading commands for
V-230232, V-258231 and V-281221 are not executed or logged by generated scripts.

---

## Validation scripts

**Export script ▾** in the results bar turns the validation commands for the **currently filtered rules** into a
script you can copy to a system and run:

| Script | For | Run with |
|---|---|---|
| **PowerShell (`.ps1`)** | Windows rules | `powershell.exe -ExecutionPolicy Bypass -File .\stig_validation.ps1 [-All] [-LogPath results.txt]` from an elevated prompt |
| **Bash (`.sh`)** | RHEL and Ubuntu rules | `sudo bash stig_validation.sh [--all]` |

How the scripts behave:

- **They run only what applies.** The script detects the OS (Windows 10/11 and Server 2016–2025 from the OS caption;
  RHEL and its rebuilds, and Ubuntu, from `/etc/os-release`) and runs only that STIG's checks. On Windows Server it
  also detects whether the machine is a domain controller and skips rules for the other role. `-All` / `--all` runs
  every check in the file.
- **Only allowlisted checks execute.** Unsupported/complex commands, `secedit` exports, shell pipelines and all
  password-hash-reading commands are marked manual-only. The scripts no longer create a temporary CMD file.
- **They report but don't judge.** Each check prints the rule ID, severity, title (with any tag such as `[FMCC]`), the
  command, the expected result and the actual output. The script does not decide pass or fail; review each output
  against *Expected*. `-LogPath` saves the whole run to a file; on Linux, redirect the output (`> results.txt`).
- **Manual checks are listed, not run.** Commands outside the narrow reviewed allowlist (including placeholders and
  complex shell expressions) appear at the end as comments alongside procedural rules.
- **They work without sudo installed.** When the Bash script runs as root it drops `sudo` from commands automatically.

Filter first to keep scripts focused, for example one STIG, CAT I only, or a single tag such as FMCC. Exporting every
rule includes approximately 692 approved Windows commands and 358 approved Linux commands (from the supplied
November 2026 dataset); the other commands are manual-only. Rebuilt data may change these counts.

---

## Domain controllers

DISA publishes one STIG per Windows Server version that covers both domain controllers and member servers. STIG
Explorer tags every Windows Server rule with its role, using DISA's STIG ID (`WN22-DC-…` = domain controller,
`WN22-MS-…` = member server) and the "NA" statements in the check text:

| Role | Rules (all four Server versions) |
|---|---|
| Domain controller only | 174 |
| Member server only | 59 |
| All servers | 890 |

Where domain controllers appear:

- **In the app:** a purple **Domain controller only** chip on DC rules and a teal **Member server only** chip on
  member-server rules. The **Domain controller views** list in the STIG filter shows everything that applies to a DC
  for a given Server version. The **Windows Server role** filter offers both role-specific and "all that apply"
  options.
- **In the documents:** each Windows Server document has three sections: *Rules for all servers*, *Domain
  controller-only rules* and *Member server-only rules*. A separate **`WIN_SERVER_<version>_DC`** document per version
  contains only what applies to a domain controller, with the DC-specific rules first.
- **In validation scripts:** they detect domain controllers automatically. See above.

---

## Custom tags (FMCC)

DISA's STIG files don't mark any rule as a *Federally Mandated Critical Control* (FMCC). STIG Explorer lets you maintain
that list yourself, along with any others you need, such as an AO priority list, a contract subset or a POA&M
watch-list. Each CSV file in `tags/` defines one tag. `tags/FMCC.csv` ships as an **empty template**.

**1. Add identifiers.** Open `tags/FMCC.csv` in Excel or any editor and add one identifier per row. The optional second
column is a note, such as the source document and paragraph, which is shown on the rule in the app:

```csv
id,note
V-257984,Source doc para 3.2
WN22-SO-000150,
CCI-000048,All logon-banner rules
IA-5(1),
rev3:AC-17,
```

| Identifier | Tags |
|---|---|
| `V-257984`, `RHEL-09-255040`, `SV-257984r…_rule` (the revision suffix is optional) | that one rule |
| `CCI-000048` | every rule that cites the CCI |
| `AC-7`, `IA-5(1)`, `IA-5 (1)` | every rule mapped to that NIST 800-53 **Rev 5** control (`rev3:` / `rev4:` prefixes use those revisions) |
| `SRG-OS-000480-GPOS-00227` | every rule under that SRG requirement |

**2. Compile.** Run `python -m stig_explorer.tags`. It needs no internet access and no DISA zips, and it prints how many
rules each file tagged. It also lists any identifier that matched nothing, with the line number, so typos are caught:

```
  tag FMCC       FMCC.csv: 5 entries -> 212 rules
    ! line 26: 'V-99999': no rules match this vulnerability ID
```

**3. Reload the app.** Tagged rules get:
- a colored **FMCC** badge in the results list and on the rule page, plus a callout with your note
- a **Tags** filter, and searching `fmcc` finds them
- a Tags column in the CSV export and `[FMCC]` in validation scripts
- tags in the Word/Markdown documents (re-run `python -m stig_explorer.export_docs`)
- tags in the API (`/api/tags`, `/api/search?tag=fmcc`)

**More tags:** copy `FMCC.csv` to a new file such as `AO_PRIORITY.csv` and edit its header lines:

```
# label: FMCC                                  (short badge text)
# name: Federally Mandated Critical Control    (full name, shown on hover and in the callout)
# color: #b71c1c                               (badge color, #rrggbb)
# description: …                               (shown in the Tags filter)
```

**Containers:** the container serves the compiled `web/data/tags.js`. Rebuild the image after compiling, or uncomment
the tags volume in `docker-compose.yml` so changes are picked up on restart.

---

## Word and Markdown documents

Generated documents are in `docs/`. Word files are in `docs/word/` and Markdown files in `docs/markdown/`.

| Document | Contents |
|---|---|
| `STIG_Explorer_Guide.docx` / `.md` | Purpose and how to read the documents; STIG inventory (including domain controller views) with severity counts; NIST 800-53 Rev 5 and Rev 3 control-family coverage; a **topic reference explaining all 42 security topics at all three levels**, with RHEL, Ubuntu and Windows administrator guidance (useful as training material or for briefings); severity definitions; how to use the app |
| `<STIG>.docx` / `.md` (14 files) | Every rule in the STIG: an ID/severity/SRG/topic/CCI/NIST Rev 5/4/3 table, server role and tags, then all three explanation levels including settings changed, command-line validation and DISA check/fix text. Each document opens with a summary by severity, topic and tag. |
| `WIN_SERVER_<ver>_DC.docx` / `.md` (4 files) | Domain controller view of each Windows Server STIG: DC-specific rules, then rules common to all servers |

In Word, right-click the table of contents and choose **Update Field** to build it. Regenerate the documents with
`python -m stig_explorer.export_docs` (or `build --docs`). Word output needs `python-docx`.

---

## Keeping content current

DISA publishes STIG updates quarterly. To pull the newest releases and regenerate everything:

```bash
cd STIG_Explorer
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt                    # python-docx, only for Word output
python -m stig_explorer.build --fetch --docs       # download, parse, build data, compile tags, write documents
docker compose up -d --build                       # if you use the container
```

`--fetch` enforces a maximum download size, records locally observed `.sha256` hashes and checks recorded hashes
when using cached files. A recorded hash does **not** independently prove authenticity: compare against a trusted
external release digest when available. ZIP parsing imposes size, ratio, file-count and depth limits.

`--fetch` probes `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/` for the newest `V#R#` of each product, plus
`U_CCI_List.zip` (the CCI-to-NIST mapping), and removes older releases from `data/raw/`.

**Offline or air-gapped networks:** the DISA source zips are committed to this repository in `data/raw/`, so a clone
already has everything needed to rebuild. On the air-gapped machine, run the build without `--fetch`:

```bash
cd STIG_Explorer
python -m stig_explorer.build --docs               # parse data/raw/, build data, compile tags, write documents
```

`--docs` writes Word files only when `python-docx` is installed; without it, the Markdown documents are still written
and the app and its data are unaffected. Because `pip install` needs internet access, download the packages on a
connected machine and carry them across:

```bash
# On a connected machine (same Python version and OS as the air-gapped machine)
pip download -r requirements.txt -d wheels/

# On the air-gapped machine
pip install --no-index --find-links wheels/ -r requirements.txt
```

To update the STIGs, run `python -m stig_explorer.build --fetch --docs` on a connected machine, commit and push the
new zips in `data/raw/` with the regenerated files, then bring the updated repository across to the air-gapped network.
You can also download zips manually from <https://public.cyber.mil/stigs/downloads/> (or use the quarterly SRG-STIG
library zip) and copy them into `data/raw/`. Nested zips are handled, and if several releases of the same STIG are
present only the newest is used.

**Adding a product:** add its DISA zip prefix (e.g. `U_CAN_Ubuntu_26-04_LTS`) to `PRODUCTS` in
`stig_explorer/fetch.py`. RHEL, Ubuntu and Windows XCCDF files are recognised automatically. Other products need a small
addition to `parse.py` (`stig_key`, `family_of`, `platform_of`).

---

## Command reference

Run these from `STIG_Explorer/`. Only `build --fetch` needs internet access.

| Command | Purpose | Options |
|---|---|---|
| `python -m stig_explorer.build` | Parse DISA files in `data/raw/`, write `web/data/stig_data.js` and compile tags | `--fetch` download the latest releases first · `--docs` also write Word/Markdown · `--raw DIR` source folder · `--out FILE` data file |
| `python -m stig_explorer.fetch` | Download the latest STIG zips and CCI list only | `--dest DIR` (default `data/raw`) · `--product U_RHEL_9` (repeatable) |
| `python -m stig_explorer.tags` | Compile `tags/*.csv` into `web/data/tags.js` | `--dir DIR` · `--out FILE` |
| `python -m stig_explorer.export_docs` | Write Word and Markdown documents | `--stig RHEL_9` (repeatable) · `--no-word` |
| `python -m stig_explorer.server` | Web UI and JSON API | `--host` (default `127.0.0.1`, env `STIGX_HOST`) · `--port` (default `8080`, env `STIGX_PORT`) · `--data FILE` · env `STIGX_QUIET=1` silences request logs |
| `python -m unittest discover -s tests` | Run the test suite | |

---

## JSON API

Available when running the server or container. All endpoints are read-only `GET` requests that return JSON.

| Endpoint | Returns |
|---|---|
| `/api/health` | Status, rule count, data build time |
| `/api/stigs` | Loaded STIGs with release, benchmark date and rule count |
| `/api/topics` | The topic knowledge base (all three levels) |
| `/api/tags` | Custom tags (e.g. FMCC) with how many rules each covers |
| `/api/search` | Full-text search (SQLite FTS5, BM25-ranked) with filters (see below) |
| `/api/rule/<id>` | One full rule, including settings, validation commands, topic and CCI details, server role and tags with notes. `<id>` can be a rule ID, V-ID or STIG ID. |

`/api/search` parameters (all optional): `q` (text; `"phrases"` supported), `stig` (comma-separated keys, e.g.
`RHEL_9,WIN_11`), `severity` (`high,medium,low`), `topic` (topic id, e.g. `ssh`), `nist` (control, e.g. `AC-7` or
`IA-5(1)`) with `rev` (`rev5` default, `rev4`, `rev3`), `tag` (e.g. `fmcc`), `limit` (1–500, default 50), `offset`.

```bash
curl 'http://localhost:8080/api/search?q=password&stig=WIN_SERVER_2022&severity=high'
curl 'http://localhost:8080/api/search?nist=IA-5(1)&rev=rev5&limit=200'
curl 'http://localhost:8080/api/rule/WN22-SO-000150'
```

---

## Container deployment and security

The image (`python:3.12-slim-bookworm`, about 150 MB) is hardened by default:

- runs as a **non-root** user (UID 10001) on a **read-only** root filesystem, with **all Linux capabilities dropped**
  and `no-new-privileges` (in `docker-compose.yml`)
- published on **127.0.0.1 only**. For team access, put it behind an authentication- and TLS-enforcing reverse
  proxy with request limits; do **not** directly publish the unauthenticated API on a network
- sends security headers on every response: a strict Content-Security-Policy (`default-src 'self'`, no inline script
  or style), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`
- makes no outbound connections and loads no external scripts, fonts or images; everything is served locally
- the API is read-only, quotes FTS search terms, bounds request size and search length, applies per-IP rate limits,
  and caps simultaneous request threads
- stops promptly on `docker stop` (handles SIGTERM) and includes a health check on `/api/health` (with Podman, build
  with `--format docker` to keep the HEALTHCHECK)

The runtime image has **no third-party Python dependencies**. `requirements.txt` pins host-only document creation
packages. For reproducible releases, select and approve a base-image digest, then build with
`--build-arg PYTHON_BASE_IMAGE=python:3.12-slim-bookworm@sha256:<approved-digest>`; the default image tag remains mutable.
Scan the built image for known vulnerabilities as part of your CI release process.

The STIG data is baked into the image. After refreshing content, rebuild the image (`docker compose up -d --build`).

---

## How the content is produced

| Content | Source |
|---|---|
| Titles, severity, vulnerability discussion, check and fix text, SRG, CCIs, documentable flag, mitigations | **Quoted from DISA's XCCDF** benchmark files |
| CCI definitions and NIST SP 800-53 **Rev 3, Rev 4 and Rev 5** control mappings | **DISA CCI List** (`U_CCI_List.xml`) |
| **Settings changed** table | **Extracted automatically** from the check and fix text: registry blocks, `Computer Configuration >> …` policy paths (including user-rights account lists), config-file lines, `sysctl`, `dconf`, `systemctl`, `dnf`/`yum`/`apt` packages, `chmod`/`chown`/`chgrp`, audit rules and Windows feature removals. 2,889 rules have at least one extracted setting; the rest are procedural or described in prose. |
| **Command-line validation** | Quoted from DISA check text, generated from the extracted setting, or hand-written for well-known checks (`stig_explorer/validate.py`) |
| **Server role** | DISA STIG ID segment (`-DC-`, `-MS-`) and "NA for domain controllers" statements in the check text |
| **Related rules in other STIGs** | Matching normalised titles, registry values, kernel parameters and Group Policy settings across STIGs (3,049 rules have at least one counterpart) |
| **Topic explanations** (all three levels), threat context, ATT&CK techniques, operational impact | **Written for STIG Explorer**: 42 security topics in `stig_explorer/topics.py`, with administrator guidance written separately for RHEL, Ubuntu and Windows. Each rule is matched to one or two topics by keyword patterns on its title and fix text. |
| Plain-language title ("This computer must…") and key-term glossary | Generated per rule (44 glossary terms) |

Topic assignment is pattern-based. It was checked and tuned against samples from every STIG, but an individual rule can
still land on a less-than-ideal topic. The DISA text shown beside it is always the rule's actual requirement.

---

## Project layout and development

```
STIG_Explorer/
├── stig_explorer/
│   ├── fetch.py        # find and download the latest STIG zips + CCI list from DISA
│   ├── parse.py        # XCCDF and CCI list parsers (handles zips inside zips)
│   ├── settings.py     # extract the settings each rule changes
│   ├── topics.py       # 42-topic knowledge base (3 levels, RHEL/Ubuntu/Windows), glossary, classifier
│   ├── explain.py      # plain-language titles, DISA check commands
│   ├── validate.py     # command-line validation commands per rule
│   ├── build.py        # orchestrates everything -> web/data/stig_data.js; server roles; related rules
│   ├── tags.py         # compile tags/*.csv (e.g. FMCC) -> web/data/tags.js
│   ├── export_docs.py  # Word and Markdown documents
│   └── server.py       # standard-library web server + JSON API (SQLite FTS5)
├── web/
│   ├── index.html, app.js, style.css   # the application (no external dependencies)
│   ├── scripts.js                      # validation script export (.ps1 / .sh)
│   └── data/stig_data.js, tags.js      # generated data (committed, so the app works out of the box)
├── tags/FMCC.csv       # editable tag list template
├── docs/               # generated guide and per-STIG Word/Markdown documents
├── data/raw/           # DISA source zips (committed, for offline rebuilds)
├── tests/test_core.py  # existing unit and integration tests
├── tests/test_security.py # injection, archive, CSV, API and download regression tests
├── requirements.txt    # python-docx (Word output only)
├── Dockerfile
└── docker-compose.yml
```

**Tests:** `python -m unittest discover -s tests` covers setting extraction, topic classification, plain-language
titles, validation command generation, server roles, Ubuntu handling, the search index (including FTS injection),
tag compilation and matching, and the exported scripts. The script tests need Node.js; they generate the scripts,
syntax-check the Bash script with `bash -n`, check the new allowlist and hostile-input regression cases and, if `pwsh` is installed, parse
the PowerShell script with the real PowerShell parser.

The front end is plain HTML, CSS and JavaScript with no build step and no external libraries. All data strings are
HTML-escaped before display.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| App shows "Data file not found" | Run `python -m stig_explorer.build` (needs DISA zips in `data/raw/`, or add `--fetch`) |
| `--fetch` finds no release for a product | DISA may have retired or renamed it. Download it manually from public.cyber.mil and place it in `data/raw/`, or check `PRODUCTS` in `fetch.py`. |
| "No RHEL/Windows XCCDF benchmarks found" | `data/raw/` is empty or holds only SCAP benchmarks. Use the *Manual STIG* zips (`U_<product>_V#R#_STIG.zip`). |
| Word files aren't generated | `pip install -r requirements.txt` (installs `python-docx`) |
| Word table of contents says "Update Field" | Right-click it in Word and choose **Update Field** |
| Tag badges don't appear | Run `python -m stig_explorer.tags`, check its "matched nothing" warnings, then reload. In the container, rebuild the image or mount `tags.js`. |
| `secedit` / `auditpol` checks fail or show nothing | Run PowerShell or Command Prompt **as Administrator** |
| PowerShell won't run the exported script | Use `powershell.exe -ExecutionPolicy Bypass -File .\stig_validation.ps1`, or unblock the downloaded file (`Unblock-File`) |
| Bash script skips every check | The OS wasn't detected as a supported release (it reports the detected STIG at the top). Use `--all`. |
| Container port not reachable from other machines | It's bound to `127.0.0.1` by default; change the port mapping in `docker-compose.yml` |

---

## Requirements and limitations

**Requirements**

- Python 3.10 or later; the build, fetch, tags and server use only the standard library
- `python-docx` for Word output only
- A modern browser (Chrome, Edge, Firefox, Safari) for the app
- Docker or Podman for the container option
- Node.js only for running the script-export tests

**Limitations**

- STIG Explorer is a reference and triage aid, not a compliance scanner. Use SCAP/STIG Viewer/your enterprise tools for
  official assessments.
- Topic explanations and generated commands are guidance. Where they and DISA's text differ, DISA's text governs.
- Validation scripts report values but don't decide pass/fail. After security hardening, only allowlisted command
  forms run; most original checks are manual-only. This hardened version has **not** been run on production endpoints.
  A real PowerShell parser test requires `pwsh` and is skipped where it is unavailable.
- Windows Server 2012/2012 R2 isn't available from DISA anymore (see [What's included](#whats-included)).
- FMCC is not a DISA designation. The FMCC tag is only as complete as the list you provide.
