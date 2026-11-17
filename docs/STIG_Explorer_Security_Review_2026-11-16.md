# STIG Explorer — Source Code Security Review

**Review date:** 2026-11-16  
**Source artifact:** `ISSO_Tools-main.zip` (77 ZIP entries; 43,659,582 bytes uncompressed)  
**Scope:** `STIG_Explorer/` Python modules, browser JavaScript/HTML, bundled STIG data, Dockerfile, Compose file, and existing tests.  
**Method:** Offline static code review, inspection of bundled data, unit tests, and controlled, non-destructive demonstrations of generated script content. No production system was scanned, no exported validation script was executed, and no penetration test against a deployed server was performed.

## Executive summary

The application is relatively well hardened for **local, read-only browsing**: the default Compose port is bound to `127.0.0.1`, the container runs as a non-root UID with a read-only filesystem and dropped Linux capabilities, the server sets a restrictive Content Security Policy, and the SQLite search uses query parameters. However, **the exported validation scripts require remediation before being used as privileged production diagnostics**.

**Top priority:** A malicious search fragment can insert an executable line into a Bash export header. This was demonstrated without executing any generated script. More generally, the exporter assumes commands embedded in data are safe and does not enforce read-only execution. Additionally, actual bundled STIG checks would print password-hash fields to stdout if run with sufficient privileges.

These are vulnerability findings in the source code; exploitation prerequisites are indicated below. They do not establish that the supplied ZIP contains active malware or that the default local web server is compromised.

## Findings

### STIG-01 — Search-fragment-to-Bash-script command injection (HIGH; confirmed)

**Files:** `web/app.js:527-529`, `web/app.js:550-554`, `web/app.js:679-685`; `web/scripts.js:60-76`, `web/scripts.js:170-178`.

**Issue:** The browser decodes the `q=` field from `location.hash` and assigns it to `state.q`. The export path includes that value in `filterSummary()`, then `describe()` inserts the entire filter string into a comment header. The `header()` function prefixes each input *string* with `#`, but does not prefix each *line* if the string includes a newline. As a result, newline characters embedded in the URL fragment become un-commented executable shell lines in the downloaded Bash script.

**Safe proof:** With a synthetic filter string equivalent to `search "grep\nid\n#"`, the generated Bash header contains:

```bash
# Filter: search "grep
id
#"
```

`id` on its own line is executable shell code. A generated script containing that harmless marker passed `bash -n`. A separate static corpus check identified **247 bundled rules** whose searchable content contains all three terms `grep`, `id`, and `#`, so this is not merely a zero-result artificial filter scenario. **No generated script was executed.**

**Impact:** A crafted link could influence the script a user downloads; if that user runs it (potentially under `sudo`, as documented), the injected line executes with the script's privileges. This is a user-assisted code-execution vulnerability, not direct unauthenticated server-side RCE.

**Remediation:** Treat filter metadata as untrusted. Canonicalize all header text to one line (including `\r`, `\n`, Unicode line separators), ensure *each* output line is commented, and neutralize the `#>` terminator in PowerShell block comments. Prefer a structured header helper which explicitly encodes untrusted strings as data, not source-code fragments. Add tests that supply URL-style percent-encoded newlines and metacharacters, generate scripts, verify syntax, and verify every metadata line is a comment. Review both Bash and PowerShell variants.

### STIG-02 — Exported validation commands are not read-only enforced (HIGH; confirmed unsafe design, exploitation conditional)

**Files:** `web/scripts.js:16-57`, `web/scripts.js:124-147`, `web/scripts.js:198-215`; `stig_explorer/validate.py` (command generation).

**Issue:** `pick()` rejects a handful of known commands, prompts/placeholders, and some syntactically malformed PowerShell commands. It does **not** ensure the remainder is read-only. Accepted Linux commands are executed using `bash -c "$cmd"`; accepted PowerShell commands execute in script blocks, and CMD checks execute through `cmd.exe`.

**Safe proof:** The exporter accepted and embedded synthetic file-writing examples into both Bash and PowerShell exports. These examples were **not executed**. A synthetic line containing the literal Bash heredoc terminator `STIGX_EOF` was also accepted and allowed content to appear outside the intended heredoc in generated shell output. None of the checked-in validation commands contained that terminator at review time.

**Prerequisites:** A modified or malicious imported STIG benchmark, altered generated dataset, or future mistake in generated/curated validation code; a user must subsequently download and run the generated script.

**Impact:** A poisoned command may perform unauthorized modifications or worse under elevated credentials. This conflicts with the application's claimed read-only safety guarantee.

**Remediation:** Default to **manual review** for unapproved commands; use reviewed, narrowly scoped templates with fixed options and allowlisted arguments rather than arbitrary shell strings; do not treat regex blacklists or balanced quotes as a sandbox. Reject embedded heredoc delimiters or replace heredoc generation with safely encoded literal data. Until corrected, disable privileged batch script exports or require human command review and a test environment before use. Add tests proving write, network, command-substitution, and multiline payloads are never selected for unattended execution.

### STIG-03 — Password hashes can be printed by shipped exported checks (MEDIUM; current data confirmed)

**Files:** `web/data/stig_data.js` (bundled generated data); `web/scripts.js:198-204` (prints command output).

**Evidence:** Current data contains `cut -d: -f1,2 /etc/shadow` under **V-230232 (RHEL 8)**, **V-258231 (RHEL 9)** and **V-281221 (RHEL 10)**. The command prints username and full password-hash fields from `/etc/shadow` if run with sufficient privileges. The Bash check helper prints stdout, so hashes may enter terminal recordings, tickets or log captures. The application does not itself transmit them.

**Remediation:** Mark those three checks manual-only or emit only the algorithm identifier without the full hash; redact secrets from exported-script output and discourage inclusion in tickets/logs. Preserve DISA's authoritative text in the reference view while preventing sensitive content from automated bulk output.

### STIG-04 — Unbounded ZIP decompression and nested archive processing (MEDIUM; malicious input required)

**Files:** `stig_explorer/parse.py:35-59`, `stig_explorer/parse.py:75-77`, `stig_explorer/parse.py:176-177`; `stig_explorer/fetch.py:64-70`.

**Issue:** ZIP members are fully read into memory with `zf.read(info)` and nested ZIPs are recursively opened without total extracted-byte, per-member-size, compression-ratio, file-count or recursion-depth limits. XML is parsed in memory. A specially constructed benchmark archive could consume excessive memory, CPU or recursion depth during a developer/operator-triggered refresh. Download sizes are also not bounded. The workflow does **not** expose a remote upload API.

**Remediation:** Impose depth and cumulative decompression limits, reject oversized members and excessive ZIP ratios, stream or bound downloads, limit XML sizes, and fail closed on suspicious input. Run refreshes with limited CPU and RAM and only from approved sources.

### STIG-05 — CSV formula injection when exporting tainted content (MEDIUM; conditional)

**File:** `web/app.js:505-519`.

**Issue:** `exportCsv()` properly quotes CSV separators and quotation marks, but does not neutralize spreadsheet formula prefixes such as `=`, `+`, `-` and `@`. If externally sourced rule fields or local tag metadata are modified to contain formulas, opening the exported CSV in spreadsheet software can cause formula interpretation. No leading-formula values were identified in the currently bundled `title`, `plain`, `check`, `fix`, or `discussion` fields.

**Remediation:** In addition to CSV quoting, prefix formula-like cells with a literal text marker (`'`) when a cell's first non-whitespace character is a formula introducer, and test spreadsheet-specific edge cases including tabs and carriage returns. Or offer a text-only export format.

### STIG-06 — Unescaped metadata in HTML attributes (MEDIUM in offline/untrusted-data workflow; conditional)

**Files:** `web/app.js:233-234`, `web/app.js:269-271`, `web/app.js:308-312`, `web/app.js:381-385`; `stig_explorer/parse.py:190-200`.

**Issue:** Most content is escaped with `esc()`, but some interpolations—including `r.severity` inside class attributes and generated element IDs containing `r.vuln_id`—are placed into HTML without attribute escaping or strict validation. The parser copies severity and group identifiers from the supplied XCCDF without an output-safe schema check. A malicious source file could inject HTML attributes or elements after a data rebuild. The HTTP server's CSP mitigates inline-script execution, but the supported `file://` mode has no server-provided CSP.

**Remediation:** Apply `esc()` in every interpolated HTML attribute; validate severity against `{high,medium,low}` and identifiers against expected character formats on import; avoid `innerHTML` for untrusted input when possible. Add malicious-XCCDF UI tests for both hosted and offline file modes.

### STIG-07 — Additional availability risks when exposed on a network (LOW–MEDIUM; deployment dependent)

**Files:** `stig_explorer/server.py:85-129`, `stig_explorer/server.py:165-188`, `stig_explorer/server.py:202-214`; `docker-compose.yml:5-9`.

**Issue:** The JSON API has no authentication or request-rate limits and does not impose a maximum search-string length. The standard-library threaded HTTP server can be subjected to concurrent/slow request pressure, and the search materializes matching IDs before pagination. At the default localhost-only configuration this is less exposed. If bound to a network interface, the lack of TLS/authentication and rate/size limits becomes relevant. Public STIG data is not, by itself, confidential.

**Remediation:** Keep the existing localhost binding; for team use, place a secure TLS/authentication reverse proxy in front, set request-size and rate controls, cap query length, and bound request concurrency and timeouts.

### STIG-08 — Update and image reproducibility gaps (LOW / hardening)

**Files:** `Dockerfile:2-9`; `requirements.txt:1-3`; `stig_explorer/fetch.py:64-70`.

**Issue:** `python-docx==1.2.0` is pinned directly, but transitive dependencies are not locked, and `python:3.12-slim-bookworm` is a mutable tag without digest pinning. The DISA refresh operation uses HTTPS but no application-level expected-hash verification of the downloaded ZIP. These are build-integrity and reproducibility limitations, **not evidence of a specific vulnerable installed package**.

**Remediation:** Pin the container image by digest as part of a controlled refresh process, produce a locked and audited dependency inventory, and retain download SHA-256 hashes and origin metadata for each release. Run container-image and dependency vulnerability scans against the actual image before deployment.

## Verified strengths

- Default Compose port is bound only to `127.0.0.1:8080` (`docker-compose.yml`).
- Container has `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, and non-root UID 10001 (`Dockerfile`, `docker-compose.yml`).
- HTTP responses include a restrictive CSP, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `X-Frame-Options: DENY` (`server.py:36-42`, `151-154`).
- SQLite SQL construction uses parameter placeholders for user values (`server.py:85-116`); no conventional SQL injection was found in reviewed paths.
- Normal UI display strings are generally passed through an HTML escaping helper (`web/app.js:17-18`), though the exceptions above must be fixed.
- ZIP filename inspection of the **supplied project ZIP** found no `../` or absolute-path entries; ZIP integrity check passed.
- The web UI does not require third-party browser JavaScript libraries or CDNs.

## Tests performed

1. Ran `python -m unittest discover -s tests -v`: **31 tests reported, 30 passed, 1 skipped** (the skipped PowerShell parser test requires `pwsh`).
2. Confirmed with a harmless synthetic input that `pick()` accepts a Bash command that writes a local file and a PowerShell `Set-Content` command; generated strings were inspected but not run.
3. Confirmed a synthetic Bash heredoc-breakout string passes through `pick()` into exported script text; it was not run.
4. Produced a Bash export with a harmless `id` line injected via multiline filter text and confirmed the generated script passes `bash -n`. The script itself was **not executed**.
5. Inspected the bundled 3,877 rules and 7,113 validation commands. Confirmed three `/etc/shadow` full-hash-output commands in shipped content.
6. Checked the supplied ZIP for damaged members and unsafe entry paths: none found.

## Prioritized remediation plan

1. **Immediately:** Fix multiline/header injection in `scripts.js`, cover both shell languages, and add regression tests using URL fragments; suspend trusted use of exported scripts until patched.
2. **Immediately:** Change the exporter to run only explicitly reviewed, known-read-only checks, not arbitrary DISA-extracted command text. Treat unsupported commands as manual-only.
3. **Before administrator rollout:** Remove or redact `/etc/shadow` full-hash checks and review other sensitive output and high-cost checks.
4. **Before accepting externally updated benchmarks:** Constrain ZIP recursion and decompression; validate imported XML identifiers and metadata; fix all unescaped HTML attributes.
5. **Before spreadsheets/network rollout:** Sanitize CSV formula content; place any network-exposed deployment behind authenticated TLS reverse proxy with rate/resource controls.
6. **For release assurance:** Add automated image/dependency scanning and reproducible dependency/image pinning.

## Limitations and interpretation

This review does not establish the presence or absence of every vulnerability. It is not a full dynamic penetration test, fuzz campaign, malware sandbox analysis, or CVE scan of an installed Docker image. There was no live Linux/Windows benchmark host, and the PowerShell parser was unavailable. Findings concerning **malicious source files** require an attacker to influence benchmark/tag/generated data. Findings concerning **script execution** require a user to download and execute exported scripts. The supplied project ZIP was evaluated; no user files or production systems were modified.
