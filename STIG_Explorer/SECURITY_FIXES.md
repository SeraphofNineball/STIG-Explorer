# STIG Explorer — Security Remediation Notes

**Updated:** 2026-11-16  
**Based on:** `docs/STIG_Explorer_Security_Review_2026-11-16.md` (original findings)  
**Scope:** Browser app, exported Bash/PowerShell checks, Python import/download pipeline, API, and Docker build.

## What changed

| Finding | Remediation in this release | Status |
| --- | --- | --- |
| STIG-01: Bash filter-to-script injection | All dynamic script-header metadata is forced to one line; PowerShell `#>` comment breaks are neutralized. User-supplied commands no longer enter a Bash heredoc. | **Patched; regression-tested** |
| STIG-02: Unsafe automated validation | Default-deny command selection. Only narrowly defined, anchored read-only command patterns are automatically included in scripts. All remaining checks are listed as manual-only. CMD checks no longer create temporary batch files. | **Patched with stricter behavior** |
| STIG-03: `/etc/shadow` hash disclosure | Commands reading `/etc/shadow` or `/etc/gshadow` are excluded from automatic execution; three known DISA-derived hash-printing checks are manual-only. Original reference text is retained in the viewer. | **Automated exposure blocked** |
| STIG-04: ZIP/XML resource exhaustion | Bounded XML and nested-ZIP sizes, total expansion, depth, entry count and compression ratio. DTD and entity declarations are rejected. Downloads are also size-limited and saved atomically. | **Patched; regression-tested** |
| STIG-05: CSV formula injection | New `web/security.js` escapes formula-like cells as literal text before CSV quoting, including whitespace-prefixed formulas. | **Patched; regression-tested** |
| STIG-06: Unescaped HTML metadata | Variable class names and IDs are escaped. The XML parser rejects unknown severity values and malformed benchmark group/rule IDs. | **Patched for identified locations** |
| STIG-07: API resource pressure | 4 KiB URL cap, 256-character search input caps, offset cap, 10-second socket timeout, 32 concurrent handlers, and 240 API requests/minute per IP. Default localhost-only binding retained; container memory and process limits added. | **Local hardening added** |
| STIG-08: Build/dependency integrity | Docker runtime installs **no third-party Python packages**. Documentation-only dependencies are directly pinned, optional base-image digest override added, downloader records/verifies local SHA-256 provenance. | **Partially addressed; release approval still required** |

## Material behavior change: automated coverage

This update deliberately favors **manual review over automation**. On the original bundled November 2026 dataset, the new policy approves approximately **692 Windows command entries** and **358 Linux command entries** for export; thousands of additional check commands remain visible in the interface but are **not executed by generated scripts**.

The allowlist in `web/scripts.js` intentionally recognizes only uncomplicated, specific read-only query patterns. To expand automatic coverage, review a new command or template for side effects, credential disclosure, privilege and runtime requirements, then add a narrowly scoped pattern and security regression tests. Do not merely extend a blacklist or allow arbitrary pipelines, shell expansion, `Invoke-Expression`, scripting blocks, or redirections.

Review scripts and outputs before use, especially if running as administrator/root. The UI's original check commands are reference text and **must not be assumed safe to copy and run**.

## Tests

From `STIG_Explorer/`:

```sh
python -m unittest discover -s tests -v
node --check web/scripts.js
node --check web/security.js
node --check web/app.js
```

**Observed in the preparation environment:** 41 unit/integration tests run, 40 passed and one skipped. The skip is the real PowerShell parser check because `pwsh` was unavailable. `bash -n` passed against the fully generated Bash export and against malicious-input regression examples. A local server smoke test successfully loaded `/api/health`, `/api/search`, and `/security.js`, verified HTTP 400 for oversized search terms, and verified presence of HTTP security headers.

## Deployment and limitations

1. Keep Compose bound to `127.0.0.1` for personal use. **The JSON API remains unauthenticated**. Team use requires an authenticated HTTPS reverse proxy, plus infrastructure-layer rate limits, access logging, and network restrictions. The built-in per-IP limiter is **not** a replacement for these controls.
2. Rebuild after updating the source: `docker compose up -d --build`. The environment used for this patch did **not** provide Docker or PowerShell; neither an image build nor live Windows execution has been verified here. Test on non-production representative systems before rollout.
3. The base image tag is **not pinned by default**. For controlled release builds, pass `--build-arg PYTHON_BASE_IMAGE=python:3.12-slim-bookworm@sha256:<verified-digest>`, using a trusted current digest appropriate for your platform; run an image and dependency CVE scan during the build.
4. The `.sha256` sidecar produced by the downloader only shows what bytes were downloaded and detects subsequent accidental changes. It does **not** authenticate DISA's release; compare it against an independently trusted release hash where provided.
5. The source ZIP contains previously generated STIG data and documentation. The documentation artifacts were **not re-generated** because the underlying source benchmark ZIPs are not included under `data/raw/`. The `README.md` and this file describe the updated export behavior.
6. Read-only *query forms* cannot guarantee zero side effects from OS commands, vendor modules, plugins, or unusual environments. The changes significantly narrow command execution risk but are not a sandbox or a certification of compliance.

## Files directly changed

- `web/scripts.js` — command allowlist, safer script rendering, redaction/manual-only exclusions
- `web/security.js` — testable CSV cell encoding
- `web/app.js` and `web/index.html` — UI escaping and accurate safety notices
- `stig_explorer/parse.py` — bounded XML/ZIP parsing and identifier validation
- `stig_explorer/fetch.py` — download size, SHA-256 record, atomic download/cleanup
- `stig_explorer/server.py` — request limits and concurrent-handler throttling
- `Dockerfile`, `docker-compose.yml`, `requirements.txt` — runtime/deployment hardening
- `tests/test_security.py`, `tests/test_core.py` — regression coverage and updated exporter expectations
- `README.md` — updated operating guidance
