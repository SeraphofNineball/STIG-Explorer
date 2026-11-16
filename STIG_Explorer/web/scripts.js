/* STIG Explorer: validation script export.
 *
 * Builds a read-only PowerShell (.ps1) or Bash (.sh) script from the validation
 * commands of a set of rules. Pure functions, no DOM access, so the same code
 * runs in the browser (window.STIGX_SCRIPT) and under Node for testing
 * (module.exports).
 */
(function (root) {
  "use strict";

  const SEV = { high: "CAT I", medium: "CAT II", low: "CAT III" };

  // Placeholders DISA uses for values the reader must fill in, e.g. "<filename>", "[user]".
  const PLACEHOLDER = /\[[A-Za-z][A-Za-z _-]*\]|<[A-Za-z][A-Za-z _/-]*>/;

  // Only approved read-only command forms may be run automatically. Source data
  // (including DISA check text) is not trusted executable code. Everything not
  // explicitly recognized below is presented as MANUAL ONLY in the export.
  // This is a deliberately small list, not a general-purpose shell parser.
  const UNSAFE = [
    [/\/(?:etc\/)?(?:shadow|gshadow)(?:\b|\/)|\\(?:SAM|SECURITY)(?:\b|\\)/i,
      "may expose credential material; review locally and do not collect raw output"],
    [/\bsshd\s+-d/, "may start an interactive daemon"],
    [/\blogger\b/, "writes to the system log"],
    [/\bapt(?:-get)?\s+download\b|\bdpkg-deb\b/, "downloads or extracts files"],
    [/\baide(?:\.wrapper)?\b[^|;]*--check/, "runs an expensive full-system scan"],
    [/\brpm\s+-Va\b/, "runs an expensive full-system scan"],
  ];
  const unsafeReason = (cmd) => (UNSAFE.find(([re]) => re.test(String(cmd ?? ""))) || [, ""])[1];

  const psq = (s) => "'" + String(s ?? "").replace(/'/g, "''") + "'";
  const shq = (s) => "'" + String(s ?? "").replace(/'/g, "'\\''") + "'";
  const oneLine = (s) => String(s ?? "").replace(/[\s\u2028\u2029\u0085\u0000-\u001f\u007f]+/g, " ").trim();
  const psComment = (s) => oneLine(s).replace(/#>/g, "# >");
  const tagged = (r) => ((r._tagLabels || []).length ? `[${r._tagLabels.join(", ")}] ` : "") + oneLine(r.title);
  const PACKAGE = "[A-Za-z0-9][A-Za-z0-9._+@-]*";
  const SYSCTL_KEY = "[A-Za-z][A-Za-z0-9_.-]*";
  const SERVICE = "[A-Za-z0-9][A-Za-z0-9_.@-]*";
  const bashSafe = [
    new RegExp(`^(?:sudo )?sysctl ${SYSCTL_KEY}$`),
    new RegExp(`^(?:sudo )?rpm -q ${PACKAGE}$`),
    new RegExp(`^(?:sudo )?dpkg -s ${PACKAGE}$`),
    new RegExp(`^(?:sudo )?systemctl (?:is-enabled|is-active) ${SERVICE}$`),
    /^(?:sudo )?(?:getenforce|sestatus|lsblk --tree|blkid|nmcli device(?: status)?|pro status)$/, 
    /^(?:sudo )?firewall-cmd (?:--state|--list-all)$/,
    /^(?:sudo )?update-crypto-policies --show$/,
    new RegExp(`^(?:sudo )?getsebool ${SYSCTL_KEY}$`),
    /^(?:sudo )?gsettings get [A-Za-z0-9_.-]+ [A-Za-z0-9_.-]+$/,
  ];
  // Registry location and value names are *data*, not PowerShell expressions.
  // Restrict the registry root and character set; disallow interpolation, pipes,
  // redirection, semicolons, quotes inside values, and command substitutions.
  const PS_REG = /^Get-ItemProperty -Path 'HKLM:\\(?:SOFTWARE\\Policies|SYSTEM\\CurrentControlSet\\Control)\\([A-Za-z0-9_ .\\-]+)' -Name '([A-Za-z0-9_ .-]+)' \| Select-Object -ExpandProperty '([A-Za-z0-9_ .-]+)'$/;
  const psSimple = new Set([
    "Confirm-SecureBootUEFI", "Get-Tpm", "Get-WindowsFeature", "Get-BitLockerVolume",
    "Get-MpComputerStatus", "Get-NetFirewallProfile", "Get-LocalUser", "Get-Volume",
    "Get-NetAdapter", "Get-SmbShare", "Get-WindowsCapability", "Get-Service",
  ]);
  const cmdSafe = [
    /^reg query "HKLM\\(?:SOFTWARE\\Policies|SYSTEM\\CurrentControlSet\\Control)\\[A-Za-z0-9_ .\\-]+" \/v "[A-Za-z0-9_ .-]+"$/,
    /^auditpol \/get \/subcategory:"[A-Za-z0-9_ .\/&()-]+"$/,
    /^net (?:accounts|share)$/,
    /^manage-bde -status$/,
    /^netsh interface portproxy show all$/,
  ];

  function approvedCommand(v) {
    if (!v || typeof v.cmd !== "string" || !v.cmd || v.cmd.length > 1024) return false;
    const cmd = v.cmd;
    // Reject multiline, control characters, shell expansion and dangerous output
    // sources before checking the limited, anchored command patterns.
    if (/[\r\n\u0000-\u001f\u007f\u0085\u2028\u2029]/.test(cmd) || unsafeReason(cmd)) return false;
    if (v.shell === "bash") return bashSafe.some((re) => re.test(cmd));
    if (v.shell === "powershell") {
      const m = PS_REG.exec(cmd);
      if (m) return m[2] === m[3];
      return psSimple.has(cmd) || /^Get-CimInstance Win32_OperatingSystem$/.test(cmd);
    }
    if (v.shell === "cmd") return cmdSafe.some((re) => re.test(cmd));
    return false;
  }

  // Retained for API compatibility; command selection instead uses approvedCommand().
  function psSafe(cmd) { return approvedCommand({ shell: "powershell", cmd }); }

  function pick(rule, platform) {
    const runnable = [], manual = [];
    const cmds = (rule.validate || []).filter((v) => (platform === "windows"
      ? v.shell === "powershell" || v.shell === "cmd" : v.shell === "bash"));
    const hasPs = cmds.some((v) => v.shell === "powershell");
    for (const v of cmds) {
      // Avoid duplicate registry checks when the PowerShell version is selected.
      if (platform === "windows" && v.shell === "cmd" && hasPs && /^reg query\b/i.test(v.cmd)
          && cmds.some((x) => x.shell === "powershell" && approvedCommand(x))) continue;
      if (approvedCommand(v)) runnable.push(v);
      else manual.push({ v, why: unsafeReason(v.cmd) || "not in the reviewed read-only command allowlist" });
    }
    return { runnable, manual };
  }

  function header(lines, comment) {
    return lines.map((l) => `${comment}${oneLine(l) ? " " + oneLine(l) : ""}`);
  }

  function describe(rules, meta, filterText, platform) {
    const stigs = [...new Set(rules.map((r) => oneLine(r.stig)))];
    return [
      `Generated by STIG Explorer ${oneLine(meta.version)} on ${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC`,
      `Data: ${oneLine(meta.generated)}. ${rules.length} rules from: ${stigs.join(", ")}`,
      filterText ? `Filter: ${oneLine(filterText)}` : "",
      "",
      "SAFETY: only reviewed, allowlisted read-only command forms are run automatically.",
      "Other checks are MANUAL ONLY. Review the generated script and output before running with elevated privileges.",
      "Commands are not a definitive compliance test. DISA's check procedure remains authoritative.",
    ].map((l) => platform === "windows" ? psComment(l) : oneLine(l));
  }

  // ------------------------------------------------------------- PowerShell
  function powershell(rules, meta, filterText) {
    const win = rules.filter((r) => r.platform === "windows");
    const L = [];
    L.push("<#");
    L.push("  STIG Explorer validation script (PowerShell)");
    for (const l of describe(win, meta, filterText, "windows")) L.push("  " + psComment(l));
    L.push("");
    L.push("  Run from an elevated PowerShell prompt:");
    L.push("    powershell.exe -ExecutionPolicy Bypass -File .\\stig_validation.ps1 [-All] [-LogPath results.txt]");
    L.push("  By default only checks for the detected Windows version (and domain controller or member");
    L.push("  server role) run. -All runs every check in the file.");
    L.push("#>");
    L.push("[CmdletBinding()]");
    L.push("param([switch]$All, [string]$LogPath)");
    L.push("");
    L.push("if ($LogPath) { Start-Transcript -Path $LogPath | Out-Null }");
    L.push("$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()");
    L.push("if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {");
    L.push("    Write-Warning 'Some approved read-only queries may require elevated access.'");
    L.push("}");
    L.push("$os = Get-CimInstance Win32_OperatingSystem");
    L.push("$script:IsDC = ($os.ProductType -eq 2)");
    L.push("$script:Detected = switch -Regex ($os.Caption) {");
    L.push("    'Server 2025' { 'WIN_SERVER_2025' } 'Server 2022' { 'WIN_SERVER_2022' }");
    L.push("    'Server 2019' { 'WIN_SERVER_2019' } 'Server 2016' { 'WIN_SERVER_2016' }");
    L.push("    'Windows 11' { 'WIN_11' } 'Windows 10' { 'WIN_10' } default { '' }");
    L.push("}");
    L.push("$role = if ($script:IsDC) { ' (domain controller)' } else { '' }");
    L.push("Write-Host \"Detected: $($os.Caption) build $($os.BuildNumber) -> STIG $($script:Detected)$role\"");
    L.push("if (-not $script:Detected -and -not $All) { Write-Warning 'No matching STIG detected; use -All to run every check.' }");
    L.push("$script:Run = 0; $script:Skipped = 0");
    L.push("");
    L.push("function Start-Check([string]$Stig, [string]$Role, [string]$Id, [string]$Severity, [string]$Title) {");
    L.push("    if (-not $All) {");
    L.push("        if ($Stig -ne $script:Detected -or ($Role -eq 'dc' -and -not $script:IsDC) -or ($Role -eq 'ms' -and $script:IsDC)) {");
    L.push("            $script:Skipped++; return $false");
    L.push("        }");
    L.push("    }");
    L.push("    $script:Run++");
    L.push("    Write-Host ''");
    L.push("    Write-Host ('=' * 100) -ForegroundColor DarkGray");
    L.push("    Write-Host \"$Id  [$Severity]  $Title\" -ForegroundColor Cyan");
    L.push("    return $true");
    L.push("}");
    L.push("function Invoke-PSCheck([string]$Expected, [scriptblock]$Command) {");
    L.push("    Write-Host \"  PowerShell> $($Command.ToString().Trim())\" -ForegroundColor DarkCyan");
    L.push("    Write-Host \"  Expected: $Expected\" -ForegroundColor Yellow");
    L.push("    try { & $Command 2>&1 | Out-String -Width 250 | Write-Host }");
    L.push("    catch { Write-Host \"  ERROR: $($_.Exception.Message)\" -ForegroundColor Red }");
    L.push("}");
    L.push("function Invoke-CmdCheck([string]$Expected, [string]$Command) {");
    L.push("    Write-Host \"  CMD> $Command\" -ForegroundColor DarkCyan");
    L.push("    Write-Host \"  Expected: $Expected\" -ForegroundColor Yellow");
    L.push("    # Only strict, read-only CMD command forms were selected during generation.");
    L.push("    & cmd.exe /d /c $Command 2>&1 | Out-String -Width 250 | Write-Host");
    L.push("}");
    const manualAll = [];
    for (const r of win) {
      const { runnable, manual } = pick(r, "windows");
      manual.forEach((m) => manualAll.push([r, m]));
      if (!runnable.length) continue;
      L.push("");
      L.push(`if (Start-Check ${psq(r.stig)} ${psq(r.role || "")} ${psq(r.vuln_id + " / " + r.stig_id)} ${psq(SEV[r.severity])} ${psq(tagged(r))}) {`);
      for (const v of runnable) {
        if (v.shell === "powershell") L.push(`    Invoke-PSCheck ${psq(oneLine(v.expect))} { ${v.cmd} }`);
        else L.push(`    Invoke-CmdCheck ${psq(oneLine(v.expect))} ${psq(v.cmd)}`);
      }
      L.push("}");
    }
    L.push("");
    L.push("Write-Host ''");
    L.push("Write-Host \"Checks run: $($script:Run)   Skipped (other OS/STIG/role): $($script:Skipped)\" -ForegroundColor Green");
    L.push(...manualPs(win, manualAll));
    L.push("if ($LogPath) { Stop-Transcript | Out-Null }");
    return "﻿" + L.join("\r\n") + "\r\n";
  }

  function manualPs(rules, manualAll) {
    const none = rules.filter((r) => !(r.validate || []).length);
    if (!manualAll.length && !none.length) return [];
    const L = [""];
    L.push("<# Manual checks (not run by this script)");
    for (const [r, m] of manualAll) L.push(psComment(`   ${r.vuln_id} / ${r.stig_id}: ${m.why}: ${oneLine(m.v.cmd)}`));
    for (const r of none) L.push(psComment(`   ${r.vuln_id} / ${r.stig_id}: procedural; follow the DISA check procedure. ${oneLine(r.title)}`));
    L.push("#>");
    return L;
  }

  // ------------------------------------------------------------------ Bash
  function bash(rules, meta, filterText) {
    const lin = rules.filter((r) => r.platform === "linux");
    const L = [];
    L.push("#!/usr/bin/env bash");
    L.push(...header(["STIG Explorer validation script (Bash)", ...describe(lin, meta, filterText, "linux"), "",
      "Usage:  sudo bash stig_validation.sh [--all]",
      "By default only checks for the detected distribution and release run (RHEL 7-10 and",
      "RHEL rebuilds, Ubuntu LTS). --all runs every check in the file."], "#"));
    L.push("set -u");
    L.push("ALL=0; [ \"${1:-}\" = \"--all\" ] && ALL=1");
    L.push("IS_ROOT=0; [ \"$(id -u)\" -eq 0 ] && IS_ROOT=1");
    L.push("[ $IS_ROOT -eq 1 ] || echo 'WARNING: not running as root; checks that use sudo may prompt for a password.' >&2");
    L.push("ID=''; VERSION_ID=''; PRETTY_NAME=''");
    L.push("[ -r /etc/os-release ] && . /etc/os-release");
    L.push("case \"$ID\" in");
    L.push("  rhel|centos|rocky|almalinux|ol) DETECTED=\"RHEL_${VERSION_ID%%.*}\" ;;");
    L.push("  ubuntu) DETECTED=\"UBUNTU_${VERSION_ID/./_}\" ;;");
    L.push("  *) DETECTED='' ;;");
    L.push("esac");
    L.push("echo \"Detected: ${PRETTY_NAME:-unknown} -> STIG ${DETECTED:-none (use --all)}\"");
    L.push("RUN=0; SKIPPED=0");
    L.push("");
    L.push("begin() {  # begin STIG ID SEVERITY TITLE");
    L.push("  if [ $ALL -eq 0 ] && [ \"$1\" != \"$DETECTED\" ]; then SKIPPED=$((SKIPPED + 1)); return 1; fi");
    L.push("  RUN=$((RUN + 1))");
    L.push("  printf '\\n%s\\n%s  [%s]  %s\\n' \"$(printf '=%.0s' $(seq 1 100))\" \"$2\" \"$3\" \"$4\"");
    L.push("}");
    L.push("check() {  # check COMMAND EXPECTED (only reviewed read-only commands)");
    L.push("  local cmd=$1 expected=$2");
    L.push("  # Already root: drop sudo so the checks also work where sudo isn't installed.");
    L.push("  if [ $IS_ROOT -eq 1 ] && [[ \"$cmd\" == 'sudo '* ]]; then cmd=${cmd#sudo }; fi");
    L.push("  printf '  $ %s\\n  Expected: %s\\n' \"$cmd\" \"$expected\"");
    L.push("  bash -c \"$cmd\" </dev/null 2>&1 | sed 's/^/    /'");
    L.push("}");
    const manualAll = [];
    for (const r of lin) {
      const { runnable, manual } = pick(r, "linux");
      manual.forEach((m) => manualAll.push([r, m]));
      if (!runnable.length) continue;
      L.push("");
      L.push(`if begin ${shq(r.stig)} ${shq(r.vuln_id + " / " + r.stig_id)} ${shq(SEV[r.severity])} ${shq(tagged(r))}; then`);
      for (const v of runnable) {
        L.push(`check ${shq(v.cmd)} ${shq(oneLine(v.expect))}`);
      }
      L.push("fi");
    }
    L.push("");
    L.push("printf '\\nChecks run: %d   Skipped (other distribution/release): %d\\n' \"$RUN\" \"$SKIPPED\"");
    const none = lin.filter((r) => !(r.validate || []).length);
    if (manualAll.length || none.length) {
      L.push("");
      L.push("# Manual checks (not run by this script):");
      for (const [r, m] of manualAll) L.push(`#   ${oneLine(r.vuln_id)} / ${oneLine(r.stig_id)}: ${oneLine(m.why)}: ${oneLine(m.v.cmd)}`);
      for (const r of none) L.push(`#   ${oneLine(r.vuln_id)} / ${oneLine(r.stig_id)}: procedural; follow the DISA check procedure. ${oneLine(r.title)}`);
    }
    return L.join("\n") + "\n";
  }

  function counts(rules) {
    return {
      windows: rules.filter((r) => r.platform === "windows").length,
      linux: rules.filter((r) => r.platform === "linux").length,
    };
  }

  const api = { powershell, bash, counts, pick, psSafe, unsafeReason, approvedCommand };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.STIGX_SCRIPT = api;
})(typeof window !== "undefined" ? window : globalThis);
