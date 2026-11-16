"""Command-line validation for STIG rules.

For each rule this produces copy-and-paste commands (PowerShell, CMD or a
Linux shell) that show the current value of the setting the rule governs,
plus what a compliant result looks like. These are a faster alternative to
browsing the Group Policy editor or reading config files by hand.

Sources:
    "disa"       command quoted in DISA's own check text
    "generated"  built by STIG Explorer from the extracted setting
    "curated"    hand-written command for a well-known check (matched by rule title)

Generated commands are read-only. Some need an elevated prompt (noted in
`expect`). DISA's check procedure remains the authoritative test.
"""

from __future__ import annotations

import re

from . import settings as settings_mod

# ------------------------------------------------------------------ Windows

HIVES = {"HKEY_LOCAL_MACHINE": "HKLM", "HKEY_CURRENT_USER": "HKCU", "HKEY_USERS": "HKU",
         "HKEY_CLASSES_ROOT": "HKCR"}

USER_RIGHTS = {
    "access credential manager as a trusted caller": "SeTrustedCredManAccessPrivilege",
    "access this computer from the network": "SeNetworkLogonRight",
    "act as part of the operating system": "SeTcbPrivilege",
    "add workstations to domain": "SeMachineAccountPrivilege",
    "adjust memory quotas for a process": "SeIncreaseQuotaPrivilege",
    "allow log on locally": "SeInteractiveLogonRight",
    "allow log on through remote desktop services": "SeRemoteInteractiveLogonRight",
    "back up files and directories": "SeBackupPrivilege",
    "bypass traverse checking": "SeChangeNotifyPrivilege",
    "change the system time": "SeSystemtimePrivilege",
    "change the time zone": "SeTimeZonePrivilege",
    "create a pagefile": "SeCreatePagefilePrivilege",
    "create a token object": "SeCreateTokenPrivilege",
    "create global objects": "SeCreateGlobalPrivilege",
    "create permanent shared objects": "SeCreatePermanentPrivilege",
    "create symbolic links": "SeCreateSymbolicLinkPrivilege",
    "debug programs": "SeDebugPrivilege",
    "deny access to this computer from the network": "SeDenyNetworkLogonRight",
    "deny log on as a batch job": "SeDenyBatchLogonRight",
    "deny log on as a service": "SeDenyServiceLogonRight",
    "deny log on locally": "SeDenyInteractiveLogonRight",
    "deny log on through remote desktop services": "SeDenyRemoteInteractiveLogonRight",
    "enable computer and user accounts to be trusted for delegation": "SeEnableDelegationPrivilege",
    "force shutdown from a remote system": "SeRemoteShutdownPrivilege",
    "generate security audits": "SeAuditPrivilege",
    "impersonate a client after authentication": "SeImpersonatePrivilege",
    "increase a process working set": "SeIncreaseWorkingSetPrivilege",
    "increase scheduling priority": "SeIncreaseBasePriorityPrivilege",
    "load and unload device drivers": "SeLoadDriverPrivilege",
    "lock pages in memory": "SeLockMemoryPrivilege",
    "log on as a batch job": "SeBatchLogonRight",
    "log on as a service": "SeServiceLogonRight",
    "manage auditing and security log": "SeSecurityPrivilege",
    "modify an object label": "SeRelabelPrivilege",
    "modify firmware environment values": "SeSystemEnvironmentPrivilege",
    "obtain an impersonation token for another user in the same session": "SeDelegateSessionUserImpersonatePrivilege",
    "perform volume maintenance tasks": "SeManageVolumePrivilege",
    "profile single process": "SeProfileSingleProcessPrivilege",
    "profile system performance": "SeSystemProfilePrivilege",
    "remove computer from docking station": "SeUndockPrivilege",
    "replace a process level token": "SeAssignPrimaryTokenPrivilege",
    "restore files and directories": "SeRestorePrivilege",
    "shut down the system": "SeShutdownPrivilege",
    "synchronize directory service data": "SeSyncAgentPrivilege",
    "take ownership of files or other objects": "SeTakeOwnershipPrivilege",
}

# Group Policy settings stored in the security database rather than the registry.
SECPOL_KEYS = {
    "minimum password length": "MinimumPasswordLength",
    "password must meet complexity requirements": "PasswordComplexity",
    "maximum password age": "MaximumPasswordAge",
    "minimum password age": "MinimumPasswordAge",
    "enforce password history": "PasswordHistorySize",
    "store passwords using reversible encryption": "ClearTextPassword",
    "account lockout threshold": "LockoutBadCount",
    "account lockout duration": "LockoutDuration",
    "reset account lockout counter after": "ResetLockoutCount",
    "allow administrator account lockout": "AllowAdministratorLockout",
    "accounts: administrator account status": "EnableAdminAccount",
    "accounts: guest account status": "EnableGuestAccount",
    "accounts: rename administrator account": "NewAdministratorName",
    "accounts: rename guest account": "NewGuestName",
    "network access: allow anonymous sid/name translation": "LSAAnonymousNameLookup",
    "network security: force logoff when logon hours expire": "ForceLogoffWhenHourExpire",
    "enforce user logon restrictions": "TicketValidateClient",
    "maximum lifetime for service ticket": "MaxServiceAge",
    "maximum lifetime for user ticket": "MaxTicketAge",
    "maximum lifetime for user ticket renewal": "MaxRenewAge",
    "maximum tolerance for computer clock synchronization": "MaxClockSkew",
}

AUDITPOL_NAMES = {"pnp activity": "Plug and Play Events"}

_DISA_WIN_CMD = re.compile(
    r'"((?:Get-|Search-|Confirm-|Test-|auditpol|net |reg query|secedit|bcdedit|manage-bde|icacls|whoami|systeminfo|'
    r'dism|winrm|gpresult|certutil|dsquery|repadmin|nltest|w32tm|sc query|netsh|fsutil)[^"]{1,250})"')


def _cmd(shell: str, cmd: str, expect: str = "", src: str = "generated") -> dict:
    return {"shell": shell, "cmd": cmd, "expect": expect, "src": src}


def _ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _registry(s: dict) -> list[dict]:
    target = s["target"]
    hive, _, path = target.partition("\\")
    short = HIVES.get(hive.upper(), hive)
    path = path.strip("\\ ")
    name = s["name"]
    expect = f"{name} = {s['value']}. A missing value or path is a finding."
    return [
        _cmd("powershell", f"Get-ItemProperty -Path {_ps_quote(short + ':' + chr(92) + path)} -Name {_ps_quote(name)} "
                           f"| Select-Object -ExpandProperty {_ps_quote(name)}", expect),
        _cmd("cmd", f'reg query "{short}\\{path}" /v "{name}"', expect),
    ]


def _secedit(key: str, area: str, expect: str) -> list[dict]:
    return [
        _cmd("powershell",
             f"secedit /export /cfg \"$env:TEMP\\secpol.inf\" /areas {area} /quiet; "
             f"Select-String -Path \"$env:TEMP\\secpol.inf\" -Pattern '^{key}\\b'", expect),
        _cmd("cmd", f"secedit /export /cfg %TEMP%\\secpol.inf /areas {area} /quiet && "
                    f"findstr /i /b \"{key}\" %TEMP%\\secpol.inf", expect),
    ]


def _gpo(s: dict, has_registry: bool) -> list[dict]:
    name, target, value = s["name"], s["target"], s["value"]
    low = name.lower()
    if "User Rights Assignment" in target:
        const = USER_RIGHTS.get(low)
        if const:
            want = value.replace("Only: ", "") if value else "see fix text"
            return _secedit(const, "USER_RIGHTS",
                            f"{const} lists only: {want}. Accounts appear as names or SIDs (*S-1-5-32-544 = "
                            f"Administrators, *S-1-5-32-546 = Guests, *S-1-5-11 = Authenticated Users, *S-1-5-113 = "
                            f"Local account). No line at all means no one holds the right. Run elevated.")
    if "Advanced Audit Policy" in target or "System Audit Policies" in target:
        sub = re.sub(r"^Audit\s+", "", name).strip()
        sub = AUDITPOL_NAMES.get(sub.lower(), sub)
        want = re.findall(r'"(Success|Failure)"|\b(Success|Failure)\b', value)
        flags = sorted({a or b for a, b in want}) or ["see fix text"]
        exp = (f"The '{sub}' line must include {' and '.join(flags)} "
               f"('Success and Failure' satisfies either). Run elevated.")
        return [_cmd("cmd", f'auditpol /get /subcategory:"{sub}"', exp),
                _cmd("powershell", f"auditpol /get /subcategory:\"{sub}\"", exp)]
    key = SECPOL_KEYS.get(low) or SECPOL_KEYS.get(re.sub(r"^[a-z ]+: ", "", low))
    if key:
        area = "SECURITYPOLICY"
        exp = f"{key} matches the required value: {value or 'see fix text'}. Run elevated."
        cmds = _secedit(key, area, exp)
        if key in ("MinimumPasswordLength", "MaximumPasswordAge", "MinimumPasswordAge", "PasswordHistorySize",
                   "LockoutBadCount", "LockoutDuration", "ResetLockoutCount"):
            cmds.append(_cmd("cmd", "net accounts", f"Check the line for '{name}': {value}. (Local policy view; "
                                                    f"use 'net accounts /domain' for the domain policy.)"))
        return cmds
    if has_registry:
        return []  # the registry query already validates this policy
    return [_cmd("cmd", 'gpresult /scope computer /h "%TEMP%\\gpresult.html" /f && start "" "%TEMP%\\gpresult.html"',
                 f'Find "{name}" in the report: it must be {value or "configured as the fix text says"}. Run elevated.')]


def _feature(s: dict, server: bool) -> list[dict]:
    n = s["name"]
    if server:
        return [_cmd("powershell",
                     f"Get-WindowsFeature | Where-Object {{ $_.DisplayName -eq {_ps_quote(n)} -or $_.Name -eq {_ps_quote(n)} }} "
                     f"| Select-Object Name, DisplayName, InstallState",
                     "InstallState must be 'Available' or 'Removed' (not 'Installed').")]
    return [_cmd("powershell",
                 f"Get-WindowsOptionalFeature -Online | Where-Object FeatureName -like {_ps_quote('*' + n.replace(' ', '*') + '*')} "
                 f"| Select-Object FeatureName, State",
                 "State must be 'Disabled' (or the feature is absent). Run elevated.")]


def windows(rule: dict, items: list[dict], server: bool) -> list[dict]:
    out: list[dict] = []
    for m in _DISA_WIN_CMD.finditer(rule["check"]):
        c = m.group(1).strip()
        shell = "cmd" if re.match(r"(auditpol|net |reg |secedit|bcdedit|manage-bde|icacls|whoami|systeminfo|dism|"
                                  r"winrm|gpresult|certutil|dsquery|repadmin|nltest|w32tm|sc |netsh|fsutil)", c) else "powershell"
        out.append(_cmd(shell, c, "Compare the output with the check procedure.", "disa"))
    has_reg = any(i["type"] == "registry" for i in items)
    for s in items:
        if s["type"] == "registry":
            out += _registry(s)
        elif s["type"] == "gpo":
            out += _gpo(s, has_reg)
        elif s["type"] == "feature":
            out += _feature(s, server)
    if not any(c["src"] == "generated" for c in out):
        out += windows_curated(rule["title"])
    return _dedupe(out)


# -------------------------------------------------------------------- Linux

_PLACEHOLDER = re.compile(r"<[^>]+>|\[[^\]]+\]")


def _pkg_query(name: str, family: str, want: str) -> dict:
    if family == "ubuntu":
        return _cmd("bash", f"dpkg -l {name} 2>/dev/null | grep '^ii' || echo 'package {name} is not installed'",
                    f"Package must be {want.lower()}.")
    return _cmd("bash", f"rpm -q {name}", f"Package must be {want.lower()}"
                + (" (expect 'package ... is not installed')." if want == "Removed" else "."))


def linux(rule: dict, items: list[dict], family: str, disa_cmds: list[str]) -> list[dict]:
    out: list[dict] = []
    for c in disa_cmds:
        out.append(_cmd("bash", c if c.startswith(("sudo ", "/")) or not _needs_root(c) else "sudo " + c,
                        "Compare the output with the check procedure.", "disa"))
    for s in items:
        t = s["type"]
        if t == "sysctl":
            out.append(_cmd("bash", f"sysctl {s['name']}", f"{s['name']} = {s['value']}"))
            out.append(_cmd("bash", f"sudo grep -rs '^[[:space:]]*{s['name']}' /etc/sysctl.conf /etc/sysctl.d/ "
                                    f"/run/sysctl.d/ /usr/local/lib/sysctl.d/ /usr/lib/sysctl.d/ /lib/sysctl.d/",
                            f"Every match must set {s['value']}. Conflicting values in other files are a finding."))
        elif t == "config":
            out.append(_config(s, family))
        elif t == "audit_rule":
            out.append(_audit(s))
        elif t == "dconf":
            if s["value"] == "locked":
                out.append(_cmd("bash", f"grep -rs '{s['name']}' /etc/dconf/db/*/locks/",
                                "The key must be listed in a locks file so users can't override it."))
            else:
                out.append(_cmd("bash", f"grep -rs '^[[:space:]]*{s['name']}' /etc/dconf/db/*.d/",
                                f"{s['name']}={s['value']} under {s['target']}."))
        elif t == "package":
            out.append(_pkg_query(s["name"], family, s["value"]))
        elif t == "service":
            act = s["value"]
            want = ("masked / inactive" if "mask" in act else "disabled / inactive" if "disable" in act
                    else "enabled / active")
            out.append(_cmd("bash", f"systemctl is-enabled {s['name']}; systemctl is-active {s['name']}",
                            f"Expect {want}."))
        elif t == "permission":
            path = s["name"].split()[-1]
            if s["target"] in ("chmod", "chown", "chgrp"):
                out.append(_cmd("bash", f"sudo stat -c '%a %U %G %n' {path}",
                                f"Mode/owner/group must match: {s['target']} {s['name']}."))
    return _dedupe(out)


def _needs_root(c: str) -> bool:
    return bool(re.match(r"(grep|cat|find|ls|stat|awk|auditctl|ausearch|aide|sshd|faillock)\b", c)) and \
        bool(re.search(r"/etc/(shadow|gshadow|sudoers|audit|security|ssh/sshd_config)|auditctl|aide|sshd -T|/var/log/audit", c))


def _config(s: dict, family: str) -> dict:
    key, val, target = s["name"], s["value"], s["target"]
    if "ssh/sshd_config" in target:
        return _cmd("bash", f"sudo sshd -T | grep -i '^{key} '",
                    f"{key.lower()} {val} (the effective value sshd is using).")
    if key in ("auth", "account", "password", "session"):
        mod = re.search(r"(pam_\w+\.so)", val)
        pat = mod.group(1) if mod else key
        return _cmd("bash", f"grep -rs '{pat}' {target if not target.endswith('.d') else target + '/'}",
                    f"Line present: {key} {val}")
    if key == "GRUB_CMDLINE_LINUX" and family != "ubuntu":
        arg = val.strip('"').split()[0] if val.strip('"') else ""
        return _cmd("bash", f"sudo grubby --info=ALL | grep -E '^args' | grep -c '{arg}'",
                    f"Every kernel's args must include {arg}.")
    recursive = target.endswith((".d", "/")) or "." not in target.rsplit("/", 1)[-1] and not target.endswith(("conf", "defs"))
    flag = "-rsi" if recursive else "-si"
    return _cmd("bash", f"sudo grep {flag} '^[[:space:]]*{re.escape(key)}\\b' {target}",
                f"{key} {('= ' if '=' not in val else '') + val}".strip())


def _audit(s: dict) -> dict:
    line = s["name"]
    if line.startswith("-e"):
        return _cmd("bash", "sudo auditctl -s | grep enabled", "enabled 2 (rules are immutable).")
    if "loginuid-immutable" in line:
        return _cmd("bash", "sudo auditctl -s | grep loginuid_immutable", "loginuid_immutable 1 locked")
    m = re.search(r"-w\s+(\S+)", line) or re.search(r"path=(\S+)", line) or re.search(r"-S\s+([\w,]+)", line)
    pat = m.group(1).split(",")[0] if m else line
    return _cmd("bash", f"sudo auditctl -l | grep -- '{pat}'", f"Loaded rule matching: {line}")


def _dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for it in items:
        if it["cmd"] not in seen:
            seen.add(it["cmd"])
            out.append(it)
    return out


def commands(rule: dict, family: str, stig_key: str, disa_cmds: list[str]) -> list[dict]:
    items = [i for i in rule["settings"] if i["type"] != "command"]
    if rule["platform"] == "windows":
        return windows(rule, items, server="SERVER" in stig_key)
    return linux(rule, items, family, disa_cmds)


SHELL_LABELS = {"powershell": "PowerShell", "cmd": "CMD", "bash": "Bash (Linux)"}


# ---------------------------------------------------------------------------
# Curated commands for Windows rules with no registry/GPO setting (matched on
# the rule title). Each entry: (title regex, [(shell, command, expected result)]).
# ---------------------------------------------------------------------------

_AD = "Import-Module ActiveDirectory; $dn = (Get-ADDomain).DistinguishedName; "


def _adacl(path: str, audit: bool) -> str:
    if audit:
        return (_AD + f'(Get-Acl -Path "AD:{path}" -Audit).Audit | '
                "Format-Table IdentityReference, AuditFlags, ActiveDirectoryRights, InheritanceType -AutoSize")
    return (_AD + f'(Get-Acl -Path "AD:{path}").Access | '
            "Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType, IsInherited -AutoSize")


WIN_TITLE_CMDS: list[tuple[str, list[tuple[str, str, str]]]] = [
    (r"OpenSSH (configuration file|private host key|public host key)", [
        ("cmd", "icacls %ProgramData%\\ssh\\sshd_config && icacls %ProgramData%\\ssh\\ssh_host_*",
         "Permissions match the check procedure (private keys: SYSTEM and Administrators only).")]),
    (r"OpenSSH", [
        ("powershell", "Get-Service sshd | Select-Object Status, StartType; Select-String -Path \"$env:ProgramData\\ssh\\sshd_config\" -Pattern '^\\s*[^#\\s]'",
         "sshd is running and the directive named in the check procedure is set as required (uncommented lines shown). Run elevated.")]),
    (r"Wi-Fi enabled|wireless network adapters", [
        ("powershell", "Get-NetAdapter -IncludeHidden | Where-Object { $_.PhysicalMediaType -match '802.11' -or $_.InterfaceDescription -match 'Wi-?Fi|Wireless' } | Select-Object Name, Status, InterfaceDescription",
         "No wireless adapters, or all are Disabled (unless documented as required).")]),
    (r"Bluetooth enabled", [
        ("powershell", "Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Select-Object FriendlyName, Status",
         "No Bluetooth devices, or all are disabled (unless documented as required).")]),
    (r"security-relevant software updates", [
        ("powershell", "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, Description, InstalledOn",
         "The most recent cumulative/security updates were installed within the organization's required timeframe.")]),
    (r"roles and features required", [
        ("powershell", "Get-WindowsFeature | Where-Object Installed | Select-Object Name, DisplayName",
         "Only roles and features documented as required for the server's function.")]),
    (r"Trusted Platform Module|\bTPM\b", [
        ("powershell", "Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled",
         "TpmPresent and TpmReady are True. Run elevated. (Check the TPM version with 'Get-CimInstance -Namespace root/cimv2/security/microsofttpm -ClassName Win32_Tpm | Select SpecVersion'.)")]),
    (r"Secure Boot", [
        ("powershell", "Confirm-SecureBootUEFI", "True. Run elevated.")]),
    (r"Unified Extensible Firmware Interface|\bUEFI\b", [
        ("powershell", "$env:firmware_type", "UEFI (not Legacy).")]),
    (r"BitLocker|data-at-rest|data at rest|encrypt all disks", [
        ("cmd", "manage-bde -status", "Every fixed volume shows 'Protection On' and 'Fully Encrypted'. Run elevated."),
        ("powershell", "Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, KeyProtector",
         "ProtectionStatus On and VolumeStatus FullyEncrypted for every fixed volume.")]),
    (r"Enterprise Edition 64-bit", [
        ("powershell", "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, OSArchitecture",
         "Caption contains 'Enterprise' and OSArchitecture is 64-bit.")]),
    (r"supported servicing level", [
        ("powershell", "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber",
         "The version/build must still be in Microsoft's servicing support (compare with the Windows release health page).")]),
    (r"antivirus|anti-virus|intrusion detection and prevention|host-based intrusion", [
        ("powershell", "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated",
         "Enabled and current signatures, unless a different DoD-approved product is installed (check its service and console)."),
        ("powershell", "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName, productState",
         "Lists the registered antivirus product (workstations only; Security Center is not present on servers).")]),
    (r"NTFS", [
        ("powershell", "Get-Volume | Where-Object DriveType -eq 'Fixed' | Select-Object DriveLetter, FileSystem",
         "Every fixed volume shows NTFS (or ReFS).")]),
    (r"file shares", [
        ("powershell", "Get-SmbShare | Where-Object Special -eq $false | Get-SmbShareAccess",
         "Only groups that need access are listed; no 'Everyone' with Full or Change access."),
        ("cmd", "net share", "Review any non-default shares (ADMIN$, C$, IPC$, NETLOGON and SYSVOL are system-created).")]),
    (r"Backup Operators", [
        ("powershell", "Get-LocalGroupMember -Group 'Backup Operators'", "Only accounts responsible for backups (separate from their normal accounts).")]),
    (r"Administrator rights|administrators responsible for|Administrative privileges must have separate", [
        ("powershell", "Get-LocalGroupMember -Group 'Administrators'",
         "Only accounts responsible for administering this system. On a domain controller use: Get-ADGroupMember 'Domain Admins'; Get-ADGroupMember 'Enterprise Admins'.")]),
    (r"create or run virtual machines", [
        ("powershell", "Get-LocalGroupMember -Group 'Hyper-V Administrators'", "Only authorized accounts (or empty if Hyper-V is not used).")]),
    (r"Standard local user accounts", [
        ("powershell", "Get-LocalUser | Select-Object Name, Enabled, Description",
         "Only the built-in Administrator, Guest, DefaultAccount and WDAGUtilityAccount (renamed and disabled as required).")]),
    (r"require password expiration", [
        ("powershell", "Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordExpires } | Select-Object Name",
         "No enabled accounts listed. For domain accounts: Search-ADAccount -PasswordNeverExpires -UsersOnly")]),
    (r"35 days of inactivity|Outdated or unused accounts", [
        ("powershell", "Get-LocalUser | Where-Object { $_.Enabled -and $_.LastLogon -lt (Get-Date).AddDays(-35) } | Select-Object Name, LastLogon",
         "No enabled accounts listed (accounts that never logged on show an empty LastLogon).")]),
    (r"permissions for (the )?system drive root|system drive root directory", [
        ("cmd", "icacls C:\\", "Matches the default ACL listed in the check procedure.")]),
    (r"program file directories", [
        ("cmd", 'icacls "C:\\Program Files" && icacls "C:\\Program Files (x86)"', "Matches the default ACLs listed in the check procedure.")]),
    (r"Windows directory", [
        ("cmd", "icacls C:\\Windows", "Matches the default ACL listed in the check procedure.")]),
    (r"system files and directories", [
        ("cmd", 'icacls C:\\ && icacls "C:\\Program Files" && icacls C:\\Windows', "Matches the default ACLs listed in the check procedure.")]),
    (r"HKEY_LOCAL_MACHINE registry hive", [
        ("powershell", "'HKLM:\\SECURITY','HKLM:\\SOFTWARE','HKLM:\\SYSTEM' | ForEach-Object { $_; (Get-Acl $_).Access | Format-Table IdentityReference, RegistryRights, AccessControlType -AutoSize }",
         "Matches the default permissions listed in the check procedure. Run elevated (SECURITY is readable by SYSTEM only).")]),
    (r"Application event log", [
        ("cmd", "icacls %SystemRoot%\\System32\\winevt\\Logs\\Application.evtx", "Only Eventlog, SYSTEM and Administrators with Full Control.")]),
    (r"Security event log", [
        ("cmd", "icacls %SystemRoot%\\System32\\winevt\\Logs\\Security.evtx", "Only Eventlog, SYSTEM and Administrators with Full Control.")]),
    (r"System event log", [
        ("cmd", "icacls %SystemRoot%\\System32\\winevt\\Logs\\System.evtx", "Only Eventlog, SYSTEM and Administrators with Full Control.")]),
    (r"Event Viewer must be protected", [
        ("cmd", "icacls %SystemRoot%\\System32\\Eventvwr.exe", "TrustedInstaller Full; Administrators, SYSTEM, Users and ALL APPLICATION PACKAGES Read & Execute only.")]),
    (r"Internet Information (System|Services)|\bIIS\b", [
        ("powershell", "Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole, IIS-HostableWebCore | Select-Object FeatureName, State",
         "State is Disabled (on servers: Get-WindowsFeature Web-Server shows Available).")]),
    (r"Simple Network Management Protocol|\bSNMP\b", [
        ("powershell", "Get-WindowsCapability -Online -Name 'SNMP*' | Select-Object Name, State; Get-WindowsFeature SNMP* -ErrorAction SilentlyContinue",
         "State NotPresent (not Installed).")]),
    (r"Simple TCP/IP", [
        ("powershell", "Get-WindowsOptionalFeature -Online -FeatureName SimpleTCP | Select-Object FeatureName, State", "State Disabled.")]),
    (r"Telnet Client", [
        ("powershell", "Get-WindowsOptionalFeature -Online -FeatureName TelnetClient | Select-Object FeatureName, State", "State Disabled.")]),
    (r"TFTP Client", [
        ("powershell", "Get-WindowsOptionalFeature -Online -FeatureName TFTP | Select-Object FeatureName, State", "State Disabled.")]),
    (r"Internet Explorer must be disabled", [
        ("powershell", "Get-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 | Select-Object FeatureName, State",
         "State Disabled (or the feature is not present).")]),
    (r"certificate installation files", [
        ("powershell", "Get-ChildItem -Path C:\\ -Recurse -Include *.p12, *.pfx -File -ErrorAction SilentlyContinue | Select-Object FullName",
         "No results (other than approved, documented files).")]),
    (r"host-based firewall", [
        ("powershell", "Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction",
         "Enabled True for Domain, Private and Public (or another DoD-approved firewall is installed).")]),
    (r"Secondary Logon service", [
        ("powershell", "Get-Service seclogon | Select-Object Status, StartType", "Stopped / Disabled.")]),
    (r"Wi-Fi Direct", [
        ("powershell", "Get-NetAdapter -IncludeHidden | Where-Object InterfaceDescription -like '*Wi-Fi Direct*' | Select-Object Name, Status, InterfaceDescription",
         "No adapter listed, or the adapter Status is Disabled.")]),
    (r"camera", [
        ("powershell", "Get-PnpDevice -Class Camera, Image -ErrorAction SilentlyContinue | Select-Object FriendlyName, Status",
         "Cameras are disabled (Status Error/Unknown) or physically covered.")]),
    (r"Copilot", [
        ("powershell", "Get-AppxPackage -AllUsers -Name '*Copilot*' | Select-Object Name, PackageFullName", "No results.")]),
    (r"Orphaned security identifiers", [
        ("powershell", "secedit /export /cfg \"$env:TEMP\\secpol.inf\" /areas USER_RIGHTS /quiet; Select-String -Path \"$env:TEMP\\secpol.inf\" -Pattern '\\*S-1-5-21-'",
         "Every domain/local SID listed must resolve to an existing account; unresolved SIDs are orphaned. Run elevated.")]),
    (r"DoW Root (CA|Certificate Authority)|DoD Root (CA|Certificate Authority)", [
        ("powershell", "Get-ChildItem -Path Cert:\\LocalMachine\\Root | Where-Object Subject -like '*DoD Root*' | Format-List Subject, Thumbprint, NotAfter",
         "The DoD Root CA certificates and thumbprints listed in the check procedure.")]),
    (r"External Root CA", [
        ("powershell", "Get-ChildItem -Path Cert:\\LocalMachine\\Root | Where-Object Subject -like '*ECA*' | Format-List Subject, Thumbprint, NotAfter",
         "The ECA Root CA certificates and thumbprints listed in the check procedure.")]),
    (r"CCEB Interoperability", [
        ("powershell", "Get-ChildItem -Path Cert:\\LocalMachine\\Disallowed | Where-Object Issuer -like '*CCEB Interoperability*' | Format-List Subject, Issuer, Thumbprint, NotAfter",
         "The cross-certificates listed in the check procedure are in the Untrusted (Disallowed) store.")]),
    (r"Interoperability Root CA cross-certificates|Interoperability Root Certificate Authority", [
        ("powershell", "Get-ChildItem -Path Cert:\\LocalMachine\\Disallowed | Where-Object Issuer -like '*Interoperability Root*' | Format-List Subject, Issuer, Thumbprint, NotAfter",
         "The cross-certificates listed in the check procedure are in the Untrusted (Disallowed) store.")]),
    (r"domain controllers? must have a PKI server certificate|domain controller PKI certificates", [
        ("powershell", "Get-ChildItem -Path Cert:\\LocalMachine\\My | Format-List Subject, Issuer, NotAfter, EnhancedKeyUsageList",
         "A valid server-authentication certificate issued by the DoD PKI or an approved ECA.")]),
    (r"Domain object must be configured with proper audit", [("powershell", _adacl("$dn", True), "Audit entries match the check procedure.")]),
    (r"Infrastructure object must be configured with proper audit", [("powershell", _adacl("CN=Infrastructure,$dn", True), "Audit entries match the check procedure.")]),
    (r"Domain Controllers Organizational Unit \(OU\) object must be configured with proper audit", [("powershell", _adacl("OU=Domain Controllers,$dn", True), "Audit entries match the check procedure.")]),
    (r"Domain Controllers Organizational Unit \(OU\) object must have", [("powershell", _adacl("OU=Domain Controllers,$dn", False), "Permissions match the check procedure.")]),
    (r"AdminSDHolder object", [("powershell", _adacl("CN=AdminSDHolder,CN=System,$dn", True), "Audit entries match the check procedure.")]),
    (r"RID Manager\$ object", [("powershell", _adacl("CN=RID Manager$,CN=System,$dn", True), "Audit entries match the check procedure.")]),
    (r"organization created Active Directory Organizational Unit", [
        ("powershell", _AD + "Get-ADOrganizationalUnit -Filter * | ForEach-Object { $_.DistinguishedName; (Get-Acl -Path \"AD:$($_.DistinguishedName)\").Access | Where-Object { -not $_.IsInherited } | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType -AutoSize }",
         "No unexpected identities with write, create or delete rights.")]),
    (r"Group Policy objects must have proper access control", [
        ("powershell", "Import-Module GroupPolicy; Get-GPO -All | ForEach-Object { $_.DisplayName; Get-GPPermission -Guid $_.Id -All | Format-Table Trustee, Permission -AutoSize }",
         "Only authorized groups have Edit or Edit/Delete/Modify Security permissions.")]),
    (r"directory data .* anonymous access", [
        ("powershell", _AD + "Get-ADObject \"CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$((Get-ADRootDSE).rootDomainNamingContext)\" -Properties dsHeuristics | Select-Object dsHeuristics",
         "dsHeuristics is empty, or its 7th character is not '2' (anonymous access disabled).")]),
    (r"print(er)? permissions", [
        ("powershell", "Get-Printer | ForEach-Object { Get-Printer -Name $_.Name -Full | Select-Object Name, PermissionSDDL }",
         "Non-administrative accounts have Print permission only.")]),
]
_WIN_TITLE_RX = [(re.compile(rx, re.I), cmds) for rx, cmds in WIN_TITLE_CMDS]


def windows_curated(title: str) -> list[dict]:
    for rx, cmds in _WIN_TITLE_RX:
        if rx.search(title):
            return [_cmd(sh, c, e, "curated") for sh, c, e in cmds]
    return []
