# STIG Explorer: DISA STIG Configuration Guide (RHEL, Ubuntu & Windows)

Generated 2026-11-15 21:34 UTC from DISA STIG XCCDF benchmarks (public.cyber.mil) and DISA CCI List. 3877 rules across 14 STIGs.

## Purpose

This guide explains what the DISA Security Technical Implementation Guides (STIGs) for Red Hat Enterprise Linux, Canonical Ubuntu and Microsoft Windows desktop/server operating systems change on a system, and why. It goes with the STIG Explorer search application and the per-STIG detail documents (docs/markdown and docs/word).

## How to read this document

Every rule is explained at three levels. Read the one that fits you, or all three:

- **Level 3: General Audience.** Plain language and an everyday analogy, for readers with little security or IT background.
- **Level 2: System Administrator.** The exact settings changed, where they live, how to check and fix them, and the operational impact.
- **Level 1: Cyber Security Professional.** DISA's risk rationale, threat context and MITRE ATT&CK techniques, and the CCI to NIST SP 800-53 Rev 3 / Rev 4 / Rev 5 control mapping.

Check and fix procedures, vulnerability discussions and CCI definitions are quoted from DISA's published STIG and CCI List. Topic explanations, threat context and plain-language summaries are written by STIG Explorer and should be read as guidance, not as authoritative DISA text. **The DISA STIG is always the authoritative source for compliance.**

## STIGs covered

| STIG | Release | Benchmark date | Rules | CAT I | CAT II | CAT III |
|---|---|---|---|---|---|---|
| Red Hat Enterprise Linux 7 | V3R15 | 24 Jul 2024 | 244 | 26 | 205 | 13 |
| Red Hat Enterprise Linux 8 | V2R9 | 30 Sep 2026 | 371 | 31 | 315 | 25 |
| Red Hat Enterprise Linux 9 | V2R10 | 30 Sep 2026 | 445 | 29 | 401 | 15 |
| Red Hat Enterprise Linux 10 | V1R3 | 30 Sep 2026 | 435 | 31 | 399 | 5 |
| Canonical Ubuntu 18.04 LTS | V2R15 | 24 Jul 2024 | 176 | 16 | 138 | 22 |
| Canonical Ubuntu 20.04 LTS | V2R4 | 01 Oct 2025 | 173 | 15 | 136 | 22 |
| Canonical Ubuntu 22.04 LTS | V2R10 | 30 Sep 2026 | 191 | 16 | 158 | 17 |
| Canonical Ubuntu 24.04 LTS | V1R7 | 30 Sep 2026 | 195 | 17 | 161 | 17 |
| Microsoft Windows 10 | V3R6 | 05 Jan 2026 | 267 | 28 | 221 | 18 |
| Microsoft Windows 11 | V2R11 | 30 Sep 2026 | 257 | 27 | 215 | 15 |
| Microsoft Windows Server 2016 | V2R10 | 15 Jan 2025 | 273 | 35 | 225 | 13 |
| ↳ Microsoft Windows Server 2016: domain controller view | V2R10 | 15 Jan 2025 | 259 | 33 | 213 | 13 |
| Microsoft Windows Server 2019 | V3R9 | 01 Jul 2026 | 282 | 34 | 234 | 14 |
| ↳ Microsoft Windows Server 2019: domain controller view | V3R9 | 01 Jul 2026 | 268 | 32 | 222 | 14 |
| Microsoft Windows Server 2022 | V2R11 | 30 Sep 2026 | 277 | 31 | 235 | 11 |
| ↳ Microsoft Windows Server 2022: domain controller view | V2R11 | 30 Sep 2026 | 263 | 29 | 223 | 11 |
| Microsoft Windows Server 2025 | V1R4 | 30 Sep 2026 | 291 | 31 | 249 | 11 |
| ↳ Microsoft Windows Server 2025: domain controller view | V1R4 | 30 Sep 2026 | 274 | 29 | 234 | 11 |

## NIST SP 800-53 revision mapping

Each STIG rule cites one or more CCIs (Control Correlation Identifiers). DISA's CCI List maps each CCI to NIST SP 800-53 controls in Revision 3, Revision 4 and Revision 5, so the same rule can be traced to whichever revision your authorization package (RMF/eMASS) uses. Most current DoD packages use Rev 5. Rev 3 references are kept for legacy packages and crosswalks.

| Control family | Rules mapped (Rev 5) | Rules mapped (Rev 3) |
|---|---|---|
| AC: Access Control | 897 | 494 |
| AU: Audit and Accountability | 937 | 844 |
| CM: Configuration Management | 1239 | 1069 |
| IA: Identification and Authentication | 457 | 319 |
| MA: Maintenance | 187 | 31 |
| SA: System and Services Acquisition | 4 | 0 |
| SC: System and Communications Protection | 415 | 198 |
| SI: System and Information Integrity | 158 | 81 |

## Topic reference (three levels)

Rules are grouped into security topics. Each topic below is explained at all three levels. Use it as training material or to brief stakeholders on a whole category at once.

### Security Event Auditing

*Records security-relevant events (logons, privilege use, changes).* (628 rules across all STIGs as the primary topic.)

**General audience:** This tells the computer to write down important security events in its diary, such as who logged in, who tried and failed, and who changed a setting or used admin powers. If something goes wrong, investigators can look back and see exactly what happened and who did it, much like a building's visitor sign-in log.

**System administrator (RHEL):** On RHEL, auditd rules are placed in /etc/audit/rules.d/*.rules and compiled into /etc/audit/audit.rules by 'augenrules --load'. Syscall rules use '-a always,exit -F arch=b64 -S <syscall>'. Command rules use '-F path=<binary> -F perm=x -F auid>=1000 -F auid!=unset -k <key>'. Watches use '-w <path> -p wa -k <key>'. Supply both b32 and b64 rules where the STIG shows them. Verify the loaded rules with 'auditctl -l' and search events with 'ausearch -k <key>'.

**System administrator (Ubuntu):** On Ubuntu, auditd rules are placed in /etc/audit/rules.d/*.rules and compiled into /etc/audit/audit.rules by 'augenrules --load'. Syscall rules use '-a always,exit -F arch=b64 -S <syscall>'. Command rules use '-F path=<binary> -F perm=x -F auid>=1000 -F auid!=unset -k <key>'. Watches use '-w <path> -p wa -k <key>'. Supply both b32 and b64 rules where the STIG shows them. Verify the loaded rules with 'auditctl -l' and search events with 'ausearch -k <key>'.

**System administrator (Windows):** On Windows, use Advanced Audit Policy Configuration (Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration). Also set 'Audit: Force audit policy subcategory settings to override audit policy category settings' (SCENoApplyLegacyAuditPolicy = 1), or legacy category settings may override them. Verify with 'auditpol /get /category:*'.

**Operational impact:** More audit rules mean more log volume and some CPU overhead on busy systems, particularly syscall rules on file-heavy workloads. Make sure log sizing and forwarding can handle the volume (see the audit storage rules).

**Cyber security professional:** Event auditing provides the detection and forensic record for nearly every other control. The STIG event set (logon/logoff, account and group management, privilege use, policy changes, use of privileged commands, permission changes, module loading, file deletion) implements AU-2 / AU-12 (event logging and generation), AU-3 (content) and AC-2(4) (automated audit of account actions). Coverage gaps translate directly into blind spots: an attacker's privilege escalation or persistence step that isn't logged can't be detected or reconstructed.

**ATT&CK:** T1562.002 Impair Defenses: Disable Windows Event Logging; T1562.012 Impair Defenses: Disable or Modify Linux Audit System; T1070 Indicator Removal

### File & Directory Permissions

*Restricts ownership and permissions on sensitive files and directories.* (244 rules across all STIGs as the primary topic.)

**General audience:** Every file on a computer has a label saying who owns it and who can read or change it. This rule makes sure sensitive files, such as the list of password fingerprints or system settings, can only be touched by the right people. It's like keeping personnel files in a locked HR cabinet rather than on the break-room table.

**System administrator (RHEL):** On RHEL, use 'stat -c "%a %U %G %n" <path>' to check mode and ownership, and 'chmod', 'chown' and 'chgrp' to fix them. Find problems with 'find / -xdev -nouser -o -nogroup' and 'find / -xdev -type d -perm -0002 ! -perm -1000'. Default permissions for new files come from umask (077 in /etc/login.defs and the shell profiles). 'rpm --setperms <pkg>' restores packaged defaults.

**System administrator (Ubuntu):** Check mode and ownership with 'stat -c "%a %U %G %n" <path>' and fix them with 'chmod', 'chown' and 'chgrp'. Find unowned files with 'find / -xdev -nouser -o -nogroup'. Default permissions for new files come from UMASK in /etc/login.defs. 'dpkg --verify' highlights packaged files that have changed.

**System administrator (Windows):** On Windows, check NTFS ACLs with 'icacls <path>' or 'Get-Acl'. The STIG specifies baseline ACLs for system folders, registry hives and event logs. Don't broaden the default ACLs on %SystemRoot%, Program Files or HKLM\SECURITY.

**Operational impact:** Tightening permissions can break applications that read their configuration as a non-root user. Prefer group-based access over loosening the mode, and re-check after package updates, which can reset modes.

**Cyber security professional:** Permissive ownership or modes on credentials (shadow, SSH host keys), libraries, system binaries, cron and boot configuration, and log files allow tampering, credential theft and execution-flow hijacking. This is AC-3 / AC-6 least privilege applied at the file-system layer, plus CM-5(6) (privilege to change software libraries). Unowned files and world-writable directories without the sticky bit are common persistence and escalation footholds.

**ATT&CK:** T1222 File and Directory Permissions Modification; T1574 Hijack Execution Flow; T1548.001 Abuse Elevation Control: Setuid and Setgid

### Windows User Rights Assignment

*Limits which accounts hold powerful Windows privileges.* (211 rules across all STIGs as the primary topic.)

**General audience:** Windows has a list of special powers, such as "shut down the computer", "look inside other programs' memory" or "log in remotely", and decides which accounts get each one. This rule makes sure only the right people, usually administrators, hold the powerful ones. It's like a hospital where only surgeons are allowed into the operating room.

**System administrator (RHEL):** On Linux the closest equivalents are sudoers rules, Linux capabilities, and PAM access controls.

**System administrator (Ubuntu):** On Linux the closest equivalents are sudoers rules, Linux capabilities, and PAM access controls.

**System administrator (Windows):** Configured at Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment. These are not registry values: they are stored in the local security database and applied from GptTmpl.inf in a GPO. Review the effective assignment with 'secedit /export /cfg c:\temp\secpol.inf /areas USER_RIGHTS' or the Local Security Policy console. An empty but defined setting means 'no one'.

**Operational impact:** Removing service accounts from rights such as 'Log on as a service' or 'Impersonate a client after authentication' can stop applications (SQL Server, IIS app pools, backup agents). Document required application accounts as approved exceptions before enforcing.

**Cyber security professional:** User rights (privileges) such as SeDebugPrivilege, SeImpersonatePrivilege, SeBackupPrivilege, SeTcbPrivilege and SeLoadDriverPrivilege each give a direct path to SYSTEM-level compromise or credential theft. Logon rights (network, interactive, RDP, batch, service) define which accounts can authenticate through which channel. Enforcing least privilege here implements AC-6 / AC-6(10) and limits blast radius when a lower-privileged account is compromised. Pay particular attention to 'Deny' rights for privileged domain accounts on lower-tier systems, which enforce an administrative tiering model.

**ATT&CK:** T1134 Access Token Manipulation; T1003 OS Credential Dumping; T1078 Valid Accounts

### Privilege Elevation (UAC / sudo)

*Controls how standard users and admins elevate to administrative rights.* (153 rules across all STIGs as the primary topic.)

**General audience:** Even administrators work day-to-day without full power, and the system asks them to confirm, often by re-entering a password, before doing anything that could change important settings. That way, a harmful program can't quietly use admin power behind their back. It's like a bank requiring a second signature for large withdrawals.

**System administrator (RHEL):** On RHEL, sudo policy lives in /etc/sudoers and /etc/sudoers.d/ (always edit with 'visudo', validate with 'visudo -c'). STIG items include removing NOPASSWD and !authenticate, setting 'Defaults timestamp_timeout=0', and restricting 'ALL ALL=(ALL) ALL'. 'su' is restricted to the wheel group with pam_wheel in /etc/pam.d/su.

**System administrator (Ubuntu):** On Ubuntu, sudo policy lives in /etc/sudoers and /etc/sudoers.d/ (always edit with 'visudo', validate with 'visudo -c'). STIG items include removing NOPASSWD and !authenticate, setting 'Defaults timestamp_timeout=0', and restricting 'ALL ALL=(ALL) ALL'. 'su' is restricted to the wheel group with pam_wheel in /etc/pam.d/su.

**System administrator (Windows):** UAC settings are Security Options named 'User Account Control: ...' (registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System: EnableLUA, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser, FilterAdministratorToken, EnableInstallerDetection, EnableSecureUIAPaths, EnableVirtualization).

**Operational impact:** Turning off password-less sudo affects automation such as Ansible and cron jobs. Use dedicated automation accounts with tightly scoped command lists and documented exceptions. Disabling UAC (EnableLUA = 0) is not acceptable and also breaks Store/UWP apps.

**Cyber security professional:** Elevation controls make privilege use deliberate, authenticated and auditable (AC-6(1)/(2)/(9)/(10), IA-11 re-authentication). UAC's secure-desktop prompt resists UI spoofing and input injection by malware running in the user's session. sudo restrictions (no NOPASSWD, no '!authenticate', short timestamp_timeout, no blanket ALL grants) prevent silent escalation by any process running as an admin user. Every elevation event should produce an audit record.

**ATT&CK:** T1548.002 Abuse Elevation Control: Bypass UAC; T1548.003 Abuse Elevation Control: Sudo and Sudo Caching; T1068 Exploitation for Privilege Escalation

### SSH Remote Administration

*Hardens the SSH service used for remote command-line access.* (151 rules across all STIGs as the primary topic.)

**General audience:** SSH is the secure "remote control" administrators use to manage the computer over the network by typing commands. This rule tightens how that remote control works: who may use it, how they prove their identity, and how idle connections are closed. It's like making sure the building's service entrance has a good lock and isn't propped open.

**System administrator (RHEL):** sshd reads /etc/ssh/sshd_config, and on RHEL 9/10 also drop-ins under /etc/ssh/sshd_config.d/ that are processed in lexical order, where the first value obtained wins. Put STIG settings in an early-sorting drop-in (e.g. 00-stig.conf) so a vendor file can't silently override them. Validate syntax with 'sshd -t', check the effective configuration with 'sshd -T | grep -i <keyword>', then 'systemctl reload sshd'.

**System administrator (Ubuntu):** sshd reads /etc/ssh/sshd_config and, on 22.04 and later, drop-ins in /etc/ssh/sshd_config.d/*.conf, which are included at the top of the main file so their values take precedence (first value wins). Validate with 'sshd -t', check the effective configuration with 'sshd -T | grep -i <keyword>', then 'systemctl reload ssh' (the unit is named 'ssh' on Ubuntu).

**System administrator (Windows):** For OpenSSH on Windows, configuration lives in %ProgramData%\ssh\sshd_config. Restart the 'sshd' service after changes.

**Operational impact:** Keep an existing session open while you reload sshd so a typo can't lock you out. Disabling root login requires named admin accounts plus sudo. Idle timeouts (ClientAliveInterval/CountMax) will disconnect long-running interactive sessions, so use tmux or screen for those.

**Cyber security professional:** SSH is the primary remote administration channel on Linux and therefore a high-value target. Hardening reduces the attack surface: no root or empty-password logins, no host-based trust (rhosts) or user environment injection, strict file-mode checks, idle-session termination, and approved cryptography only. These settings support AC-17 (Remote Access), AC-12, IA-2 and SC-8. Also check authorized_keys sprawl and key lifecycle, which no STIG setting fully covers.

**ATT&CK:** T1021.004 Remote Services: SSH; T1110 Brute Force; T1098.004 Account Manipulation: SSH Authorized Keys

### Audit Log Capacity, Offloading & Failure Handling

*Ensures audit logs have space, are sent off-host and alert on failure.* (140 rules across all STIGs as the primary topic.)

**General audience:** The computer keeps a "security diary" of important events. This rule makes sure the diary has enough pages, that a copy is sent to a separate, safe location, and that someone is alerted if the diary fills up or stops working. It's like a store's security cameras recording to an off-site server so a thief can't simply take the tape.

**System administrator (RHEL):** On RHEL, auditd capacity and failure behavior are set in /etc/audit/auditd.conf (space_left, space_left_action, admin_space_left(_action), disk_full_action, disk_error_action, max_log_file(_action), action_mail_acct). Off-loading uses rsyslog (omfwd with TLS via gtls/ossl stream drivers) or the audisp-remote / audit 'remote' plugin. Put /var/log/audit on its own partition so it can't starve the root file system. Restart with 'service auditd restart', because systemctl is blocked for auditd.

**System administrator (Ubuntu):** auditd capacity and failure behavior are set in /etc/audit/auditd.conf (space_left, space_left_action, disk_full_action, action_mail_acct). Off-load with audisp-remote (package audispd-plugins, configured in /etc/audit/audisp-remote.conf or plugins.d/au-remote.conf) or forward with rsyslog. Install auditd with 'apt-get install auditd audispd-plugins'.

**System administrator (Windows):** On Windows, event log sizes are set under Administrative Templates >> Windows Components >> Event Log Service >> Application/Security/System >> 'Specify the maximum log file size (KB)'. Forward events with Windows Event Forwarding (WEF) or a SIEM agent. Retention behavior is configured in the same policy node.

**Operational impact:** Actions such as 'halt' or 'single' on disk-full prioritize integrity over availability and can take a production system down. Agree the action with the ISSO/AO and monitor free space proactively. Larger local logs consume disk; forwarding requires network connectivity and certificates for TLS.

**Cyber security professional:** Logs that roll over, fill the disk or exist only on the compromised host can't support incident response. Attackers routinely clear or flood local logs. AU-4 (storage capacity), AU-4(1) (transfer to alternate storage), AU-5 (response to processing failures) and AU-9(2) (backup onto a separate system) require sized local storage, real-time off-host forwarding, and defined behavior (alert, halt or single-user) when audit capability is lost. Validate end-to-end delivery at the SIEM, not just the client configuration.

**ATT&CK:** T1070 Indicator Removal; T1562.006 Impair Defenses: Indicator Blocking

### Smart Card / PKI & Multifactor Authentication

*Requires certificate-based (CAC/PIV) or multifactor authentication.* (137 rules across all STIGs as the primary topic.)

**General audience:** Instead of (or in addition to) a password, you prove who you are with something you physically carry, such as a government ID card (CAC) with a chip in it, plus a PIN. Someone who learns your PIN still can't get in without the card. It's like a bank requiring both your debit card and your PIN at the ATM.

**System administrator (RHEL):** On RHEL, smart card login is handled by SSSD with 'pam_cert_auth = True', the certificate trust store configured in sssd.conf / /etc/sssd/pki/sssd_auth_ca_db.pem, and certificate mapping rules (matchrule/maprule). Revocation checking is configured with 'certificate_verification' (OCSP). authselect features such as 'with-smartcard' wire SSSD into PAM.

**System administrator (Ubuntu):** Ubuntu uses libpam-pkcs11 and opensc-pkcs11 for CAC/PIV login: a pam_pkcs11.so line in /etc/pam.d/common-auth, certificate mapping and OCSP/CRL policy in /etc/pam_pkcs11/pam_pkcs11.conf, and DoD CA certificates installed under /etc/ssl/certs (or /usr/local/share/ca-certificates followed by 'update-ca-certificates').

**System administrator (Windows):** On Windows the relevant settings are the Trusted Root / Intermediate certificate stores (deployed with the DoD InstallRoot tool or GPO) and 'Untrusted Certificates' for the cross-certificates DISA requires removing. Smart card enforcement is set per account or through 'Interactive logon: Require Windows Hello for Business or smart card'. Verify with certlm.msc or 'Get-ChildItem Cert:\LocalMachine\Root'.

**Operational impact:** Mis-mapped certificates or stale CA bundles lock users out. Stage CA updates before old certificates expire, test revocation checking (OCSP/CRL reachability) on isolated networks, and keep a documented break-glass account.

**Cyber security professional:** Certificate-based multifactor authentication removes reusable shared secrets from the authentication path, which neutralizes password spraying, credential stuffing and most phishing. The trust store controls which CAs can issue identities the system accepts, so installing only DoD-approved roots (and removing untrusted or cross-certified ones) is an integrity control on authentication itself. Relevant controls: IA-2(1)/(2)/(12), IA-5(2) (PKI-based authentication: path validation and revocation checking), SC-17.

**ATT&CK:** T1078 Valid Accounts; T1110 Brute Force; T1556 Modify Authentication Process

### Least Functionality: Remove Unneeded Software

*Removes or disables software, features and services that aren't required.* (135 rules across all STIGs as the primary topic.)

**General audience:** Every program on a computer is another possible way in for an attacker. This rule removes software the system doesn't need, especially old programs known to be unsafe. It's like clearing clutter out of a house: fewer things lying around means fewer things that can be broken or misused.

**System administrator (RHEL):** On RHEL, remove packages with 'dnf remove <pkg>' and verify with 'rpm -q <pkg>' (expect 'package <pkg> is not installed'). Watch for dependency cascades in the dnf transaction summary before confirming.

**System administrator (Ubuntu):** Remove packages with 'apt-get remove --purge <pkg>' (purge also deletes their configuration files) and verify with 'dpkg -l | grep <pkg>'. Check what else 'apt' plans to remove before confirming the transaction.

**System administrator (Windows):** On Windows Server, remove roles and features with 'Uninstall-WindowsFeature <Name>' or through Server Manager. On client OSes, use 'Disable-WindowsOptionalFeature -Online -FeatureName <Name>'. Verify with 'Get-WindowsFeature | Where Installed' or 'Get-WindowsOptionalFeature -Online'.

**Operational impact:** Check that no application depends on the component before removing it (e.g. legacy scripts using PowerShell 2.0, tools that shell out to telnet or ftp). Keep a record of what was removed so it can be restored if a mission requirement is identified.

**Cyber security professional:** Every installed package, role and feature is potential attack surface, and some (telnet, rsh, TFTP, SMBv1, PowerShell 2.0) are inherently insecure or allow security controls to be bypassed. For example, PowerShell 2.0 bypasses script-block logging and AMSI. CM-7 (least functionality) and CM-7(1)/(2) require removing what isn't mission-necessary. Removal also reduces patch burden and false positives in vulnerability scans.

**ATT&CK:** T1190 Exploit Public-Facing Application; T1210 Exploitation of Remote Services; T1059 Command and Scripting Interpreter

### File Sharing (SMB) & Anonymous Access

*Requires SMB signing and blocks anonymous enumeration and access.* (126 rules across all STIGs as the primary topic.)

**General audience:** Computers on a network share files with each other using a system called SMB. This rule makes every file-sharing conversation carry a tamper-proof "seal" and stops strangers who haven't signed in from browsing the list of users and shared folders. It's like requiring visitors to sign in at the front desk before they can read the staff directory.

**System administrator (RHEL):** On RHEL, Samba equivalents are 'server signing = mandatory', 'restrict anonymous = 2' and 'server min protocol = SMB2' in smb.conf.

**System administrator (Ubuntu):** On Ubuntu, Samba equivalents are 'server signing = mandatory', 'restrict anonymous = 2' and 'server min protocol = SMB2' in smb.conf.

**System administrator (Windows):** Mostly Security Options: 'Microsoft network client/server: Digitally sign communications (always)' (RequireSecuritySignature), 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' (RestrictAnonymous), 'Let Everyone permissions apply to anonymous users', 'Restrict anonymous access to Named Pipes and Shares', 'Network access: Restrict clients allowed to make remote calls to SAM'. SMBv1 is removed with 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'. Check with 'Get-SmbServerConfiguration'.

**Operational impact:** Mandatory signing adds CPU overhead on high-throughput file servers (usually negligible on modern hardware) and can break very old clients and some NAS devices. Restricting anonymous access can affect legacy apps that rely on null sessions.

**Cyber security professional:** SMB is the backbone of Windows file and administrative traffic and a principal lateral-movement channel. Unsigned SMB enables NTLM relay attacks. Anonymous (null session) access and SAM/share enumeration give unauthenticated attackers reconnaissance data such as user lists and group memberships. SMBv1 lacks modern protections and was the propagation vector for WannaCry and NotPetya. These settings support AC-3, AC-14 (actions without identification), SC-8 and CM-7.

**ATT&CK:** T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay; T1135 Network Share Discovery; T1087 Account Discovery; T1021.002 Remote Services: SMB/Windows Admin Shares

### Network Stack Hardening

*Hardens IP/ICMP behavior and disables risky name-resolution protocols.* (122 rules across all STIGs as the primary topic.)

**General audience:** These settings change how the computer handles network traffic at a low level, for example ignoring suspicious "take a detour" messages and not answering "who is this?" broadcasts that attackers can fake. It's like a mail room that refuses packages with forged return addresses and won't hand mail to anyone who just shouts a name.

**System administrator (RHEL):** On RHEL, set these with sysctl drop-ins in /etc/sysctl.d/ (net.ipv4.conf.all/default.accept_redirects = 0, send_redirects = 0, accept_source_route = 0, ip_forward = 0, rp_filter = 1, tcp_syncookies = 1, icmp_echo_ignore_broadcasts = 1, and IPv6 equivalents). Apply them with 'sysctl --system'. Both 'all' and 'default' must be set so that new interfaces inherit the values. DNS resolvers are set through NetworkManager or /etc/resolv.conf.

**System administrator (Ubuntu):** On Ubuntu, set these with sysctl drop-ins in /etc/sysctl.d/ (net.ipv4.conf.all/default.accept_redirects = 0, send_redirects = 0, accept_source_route = 0, ip_forward = 0, rp_filter = 1, tcp_syncookies = 1, icmp_echo_ignore_broadcasts = 1, and IPv6 equivalents). Apply them with 'sysctl --system'. Both 'all' and 'default' must be set so that new interfaces inherit the values. DNS resolvers are set through NetworkManager or /etc/resolv.conf.

**System administrator (Windows):** On Windows, set these through MSS (Legacy) templates included with the STIG GPO package (DisableIPSourceRouting, EnableICMPRedirect, NoNameReleaseOnDemand) and Network >> DNS Client >> 'Turn off multicast name resolution' (EnableMulticast = 0). Hardened UNC Paths requires mutual authentication and integrity for \\*\SYSVOL and \\*\NETLOGON.

**Operational impact:** Hosts that legitimately route (VPN concentrators, container and Kubernetes nodes, libvirt hosts) need IP forwarding and must document the exception. Disabling LLMNR and NetBIOS requires working DNS for all name lookups.

**Cyber security professional:** Host network-stack defaults favor interoperability over safety. Accepting ICMP redirects or source-routed packets lets an on-path attacker reroute traffic. IP forwarding turns a host into an unintended router between security zones. Multicast name resolution (LLMNR, NBT-NS, mDNS) is trivially poisoned to capture NTLM hashes. Reverse-path filtering and SYN cookies blunt spoofing and resource-exhaustion attacks. These settings support SC-5, SC-7 (boundary protection) and CM-7.

**ATT&CK:** T1557 Adversary-in-the-Middle; T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay; T1040 Network Sniffing; T1498 Network Denial of Service

### Audit Log & Tool Protection

*Protects audit logs, configuration and tools from tampering.* (111 rules across all STIGs as the primary topic.)

**General audience:** The security diary is only useful if nobody can secretly edit or tear pages out of it. This rule locks down who can read or change the logs and the tools that manage them. It's like keeping the security camera footage in a locked room that only a couple of trusted people can enter.

**System administrator (RHEL):** On RHEL, audit logs live under /var/log/audit/ (mode 0600 or 0640, owned by root, group per log_group). Audit tools are /sbin/auditctl, aureport, ausearch, autrace, auditd, rsyslogd and augenrules (mode 0755, owned by root). '-e 2' at the end of the rules makes the configuration immutable until reboot, and '--loginuid-immutable' prevents processes from changing their audit login UID.

**System administrator (Ubuntu):** On Ubuntu, audit logs live under /var/log/audit/ (mode 0600 or 0640, owned by root, group per log_group). Audit tools are /sbin/auditctl, aureport, ausearch, autrace, auditd, rsyslogd and augenrules (mode 0755, owned by root). '-e 2' at the end of the rules makes the configuration immutable until reboot, and '--loginuid-immutable' prevents processes from changing their audit login UID.

**System administrator (Windows):** On Windows, event log file permissions are on %SystemRoot%\System32\winevt\Logs\*.evtx. The default ACL (Eventlog service, SYSTEM, Administrators) must not be broadened. The 'Manage auditing and security log' user right must be limited to Administrators.

**Operational impact:** With '-e 2', any later audit rule change requires a reboot to take effect, so schedule audit rule updates in maintenance windows.

**Cyber security professional:** If a non-privileged user, or an attacker running as one, can read, alter or delete audit data or reconfigure the audit subsystem, the audit trail loses its evidentiary value. AU-9 (protection of audit information) together with AU-9(3) (cryptographic protection) and AU-9(4) (access by subset of privileged users) require restrictive ownership and modes on logs and tools, integrity verification of audit binaries (via AIDE), and immutable audit rules ('-e 2') so the rule set can't be changed without a reboot.

**ATT&CK:** T1070.002 Indicator Removal: Clear Linux or Mac System Logs; T1070.001 Indicator Removal: Clear Windows Event Logs; T1562.012 Impair Defenses: Disable or Modify Linux Audit System

### Kernel & Memory Exploit Mitigations

*Enables OS defenses that make software exploits harder (ASLR, DEP, etc.).* (107 rules across all STIGs as the primary topic.)

**General audience:** Hackers often break in by tricking a program into running their own instructions. These settings turn on built-in defenses that shuffle where things sit in memory and refuse to run code from places it shouldn't come from. It's like a bank regularly moving the vault around and refusing to accept instructions written on deposit slips.

**System administrator (RHEL):** On RHEL, kernel tunables are set in /etc/sysctl.d/*.conf (applied with 'sysctl --system' and verified with 'sysctl <key>'). Remember that a later file or /etc/sysctl.conf can override an earlier drop-in, and the STIG check typically greps all locations for conflicts. Boot parameters (e.g. 'vsyscall=none', 'page_poison=1', 'pti=on', 'slub_debug=P', 'audit=1') are set with 'grubby --update-kernel=ALL --args=...'. Core dumps are controlled through /etc/systemd/coredump.conf and 'ulimit -c'.

**System administrator (Ubuntu):** Set kernel tunables in /etc/sysctl.d/*.conf and apply them with 'sysctl --system'. Boot parameters are added to GRUB_CMDLINE_LINUX in /etc/default/grub, followed by 'update-grub' and a reboot. Disable core dumps through /etc/security/limits.conf ('* hard core 0') and /etc/systemd/coredump.conf.

**System administrator (Windows):** On Windows, set these through Exploit Protection (system DEP, SEHOP, ASLR: 'Get-ProcessMitigation -System'), the 'Turn On Virtualization Based Security' policy under Device Guard, and the MS Security Guide 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' policy.

**Operational impact:** Restricting ptrace and dmesg affects debuggers (gdb, strace) for non-root users. Disabling core dumps removes crash diagnostics. HVCI can block older or unsigned drivers, so check driver compatibility first. Most sysctl changes are immediate, while boot parameters require a reboot.

**Cyber security professional:** These mitigations don't remove vulnerabilities. They raise the cost and lower the reliability of exploiting them. ASLR, DEP/NX and SEHOP break classic memory-corruption techniques. Restricting ptrace, kernel pointer exposure, dmesg, unprivileged BPF and kexec removes common local-privilege-escalation primitives and information leaks. Hypervisor-enforced code integrity (HVCI) and VBS protect the kernel itself. These support SI-16 (memory protection), SC-39 (process isolation) and CM-6 baseline configuration.

**ATT&CK:** T1068 Exploitation for Privilege Escalation; T1055 Process Injection; T1014 Rootkit; T1203 Exploitation for Client Execution

### Account Lifecycle Management

*Disables inactive, temporary and unauthorized accounts.* (106 rules across all STIGs as the primary topic.)

**General audience:** Every person should have their own account, and accounts that nobody is using (people who left, temporary contractors, test accounts) should be turned off. Forgotten accounts are like old keys still floating around after someone moves out. You never know who might use them.

**System administrator (RHEL):** On RHEL, inactivity is enforced with 'INACTIVE=35' in /etc/default/useradd ('useradd -D -f 35') for new accounts and 'chage -I' for existing ones. Temporary accounts get an expiry date ('chage -E'). Check /etc/passwd and /etc/group for duplicate UIDs and GIDs ('pwck', 'grpck') and that every interactive user has a valid, owned home directory.

**System administrator (Ubuntu):** On Ubuntu, inactivity is enforced with 'INACTIVE=35' in /etc/default/useradd ('useradd -D -f 35') for new accounts and 'chage -I' for existing ones. Temporary accounts get an expiry date ('chage -E'). Check /etc/passwd and /etc/group for duplicate UIDs and GIDs ('pwck', 'grpck') and that every interactive user has a valid, owned home directory.

**System administrator (Windows):** On Windows, use 'Search-ADAccount -AccountInactive -TimeSpan 35' for domain accounts. For local accounts, review 'Get-LocalUser' (LastLogon, PasswordExpires) and disable or delete accounts that aren't needed. Shared accounts require ISSO-documented justification.

**Operational impact:** Before you automatically disable inactive accounts, confirm that service, break-glass and seasonal-user accounts are inventoried and either exempted with documentation or monitored.

**Cyber security professional:** Dormant, orphaned and shared accounts are prime persistence and initial-access vectors because nobody notices their use. AC-2 (Account Management) and its enhancements (AC-2(2) temporary/emergency account removal, AC-2(3) disable inactive accounts) require automated lifecycle enforcement. IA-2 and IA-4 require unique identifiers so actions can be attributed to individuals. Assessors typically sample accounts against an authoritative roster.

**ATT&CK:** T1078 Valid Accounts; T1136 Create Account; T1098 Account Manipulation

### Password Strength & Complexity

*Sets minimum length and character-mix rules for passwords.* (103 rules across all STIGs as the primary topic.)

**General audience:** This sets the rules for how strong a password must be: long enough, and mixing capitals, lowercase letters, numbers and symbols. Short or simple passwords can be guessed by computers in seconds. A long, varied password is like a key with many unique notches that's much harder to copy.

**System administrator (RHEL):** RHEL enforces this through pam_pwquality, configured in /etc/security/pwquality.conf or a drop-in under /etc/security/pwquality.conf.d/ (minlen, dcredit/ucredit/lcredit/ocredit as negative numbers meaning 'at least N', minclass, maxrepeat, maxclassrepeat, difok, dictcheck). The pam_pwquality module must appear in the password stack of system-auth and password-auth. Test with 'pwscore' or by changing a test user's password.

**System administrator (Ubuntu):** Install libpam-pwquality ('apt-get install libpam-pwquality'), set minlen, dcredit/ucredit/lcredit/ocredit, difok, dictcheck and enforcing in /etc/security/pwquality.conf, and make sure /etc/pam.d/common-password calls pam_pwquality.so (with retry=3). Ubuntu manages the PAM stack with 'pam-auth-update'.

**System administrator (Windows):** Windows sets this in Account Policies >> Password Policy ('Minimum password length', 'Password must meet complexity requirements'). Domain-wide values come from the Default Domain Policy or Fine-Grained Password Policies (PSOs). Lengths above 14 require the 'Relax minimum password length limits' setting on newer builds.

**Operational impact:** Takes effect at each user's next password change. Communicate the new requirements beforehand, and check that provisioning scripts and self-service reset portals can generate compliant passwords.

**Cyber security professional:** Length and composition rules raise the cost of both online guessing and offline cracking of captured hashes (IA-5(1)). DoD still requires a 15-character minimum with character-class rules, while NIST SP 800-63B now favors length plus breached-password screening over composition rules. Where the two conflict, the STIG governs for DoD systems. Note that complexity rules apply only when a password is changed, so assess the age of existing passwords too.

**ATT&CK:** T1110.002 Brute Force: Password Cracking; T1110.001 Brute Force: Password Guessing

### File System Layout & Mount Options

*Separates partitions and restricts execution/device files via mount options.* (101 rules across all STIGs as the primary topic.)

**General audience:** The computer's storage is divided into separate sections, like rooms in a house. This rule keeps certain rooms separate so one can't overflow into the others, and marks rooms such as the "temporary storage" area as places where programs aren't allowed to run. It's like a garage where you can store things but nobody is allowed to live.

**System administrator (RHEL):** On RHEL, partitions are defined at install time (/home, /tmp, /var, /var/log, /var/log/audit, /var/tmp). Changing them later generally needs LVM work or a rebuild. Mount options go in /etc/fstab (e.g. 'defaults,nodev,nosuid,noexec') and are applied with 'mount -o remount <mountpoint>'. Verify with 'findmnt -no OPTIONS <mountpoint>'. Disable autofs ('systemctl disable --now autofs') unless it's required.

**System administrator (Ubuntu):** On Ubuntu, partitions are defined at install time (/home, /tmp, /var, /var/log, /var/log/audit, /var/tmp). Changing them later generally needs LVM work or a rebuild. Mount options go in /etc/fstab (e.g. 'defaults,nodev,nosuid,noexec') and are applied with 'mount -o remount <mountpoint>'. Verify with 'findmnt -no OPTIONS <mountpoint>'. Disable autofs ('systemctl disable --now autofs') unless it's required.

**System administrator (Windows):** On Windows, NTFS is required for all local volumes. Separate data volumes are an availability practice.

**Operational impact:** 'noexec' on /tmp can break installers and tools that extract and run helpers there. Set TMPDIR to an alternate location for those. Re-partitioning a running system is disruptive, so build the layout into the kickstart profile instead.

**Cyber security professional:** Separate partitions keep runaway logs or user data from exhausting the root file system, which is an availability and audit-integrity concern (AU-4, SC-5). Mount options remove whole classes of attack. 'nodev' blocks device files, 'nosuid' neutralizes planted SUID binaries, and 'noexec' prevents execution from world-writable locations such as /tmp and /dev/shm, a common staging area for exploits (CM-6, CM-7).

**ATT&CK:** T1068 Exploitation for Privilege Escalation; T1499 Endpoint Denial of Service

### Active Directory & Domain Controller Security

*Hardens domain controllers, LDAP, secure channel and directory objects.* (95 rules across all STIGs as the primary topic.)

**General audience:** In an organization, a few central servers (domain controllers) keep the master list of every user, password and permission. This rule adds extra protection to those servers and the conversations other computers have with them. It's like guarding the room that holds the master key cabinet more tightly than any other room in the building.

**System administrator (RHEL):** On RHEL, the counterparts are realmd/SSSD domain join settings and the 'ldap_id_use_start_tls' and 'ldap_tls_reqcert' options.

**System administrator (Ubuntu):** On RHEL, the counterparts are realmd/SSSD domain join settings and the 'ldap_id_use_start_tls' and 'ldap_tls_reqcert' options.

**System administrator (Windows):** On Windows, the relevant Security Options include 'Domain controller: LDAP server signing requirements' (Require signing), 'Domain member: Digitally encrypt or sign secure channel data (always)' and 'Domain member: Maximum machine account password age' (30 days). DC-specific checks review permissions on NTDS (%SystemRoot%\NTDS), SYSVOL and GPOs, and AD object auditing (SACLs). Use 'dcdiag', 'repadmin /showrepl' and ADSI Edit or 'Get-Acl AD:' to verify.

**Operational impact:** Enforcing LDAP signing or channel binding breaks clients and appliances that use simple binds over unsigned LDAP. Check Directory Service event 2889 to find them before enforcing.

**Cyber security professional:** Domain controllers hold the keys to every domain identity, so DC compromise is total enterprise compromise. Requirements cover LDAP signing and channel binding (anti-relay), secure-channel signing and sealing, machine-account password rotation, protection of NTDS/SYSVOL/GPO permissions, restricting who can administer and log on to DCs, and directory auditing. These implement AC-3, AC-6, SC-8, SC-23 and AU-2 for the identity tier. Assess them alongside the administrative tiering model.

**ATT&CK:** T1003.006 OS Credential Dumping: DCSync; T1484 Domain or Tenant Policy Modification; T1558 Steal or Forge Kerberos Tickets; T1557 Adversary-in-the-Middle

### Approved Cryptography (FIPS 140)

*Restricts encryption, hashing and key exchange to approved, strong algorithms.* (94 rules across all STIGs as the primary topic.)

**General audience:** Encryption is how computers scramble information so eavesdroppers can't read it. Some older scrambling methods have been "cracked" and are no longer safe. This rule makes the computer use only methods the U.S. government has tested and approved, like requiring modern, certified locks instead of old ones that a locksmith can easily pick.

**System administrator (RHEL):** RHEL centralizes crypto settings in system-wide crypto policies: 'fips-mode-setup --enable' (RHEL 8) or 'fips=1' on the kernel command line at install time (RHEL 9/10), then 'update-crypto-policies --set FIPS'. Back-end files under /etc/crypto-policies/back-ends/ (openssh, opensslcnf, bind, gnutls and others) are generated from the policy, and individual services such as sshd must be pointed at them rather than hard-coding algorithms. Verify with 'fips-mode-setup --check' and 'update-crypto-policies --show'.

**System administrator (Ubuntu):** Ubuntu provides FIPS 140-validated modules through Ubuntu Pro: 'pro enable fips-updates' (or 'fips'), then reboot into the FIPS kernel. Verify with 'cat /proc/sys/crypto/fips_enabled' (expect 1). sshd ciphers, MACs and key exchange algorithms are set explicitly in /etc/ssh/sshd_config, because Ubuntu has no RHEL-style system-wide crypto-policies.

**System administrator (Windows):** On Windows, 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' (HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\Enabled) restricts Schannel and CNG to FIPS-approved algorithms. Related settings cover Kerberos encryption types and NTLM session security.

**Operational impact:** Enabling FIPS mode can break applications that use non-approved algorithms (MD5 for non-security checksums, older Java code, legacy VPN or SSH clients). Enable it at install time where possible, because switching an existing RHEL 9/10 system into FIPS mode is not supported for production. Test interoperating systems before rollout.

**Cyber security professional:** Federal systems must use FIPS 140-validated cryptographic modules (SC-13). Weak or legacy algorithms (MD5, SHA-1 MACs, CBC-mode ciphers, RC4, DES/3DES, small DH groups) enable downgrade, decryption or forgery attacks against data in transit (SC-8, SC-8(1)). The control is only as strong as its weakest negotiated option, so assessors look at the full allowed list, not just the preferred algorithm. Note that FIPS mode validates the module, not the protocol configuration, so both must be checked.

**ATT&CK:** T1040 Network Sniffing; T1557 Adversary-in-the-Middle; T1600 Weaken Encryption

### Built-in & Privileged Account Hardening

*Restricts root/Administrator/Guest accounts and empty passwords.* (91 rules across all STIGs as the primary topic.)

**General audience:** Every computer comes with a few built-in "master" accounts whose names everyone knows. This rule makes those accounts harder to abuse, for example by not letting anyone log in directly as the master account and never allowing accounts with no password. It's like not leaving the master key labelled "MASTER KEY" hanging by the front door.

**System administrator (RHEL):** On RHEL, root logon is controlled through sshd ('PermitRootLogin no'), /etc/securetty (where present), and PAM. Empty passwords are blocked by removing 'nullok' from pam_unix in system-auth and password-auth and by setting 'PermitEmptyPasswords no' for sshd. Only root should have UID 0 ('awk -F: "$3==0" /etc/passwd').

**System administrator (Ubuntu):** Lock the root password ('passwd -l root') so administrators work through sudo, set 'PermitRootLogin no' and 'PermitEmptyPasswords no' for sshd, and remove 'nullok' from pam_unix in /etc/pam.d/common-auth and common-password so empty passwords are rejected.

**System administrator (Windows):** On Windows these are Security Options ('Accounts: Rename administrator account', 'Accounts: Guest account status', 'Accounts: Limit local account use of blank passwords to console logon only') plus LAPS for unique, rotated local administrator passwords.

**Operational impact:** Make sure at least one named administrator account with sudo or admin rights works before disabling root or Administrator logon paths. Renaming the built-in Administrator can break scripts that reference it by name.

**Cyber security professional:** Well-known accounts (root, Administrator, Guest) are guaranteed to exist with predictable names, which makes them ideal targets. Blocking direct logon forces attribution through named accounts (IA-2, AC-6(2)). Removing empty-password acceptance eliminates trivial access, and unique local admin passwords (LAPS) break pass-the-hash lateral movement across a fleet. Assess the effective result across every access path: console, SSH, RDP and network logon.

**ATT&CK:** T1078.001 Valid Accounts: Default Accounts; T1078.003 Valid Accounts: Local Accounts; T1110 Brute Force

### Session Lock & Inactivity Timeout

*Locks or ends idle sessions and conceals the screen.* (82 rules across all STIGs as the primary topic.)

**General audience:** If you walk away from the computer and forget to lock it, it will lock itself after a short time (15 minutes for DoD) and hide what was on the screen. Anyone who sits down then has to sign in again. It's like a car that locks its doors automatically when you walk away.

**System administrator (RHEL):** On RHEL, set GNOME locking through dconf in /etc/dconf/db/local.d/ (org/gnome/desktop/session idle-delay=uint32 900, org/gnome/desktop/screensaver lock-enabled=true, lock-delay=uint32 5) and lock each key in /etc/dconf/db/local.d/locks/ so users can't override it. Then run 'dconf update'. For terminals, set TMOUT=900 (readonly) in /etc/profile.d/. Network and SSH sessions use ClientAliveInterval/CountMax and systemd-logind StopIdleSessionSec.

**System administrator (Ubuntu):** Set GNOME locking through dconf (org/gnome/desktop/screensaver lock-enabled=true, org/gnome/desktop/session idle-delay=uint32 900) with matching locks, followed by 'dconf update'. For console sessions, install 'vlock' so users can lock a terminal, and set TMOUT=900 (readonly) in /etc/profile.d/. SSH idle termination uses ClientAliveInterval/CountMax.

**System administrator (Windows):** On Windows, set 'Interactive logon: Machine inactivity limit' (InactivityTimeoutSecs <= 900) and 'Interactive logon: Smart card removal behavior' (Lock Workstation). Personalization policies prevent the lock screen from showing slide shows or camera access.

**Operational impact:** Users running long unattended interactive jobs may be disconnected. Kiosk or operations displays that must stay visible need a documented exception and compensating physical controls.

**Cyber security professional:** Unattended, unlocked sessions are an opportunistic access path for insiders and visitors, so physical access becomes logical access. AC-11 (device lock, 15 minutes in DoD), AC-11(1) (pattern-hiding displays) and AC-12 (session termination) require automatic locking that the user can't override, re-authentication to unlock, and concealment of on-screen content. Smart-card removal locking extends this to CAC workflows.

**ATT&CK:** T1078 Valid Accounts

### Password Age, History & Reuse

*Controls how often passwords change and prevents reusing old ones.* (81 rules across all STIGs as the primary topic.)

**General audience:** This makes people change passwords every so often and stops them from simply switching back to a password they used recently. If a password was quietly stolen, it eventually stops working, a bit like changing the locks periodically in case someone copied a key.

**System administrator (RHEL):** On RHEL, defaults for new accounts come from /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS), while existing accounts must be updated individually with 'chage -M/-m <days> <user>' (review with 'chage -l <user>'). History is enforced by pam_pwhistory ('remember = 5' in /etc/security/pwhistory.conf or on the module line).

**System administrator (Ubuntu):** On Ubuntu, defaults for new accounts come from /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS), while existing accounts must be updated individually with 'chage -M/-m <days> <user>' (review with 'chage -l <user>'). History is enforced by pam_pwhistory ('remember = 5' in /etc/security/pwhistory.conf or on the module line).

**System administrator (Windows):** Windows sets this in Account Policies >> Password Policy: 'Maximum password age', 'Minimum password age', 'Enforce password history'. Domain values come from the Default Domain Policy or PSOs.

**Operational impact:** Changing login.defs does not retroactively update existing accounts, so remember to run chage for current users. Exclude non-interactive service accounts from expiry only through a documented exception (or use gMSAs on Windows).

**Cyber security professional:** Maximum age bounds the useful lifetime of a compromised credential. Minimum age plus history prevent users from cycling straight back to a known password, which would defeat the history check (IA-5(1)(d)/(e)). The trend in current guidance is to prefer event-driven rotation (on suspected compromise) over periodic rotation, but the DoD baseline values remain enforceable requirements.

**ATT&CK:** T1078 Valid Accounts; T1110.004 Brute Force: Credential Stuffing

### Removable Media, Peripherals & Wireless

*Restricts USB storage, AutoPlay, Bluetooth, wireless and other peripherals.* (77 rules across all STIGs as the primary topic.)

**General audience:** USB sticks, Bluetooth and Wi-Fi are convenient, but they're also easy ways for a virus to sneak in or for data to sneak out. This rule turns off or tightly controls these connections. It's like a secure office that doesn't let visitors plug unknown devices into its computers.

**System administrator (RHEL):** On RHEL, kernel modules are blocked by adding 'install usb-storage /bin/false' and 'blacklist usb-storage' to /etc/modprobe.d/*.conf (similar entries for bluetooth and firewire-core). USBGuard ('dnf install usbguard', policy in /etc/usbguard/rules.conf, generated with 'usbguard generate-policy') allowlists permitted devices. Wireless interfaces are disabled with 'nmcli radio all off'.

**System administrator (Ubuntu):** Block USB storage with 'install usb-storage /bin/false' and 'blacklist usb-storage' in /etc/modprobe.d/*.conf, and check with 'modprobe -n -v usb-storage'. Disable wireless interfaces with 'nmcli radio all off' or by blacklisting their driver modules. USBGuard is available from the Ubuntu archive ('apt-get install usbguard').

**System administrator (Windows):** On Windows, AutoPlay and AutoRun are under Administrative Templates >> Windows Components >> AutoPlay Policies (NoDriveTypeAutoRun = 0xFF, NoAutorun = 1). Device installation restrictions are under System >> Device Installation, and DMA protection under Kernel DMA Protection.

**Operational impact:** Blocking USB storage affects users who move data on thumb drives, so provide an approved transfer method. Make sure USBGuard policies allow keyboards, mice and smart card readers before enforcing, or you may lose console input.

**Cyber security professional:** Removable media and peripheral interfaces bypass network-layer defenses. They enable malware introduction (AutoRun worms, BadUSB, HID injection), data exfiltration, and DMA attacks via Thunderbolt or FireWire. Wireless radios add unmanaged network paths. These settings implement MP-7 (media use), AC-18/AC-19 (wireless and mobile device access) and CM-7 (least functionality) and should be paired with device-control allowlisting (USBGuard, Windows device installation restrictions).

**ATT&CK:** T1091 Replication Through Removable Media; T1052.001 Exfiltration Over USB; T1200 Hardware Additions

### Remote Desktop & Remote Management

*Hardens RDP, WinRM and other remote-management channels.* (76 rules across all STIGs as the primary topic.)

**General audience:** Administrators can control computers from far away, as if they were sitting at the keyboard. This rule makes sure those remote connections are encrypted, require a proper sign-in every time, and can't be used to copy files around carelessly. It's like requiring a video-verified, recorded call before anyone can give orders over the phone.

**System administrator (RHEL):** On RHEL, X11 forwarding ('X11Forwarding no' in sshd), VNC servers and cockpit are the main remote-access paths to restrict.

**System administrator (Ubuntu):** On Ubuntu, X11 forwarding ('X11Forwarding no' in sshd), VNC servers and cockpit are the main remote-access paths to restrict.

**System administrator (Windows):** On Windows, RDP settings are under Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host (Security / Device and Resource Redirection / Session Time Limits), and WinRM settings under Windows Components >> Windows Remote Management (WinRM Client / WinRM Service). Verify WinRM with 'winrm get winrm/config'.

**Operational impact:** Disabling drive and clipboard redirection affects admin convenience. WinRM restrictions can break management tools that use Basic auth over HTTP (some older configuration-management and monitoring products), so move those to Kerberos or HTTPS.

**Cyber security professional:** Remote-management protocols give interactive or programmatic control of a host and are a favored vector for both ransomware operators and insiders. Requirements include encrypted transport, no Basic/Digest authentication or unencrypted WinRM traffic, always prompting for credentials, no saved RDP passwords, no drive redirection, and session time limits. These implement AC-17 (remote access), AC-17(2) (confidentiality and integrity via encryption), SC-8 and AC-12 (session termination).

**ATT&CK:** T1021.001 Remote Services: Remote Desktop Protocol; T1021.006 Remote Services: Windows Remote Management; T1563 Remote Service Session Hijacking; T1040 Network Sniffing

### Windows Authentication Protocols (NTLM, Kerberos, LSA)

*Hardens NTLM/Kerberos and protects LSASS credential material.* (72 rules across all STIGs as the primary topic.)

**General audience:** When you log into a Windows network, your computer and the server trade secret "handshakes" to prove who you are. Older handshakes are easy for attackers to fake or steal. This rule switches off the old, weak handshakes and protects the part of memory where Windows keeps your sign-in secrets, like retiring an old ID badge design that was easy to forge.

**System administrator (RHEL):** On Linux these relate to Kerberos (krb5.conf) and SSSD settings. Disable weak enctypes and GSSAPI and Kerberos authentication in sshd unless they are required.

**System administrator (Ubuntu):** On Linux these relate to Kerberos (krb5.conf) and SSSD settings. Disable weak enctypes and GSSAPI and Kerberos authentication in sshd unless they are required.

**System administrator (Windows):** Most of these are Security Options under Local Policies, plus MS Security Guide templates (SecGuide.admx shipped with the STIG GPO package). Key settings include 'Network security: LAN Manager authentication level' (LmCompatibilityLevel = 5), 'Network security: Configure encryption types allowed for Kerberos', 'Minimum session security for NTLM SSP', WDigest 'UseLogonCredential' = 0, and Credential Guard via Device Guard >> 'Turn On Virtualization Based Security'. Verify with 'gpresult /h' or the registry paths shown in the check.

**Operational impact:** Enforcing NTLMv2-only or AES-only Kerberos can break legacy appliances, older NAS devices, multifunction printers and non-Windows clients. Run NTLM and Kerberos auditing (event IDs 4624/4776/4768/4769) first to inventory dependencies. Credential Guard is incompatible with some VPN clients and with unconstrained delegation.

**Cyber security professional:** Windows authentication protocols are central to most domain compromise chains. Legacy LM/NTLMv1 responses can be cracked or relayed. WDigest leaves cleartext passwords in LSASS memory. Weak Kerberos encryption types (RC4/DES) enable Kerberoasting and downgrade attacks. Credential Guard and LSA protection (RunAsPPL) isolate secrets from credential-dumping tools. These settings implement IA-2(8) (replay resistance), IA-5(1)(c), SC-8 and SC-23 (session authenticity). Validate the domain-wide impact with NTLM auditing before enforcing restrictions.

**ATT&CK:** T1003.001 OS Credential Dumping: LSASS Memory; T1550.002 Use Alternate Authentication Material: Pass the Hash; T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay; T1558 Steal or Forge Kerberos Tickets

### Telemetry, Cloud & Consumer Features

*Limits data sharing with vendors and disables consumer/cloud features.* (71 rules across all STIGs as the primary topic.)

**General audience:** Modern computers like to "phone home", sending usage data to the manufacturer, syncing to personal cloud accounts, or showing ads and suggestions. This rule turns those features off or down so government information stays inside the government's systems, like not letting a delivery driver wander through the office and take notes.

**System administrator (RHEL):** On RHEL, the equivalents are disabling the ABRT crash reporter, Insights client data sharing, and GNOME online accounts if they're not approved.

**System administrator (Ubuntu):** On Ubuntu, the equivalents are disabling Apport crash reporting ('systemctl disable --now apport'), the 'ubuntu-report' and popularity-contest data collection, MOTD news ('ENABLED=0' in /etc/default/motd-news), and GNOME online accounts if they're not approved.

**System administrator (Windows):** On Windows these are mostly Administrative Templates under Windows Components (Data Collection and Preview Builds, Cloud Content, Search, Store, OneDrive, Windows Error Reporting, App Privacy) and the Microsoft Edge templates. Verify the registry values under HKLM\SOFTWARE\Policies\Microsoft\... as shown in each check.

**Operational impact:** Users lose consumer conveniences such as Store apps, Microsoft-account sign-in and web results in search. Enterprise management may need a minimum telemetry level (e.g. for Windows Update for Business reports), so align the value with the STIG's allowed options.

**Cyber security professional:** Consumer-oriented and cloud-connected features can move government data (documents, typed input, location, diagnostic dumps containing memory contents) to vendor or third-party services outside the authorization boundary. Disabling or restricting them supports SC-7 (boundary protection), AC-20 (use of external systems), CM-7 and privacy controls, and removes unvetted functionality from the baseline.

**ATT&CK:** T1567 Exfiltration Over Web Service; T1213 Data from Information Repositories

### Account Lockout

*Locks accounts after repeated failed logon attempts.* (70 rules across all STIGs as the primary topic.)

**General audience:** If someone types the wrong password a few times in a row, the account is temporarily locked so they can't keep guessing. It's like a phone that freezes after several wrong passcodes, which stops a thief from trying every possible combination.

**System administrator (RHEL):** RHEL 8.2+ uses pam_faillock configured in /etc/security/faillock.conf (deny, fail_interval, unlock_time, even_deny_root, dir, audit, silent) and wired into system-auth and password-auth by authselect ('authselect enable-feature with-faillock'). Inspect with 'faillock --user <name>' and reset with 'faillock --user <name> --reset'. Pointing 'dir' at a persistent path such as /var/log/faillock keeps lockouts across reboots.

**System administrator (Ubuntu):** Ubuntu 22.04/24.04 use pam_faillock, configured in /etc/security/faillock.conf (deny, fail_interval, unlock_time, audit, silent, dir) and referenced from /etc/pam.d/common-auth (preauth/authfail lines) and common-account. Older releases used pam_tally2. Inspect with 'faillock --user <name>' and reset with 'faillock --user <name> --reset'.

**System administrator (Windows):** Windows configures this under Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy (threshold, duration, reset counter). For domain accounts it is set in the Default Domain Policy or a Fine-Grained Password Policy, and local policy affects only local accounts.

**Operational impact:** Service accounts with stale cached credentials (mapped drives, scheduled tasks, mobile mail clients) can trigger repeated lockouts. Identify the lockout source (Windows Event ID 4740; faillock and audit logs on Linux) before loosening the threshold.

**Cyber security professional:** Lockout thresholds turn online password guessing from an unlimited search into a handful of attempts per window (AC-7). The trade-off is denial of service: an attacker who knows usernames can deliberately lock out accounts, which is why DoD pairs a low threshold (3) with an administrator-unlock or timed-unlock requirement. Lockout does nothing against offline cracking of stolen hashes or against password spraying that stays below the threshold, so it complements, rather than replaces, password strength and MFA.

**ATT&CK:** T1110.001 Brute Force: Password Guessing; T1110.003 Brute Force: Password Spraying

### Boot Process & Console Security

*Protects the boot loader, firmware and recovery/console paths.* (70 rules across all STIGs as the primary topic.)

**General audience:** While a computer is starting up, before the normal sign-in screen appears, there are special "maintenance doors" that can skip the usual security. This rule puts locks on those doors and makes sure the computer only starts with trusted software, like making sure nobody can hot-wire a car by tampering with it before the key is turned.

**System administrator (RHEL):** On RHEL, set the GRUB2 superuser password with 'grub2-setpassword' (stored hashed in /boot/grub2/user.cfg or /boot/efi/EFI/redhat/user.cfg) and set a unique superuser name in /etc/grub.d/01_users. Rescue and emergency modes must require root authentication (sulogin in rescue.service and emergency.service). Mask Ctrl-Alt-Del with 'systemctl mask ctrl-alt-del.target' and 'CtrlAltDelBurstAction=none' in systemd's system.conf. Mask debug-shell. kdump is disabled unless it's needed.

**System administrator (Ubuntu):** Create a GRUB superuser password hash with 'grub-mkpasswd-pbkdf2' and add 'set superusers="<name>"' and 'password_pbkdf2 <name> <hash>' to /etc/grub.d/40_custom (or 00_header), then run 'update-grub'. Kernel parameters go in GRUB_CMDLINE_LINUX in /etc/default/grub, followed by 'update-grub'. Disable Ctrl-Alt-Delete with 'systemctl mask ctrl-alt-del.target' and 'systemctl daemon-reload'.

**System administrator (Windows):** On Windows, Secure Boot and the TPM are verified with 'Confirm-SecureBootUEFI' and 'Get-Tpm'. Firmware must be UEFI, not Legacy BIOS. Boot-time protection also comes from BitLocker and the Early Launch Antimalware policy.

**Operational impact:** Store the boot-loader password in the system's credential vault, because you'll need it for kernel-parameter troubleshooting. Converting Legacy BIOS installs to UEFI generally requires MBR2GPT or a rebuild.

**Cyber security professional:** Anyone with console or hypervisor access can interrupt the boot process to edit kernel parameters (e.g. 'init=/bin/bash'), boot into single-user or rescue mode, or load an untrusted boot loader, bypassing all OS authentication. A boot-loader password, authenticated rescue modes and UEFI Secure Boot close this path (AC-3, CM-6, SI-7(9) boot process integrity). Disabling Ctrl-Alt-Del and similar console actions prevents accidental or malicious reboots (availability).

**ATT&CK:** T1542 Pre-OS Boot; T1542.003 Pre-OS Boot: Bootkit; T1529 System Shutdown/Reboot

### Software & File Integrity Verification

*Verifies package signatures and detects unauthorized file changes.* (63 rules across all STIGs as the primary topic.)

**General audience:** This makes the computer check a digital "seal" on software before installing it, and keep a fingerprint of important files so it can notice if anyone changes them. It's like checking that a medicine bottle's safety seal is intact, and noticing straight away if someone has tampered with it.

**System administrator (RHEL):** On RHEL, repositories must have 'gpgcheck=1' (/etc/dnf/dnf.conf and /etc/yum.repos.d/*.repo) and 'localpkg_gpgcheck=1', with Red Hat GPG keys imported ('rpm -q gpg-pubkey'). AIDE is configured in /etc/aide.conf (rules should include acl, xattrs and sha512). Initialize with 'aide --init' and move the new database into place. Schedule 'aide --check' daily (cron or systemd timer) with notification to the SA/ISSO.

**System administrator (Ubuntu):** APT verifies repository signatures with the keys in /etc/apt/trusted.gpg.d/ and per-source 'signed-by' keyrings, so never add '[trusted=yes]' or '--allow-unauthenticated'. Install AIDE with 'apt-get install aide aide-common', initialize with 'aideinit', and configure rules in /etc/aide/aide.conf. A daily check runs from /etc/cron.daily/dailyaidecheck. 'dpkg --verify' checks installed files against package checksums.

**System administrator (Windows):** On Windows, use WDAC/AppLocker for signature enforcement, 'sfc /verifyonly' for system file verification, and the enterprise FIM product.

**Operational impact:** AIDE reports every legitimate change too, so re-baseline after approved patching and keep the database read-only or off-host. Internal repositories must sign their packages, or clients will refuse them.

**Cyber security professional:** Signature verification ensures only vendor-authentic software is installed (CM-14 signed components, SI-7 software and information integrity). File-integrity monitoring such as AIDE detects unauthorized modification of binaries and configuration after the fact (SI-7(1), CM-3(5)), catching rootkits, backdoored binaries and configuration drift. The value of FIM depends on protecting the baseline database off-host and acting on alerts.

**ATT&CK:** T1195 Supply Chain Compromise; T1554 Compromise Host Software Binary; T1014 Rootkit

### Host Firewall

*Requires an active host firewall with a deny-by-default policy.* (47 rules across all STIGs as the primary topic.)

**General audience:** A firewall is a gatekeeper that decides which network connections are allowed in and out of the computer. This rule makes sure the gatekeeper is switched on and turns away anything that isn't on the approved list, like a security guard who only lets in people with an appointment.

**System administrator (RHEL):** On RHEL, use firewalld (systemctl enable --now firewalld) with nftables as the backend (FirewallBackend=nftables in /etc/firewalld/firewalld.conf). Set the default zone to drop or deny and add only the required services and ports ('firewall-cmd --permanent --add-service=...', then '--reload'). Review with 'firewall-cmd --list-all-zones'.

**System administrator (Ubuntu):** Ubuntu uses UFW (Uncomplicated Firewall) as the front end to nftables or iptables. Install and enable it with 'apt-get install ufw' and 'ufw enable', set default-deny with 'ufw default deny incoming', and allow only the required services ('ufw allow <port>/<proto>', or 'ufw limit ssh' for rate limiting). Review with 'ufw status verbose'.

**System administrator (Windows):** On Windows, use Windows Defender Firewall with Advanced Security. Turn it on for the Domain, Private and Public profiles with inbound set to block by default. Scope management rules (RDP, WinRM, SMB) to the management subnets. Verify with 'Get-NetFirewallProfile' and 'Get-NetFirewallRule'.

**Operational impact:** An over-restrictive default can cut off management or application traffic. Make changes from the console, or stage them with a timed rollback ('firewall-cmd --timeout').

**Cyber security professional:** A host firewall enforces deny-by-default, allow-by-exception at the endpoint (SC-7(5)) and contains lateral movement even when the perimeter is breached or the host sits on a flat network. Exposed ports must match the system's PPSM registration (CM-7(1)). Remote-management exceptions should be scoped to authorized management hosts rather than 'any'. Check that the firewall service can't be stopped by non-administrators and that rule changes are audited.

**ATT&CK:** T1562.004 Impair Defenses: Disable or Modify System Firewall; T1021 Remote Services; T1046 Network Service Discovery

### Credential Storage & Password Hashing

*Ensures passwords are stored only as strong one-way hashes.* (40 rules across all STIGs as the primary topic.)

**General audience:** Computers shouldn't store your actual password. Instead they store a scrambled "fingerprint" of it that can't be turned back into the password. This rule makes sure that fingerprint is created with a strong method, so that even if someone steals the file, they can't easily work out everyone's passwords.

**System administrator (RHEL):** On RHEL, hashes are stored in /etc/shadow. The algorithm for new passwords comes from ENCRYPT_METHOD (and SHA_CRYPT_MIN_ROUNDS) in /etc/login.defs, 'crypt_style' in /etc/libuser.conf, and the pam_unix module options. Existing hashes are upgraded only when users change their passwords. Check the hash prefix in /etc/shadow ($6$ = SHA-512).

**System administrator (Ubuntu):** Ubuntu stores hashes in /etc/shadow. Set ENCRYPT_METHOD SHA512 in /etc/login.defs and make sure the pam_unix line in /etc/pam.d/common-password uses sha512 (with an appropriate rounds value). Existing hashes are only upgraded when users next change their passwords.

**System administrator (Windows):** Relevant Windows settings include 'Network security: Do not store LAN Manager hash value on next password change' (NoLMHash), 'Store passwords using reversible encryption' (Disabled), and 'Interactive logon: Number of previous logons to cache' (CachedLogonsCount).

**Operational impact:** Reducing cached logons can prevent laptop users from signing in when they are off the network. Disabling LM hashes affects only very old clients (pre-Windows 2000 era).

**Cyber security professional:** When a host is compromised, stored credential material is the attacker's path to lateral movement. Weak or reversible storage (LM hashes, reversible encryption, low-iteration hashes, excessive cached domain logons) turns a single compromise into credential recovery for many accounts. IA-5(1)(c) requires that only cryptographically protected passwords be stored and transmitted. Strong salted, iterated hashing such as SHA-512 crypt with sufficient rounds increases offline cracking cost.

**ATT&CK:** T1003 OS Credential Dumping; T1110.002 Brute Force: Password Cracking; T1552 Unsecured Credentials

### Logon Banner & Consent Notice

*Displays the DoD notice-and-consent banner before access.* (38 rules across all STIGs as the primary topic.)

**General audience:** Before anyone can sign in, the computer shows a warning message saying the system belongs to the government, that activity is monitored, and that using it means you agree to that. Think of it like the "this area is under video surveillance" sign at the entrance to a building: it doesn't lock the door, but it makes the rules clear and discourages misuse.

**System administrator (RHEL):** On RHEL the banner is typically set in /etc/issue (console and SSH pre-auth via the sshd 'Banner' directive) and in the GNOME login screen via dconf ('banner-message-enable' and 'banner-message-text'). The text must match the DoD standard banner exactly, including line breaks where the check text calls for them.

**System administrator (Ubuntu):** On Ubuntu the banner is typically set in /etc/issue (console and SSH pre-auth via the sshd 'Banner' directive) and in the GNOME login screen via dconf ('banner-message-enable' and 'banner-message-text'). The text must match the DoD standard banner exactly, including line breaks where the check text calls for them.

**System administrator (Windows):** On Windows the banner is configured through Security Options: 'Interactive logon: Message title for users attempting to log on' and 'Interactive logon: Message text for users attempting to log on' (registry LegalNoticeCaption / LegalNoticeText under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).

**Operational impact:** No functional impact. Automated logons and kiosk workflows will need to acknowledge the banner, and some scanners compare the text byte-for-byte, so copy it from the STIG rather than retyping it.

**Cyber security professional:** A notice-and-consent banner is a legal and deterrence control rather than a technical barrier. It establishes that users have no expectation of privacy, which supports monitoring, incident response and prosecution, and it satisfies AC-8 (System Use Notification). Assessors verify the exact approved DoD text, that it appears for every access path (console, GUI, SSH and other remote sessions), and that the user must acknowledge it before the session continues.

### Logon Screen & Desktop Settings

*Controls what the logon screen and desktop reveal or allow.* (35 rules across all STIGs as the primary topic.)

**General audience:** This decides what the sign-in screen shows and which shortcuts are allowed. For example, it hides the list of usernames, doesn't show who signed in last, and turns off "sign in automatically". It's like a hotel front desk that won't tell a stranger which room a guest is in.

**System administrator (RHEL):** On RHEL, GDM and GNOME settings are managed through dconf databases in /etc/dconf/db/{gdm,local}.d/ with matching locks, followed by 'dconf update'. Examples include disable-user-list, disable-restart-buttons, and 'AutomaticLoginEnable=false' in /etc/gdm/custom.conf. If no GUI is required, remove the GNOME and X packages and set 'systemctl set-default multi-user.target'.

**System administrator (Ubuntu):** On Ubuntu, GDM3 settings live in /etc/gdm3/ (for example 'AutomaticLoginEnable=false' in /etc/gdm3/custom.conf), and GNOME policy is managed through dconf databases in /etc/dconf/db/local.d/ with locks, followed by 'dconf update'. If no GUI is required, remove the desktop packages and set 'systemctl set-default multi-user.target'.

**System administrator (Windows):** On Windows, use Security Options such as 'Interactive logon: Don't display last signed-in' and 'Do not require CTRL+ALT+DEL' (Disabled). Administrative Templates >> System >> Logon covers enumerating local users, convenience PIN and picture password. Credential User Interface >> 'Do not display the password reveal button' handles the reveal button.

**Operational impact:** Users will need to type their username in full and can't use convenience sign-in methods. Hiding restart buttons on the logon screen means console users need credentials to reboot.

**Cyber security professional:** The logon surface can leak information (usernames, the last logged-on user, local administrator lists) that cuts an attacker's effort in half, and convenience features (automatic logon, picture passwords, convenience PINs, password reveal buttons) weaken authentication assurance. These settings reduce information disclosure (AC-14, IA-6 authenticator feedback) and keep interactive logon on approved authenticators.

**ATT&CK:** T1087 Account Discovery; T1078 Valid Accounts

### Time Synchronization

*Synchronizes system clocks with authoritative DoD time sources.* (33 rules across all STIGs as the primary topic.)

**General audience:** This keeps the computer's clock exactly in step with an official time source. That might sound minor, but security logs from different computers can only be pieced together if every clock agrees, and some sign-in systems refuse to work when clocks drift. It's like making sure all the witnesses' watches show the same time.

**System administrator (RHEL):** On RHEL, chronyd is configured in /etc/chrony.conf: use 'server <DoD-time-source> iburst maxpoll 16', 'port 0' (don't act as a server) and 'cmdport 0'. Verify with 'chronyc sources -v' and 'timedatectl'. Time stamps should map to UTC/GMT.

**System administrator (Ubuntu):** Ubuntu uses chrony (or systemd-timesyncd by default on some releases). For chrony, configure /etc/chrony/chrony.conf with 'server <DoD-time-source> iburst maxpoll 16' and 'makestep 1 -1', and disable systemd-timesyncd so the two don't conflict. Verify with 'chronyc sources -v' and 'timedatectl'.

**System administrator (Windows):** On Windows, domain members sync from the domain hierarchy (NT5DS). The PDC emulator must point to an authoritative source using Administrative Templates >> System >> Windows Time Service >> Time Providers >> 'Configure Windows NTP Client'. Verify with 'w32tm /query /status'.

**Operational impact:** Large clock corrections can confuse running applications. chrony slews gradually by default. Make sure the time servers are reachable through the firewall (UDP 123).

**Cyber security professional:** Accurate, synchronized time underpins log correlation across systems, Kerberos authentication (5-minute skew tolerance), certificate validity checks and forensic timelines (AU-8, AU-8(1) synchronization with an authoritative source, AU-8(2) secondary source). Time sources should be authenticated where possible and restricted to client mode, so the host can't be abused as an NTP amplifier.

**ATT&CK:** T1070.006 Indicator Removal: Timestomp

### Authentication Stack (PAM, SSSD, Directory)

*Configures PAM/SSSD authentication modules and identity sources.* (31 rules across all STIGs as the primary topic.)

**General audience:** Behind the sign-in screen is a chain of checks: the password is right, the account isn't locked, the password isn't expired, and so on. This rule makes sure every check in that chain is present and in the correct order, like making sure every guard at a multi-checkpoint entrance is at their post.

**System administrator (RHEL):** On RHEL, PAM stacks live in /etc/pam.d/ (system-auth, password-auth, login, sshd, su). Manage them through authselect profiles ('authselect select sssd with-faillock with-mkhomedir ...', 'authselect current'), because authselect overwrites hand edits. Custom changes belong in a custom profile ('authselect create-profile'). SSSD is configured in /etc/sssd/sssd.conf and conf.d/ (mode 0600, owned by root), and you restart sssd after changes. Concurrent session limits are set in /etc/security/limits.conf ('* hard maxlogins 10').

**System administrator (Ubuntu):** Ubuntu's PAM stacks are /etc/pam.d/common-auth, common-account, common-password and common-session. They are regenerated by 'pam-auth-update' from profiles in /usr/share/pam-configs/, so persistent changes belong in a custom profile there or must be re-checked after package updates. SSSD (if used) is configured in /etc/sssd/sssd.conf (mode 0600, owned by root).

**System administrator (Windows):** On Windows, the domain authentication stack is governed by Kerberos/NTLM policy and the netlogon secure channel settings.

**Operational impact:** PAM mistakes can lock everyone out, including root. Test changes from a second, still-open root session, and keep console access available.

**Cyber security professional:** PAM and SSSD define how every Linux authentication decision is made. Misordered or optional modules silently bypass controls such as faillock, pwquality and pwhistory. Credential caching lifetimes trade availability against revocation latency, so a revoked account keeps working offline until its cache expires. These settings support IA-2, IA-5(13) (expiration of cached authenticators), AC-7, AC-9 (previous logon notification) and AC-10 (concurrent session control).

**ATT&CK:** T1556.003 Modify Authentication Process: Pluggable Authentication Modules; T1110 Brute Force

### Patching & Supported Software

*Requires vendor-supported OS versions and current security updates.* (24 rules across all STIGs as the primary topic.)

**General audience:** Software makers regularly release fixes for security holes they discover. This rule requires installing those fixes and only running versions that are still supported. It's like getting the recall repair on your car: skip it, and the known problem stays there for anyone to take advantage of.

**System administrator (RHEL):** On RHEL, patch from approved repositories with 'dnf update' (or 'dnf update --security'). Review history with 'dnf history' and pending errata with 'dnf updateinfo list'. Setting 'clean_requirements_on_remove=True' in /etc/dnf/dnf.conf removes orphaned dependencies when software is removed. Check the release with 'cat /etc/redhat-release' against Red Hat's life-cycle page.

**System administrator (Ubuntu):** Patch from approved repositories with 'apt-get update && apt-get upgrade' (or 'unattended-upgrades' for automatic security updates). Review pending updates with 'apt list --upgradable'. Check the release with 'lsb_release -a' against Canonical's support lifecycle; an Ubuntu Pro subscription extends security maintenance (ESM).

**System administrator (Windows):** On Windows, patch through WSUS, ConfigMgr, Intune or Windows Update for Business. Check installed updates with 'Get-HotFix' and the OS build with 'winver' against Microsoft's lifecycle page.

**Operational impact:** Patching requires maintenance windows and sometimes reboots. Test critical applications against updates in a staging environment, but don't let testing stretch beyond IAVM deadlines.

**Cyber security professional:** Known, unpatched vulnerabilities remain the most common initial-access and privilege-escalation vector. Running an unsupported release means new vulnerabilities will never be fixed. SI-2 (flaw remediation) and SA-22 (unsupported system components) require timely patching per organizational timelines (IAVM compliance in DoD) and replacement of end-of-life components. Unsupported OS findings are CAT I because they can't be mitigated by configuration alone.

**ATT&CK:** T1190 Exploit Public-Facing Application; T1068 Exploitation for Privilege Escalation; T1210 Exploitation of Remote Services

### Anti-Malware & Reputation Protection

*Keeps antivirus, SmartScreen and malware defenses enabled and current.* (23 rules across all STIGs as the primary topic.)

**General audience:** This keeps the computer's virus scanner switched on and up to date, and warns people before they open files or websites known to be dangerous. It's the digital equivalent of a smoke detector with fresh batteries.

**System administrator (RHEL):** On RHEL, use the enterprise-approved endpoint product (e.g. Trellix/ENSL). Verify that the agent service is active and its definitions are current.

**System administrator (Ubuntu):** On Ubuntu, use the enterprise-approved endpoint product (e.g. Trellix/ENSL). Verify that the agent service is active and its definitions are current.

**System administrator (Windows):** On Windows, configure Microsoft Defender Antivirus under Administrative Templates >> Windows Components >> Microsoft Defender Antivirus, and SmartScreen under Windows Components >> File Explorer and Microsoft Edge. Verify with 'Get-MpComputerStatus' (AMServiceEnabled, AntivirusSignatureLastUpdated). If a third-party DoD-approved product is deployed, Defender may run in passive mode.

**Operational impact:** Real-time scanning adds I/O overhead. Define vetted exclusions for databases and build directories only with ISSO approval and document them.

**Cyber security professional:** Signature and behavioral anti-malware, together with reputation services such as SmartScreen, address commodity and opportunistic threats at the endpoint (SI-3 malicious code protection, SI-3(2) automatic updates). DoD typically requires an approved enterprise endpoint-security suite. The STIG check confirms that a capable product is installed, running and updating, and that users can't bypass warnings.

**ATT&CK:** T1562.001 Impair Defenses: Disable or Modify Tools; T1204 User Execution; T1566 Phishing

### System Services & Daemons

*Enables required security services and disables risky ones.* (19 rules across all STIGs as the primary topic.)

**General audience:** Computers run many background programs ("services") all the time. This rule makes sure the important security ones are always running and the unneeded or risky ones are switched off, like keeping the alarm system armed while unplugging the appliances you don't use.

**System administrator (RHEL):** On RHEL, use 'systemctl enable --now <unit>' for required services and 'systemctl disable --now <unit>' plus 'systemctl mask <unit>' for prohibited ones. Masking prevents a service from being started manually or as a dependency. Check with 'systemctl is-enabled <unit>' and 'systemctl is-active <unit>', and remember the matching .socket units.

**System administrator (Ubuntu):** On Ubuntu, use 'systemctl enable --now <unit>' for required services and 'systemctl disable --now <unit>' plus 'systemctl mask <unit>' for prohibited ones. Masking prevents a service from being started manually or as a dependency. Check with 'systemctl is-enabled <unit>' and 'systemctl is-active <unit>', and remember the matching .socket units.

**System administrator (Windows):** On Windows, set the service startup type through Group Policy (System Services) or 'Set-Service -StartupType Disabled'. Check with 'Get-Service <name> | Select Status, StartType'.

**Operational impact:** Before masking a service, confirm nothing depends on it ('systemctl list-dependencies --reverse <unit>').

**Cyber security professional:** Security functions such as auditd, firewalld, sshd's hardened configuration, fapolicyd and USBGuard only protect the system while their services are running. Conversely, every listening or socket-activated service is reachable attack surface. CM-7 (least functionality) and AU/SI controls require the security services to be enabled and the non-essential ones disabled or masked so they can't be started indirectly.

**ATT&CK:** T1543 Create or Modify System Process; T1210 Exploitation of Remote Services

### PowerShell & Scripting Security

*Enables PowerShell logging and restricts script hosts.* (18 rules across all STIGs as the primary topic.)

**General audience:** PowerShell is a powerful tool for automating tasks on Windows, which also makes it a favorite of hackers. This rule makes the computer keep a detailed record of every PowerShell command that runs, like a CCTV camera pointed at the most powerful tool in the workshop.

**System administrator (RHEL):** Not applicable to Linux, where shell history and auditd execve rules serve a similar purpose.

**System administrator (Ubuntu):** Not applicable to Linux, where shell history and auditd execve rules serve a similar purpose.

**System administrator (Windows):** On Windows, configure these under Administrative Templates >> Windows Components >> Windows PowerShell: 'Turn on PowerShell Script Block Logging' (HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging EnableScriptBlockLogging = 1) and 'Turn on PowerShell Transcription'. Logs go to Microsoft-Windows-PowerShell/Operational. Write transcripts to a protected, centrally collected location.

**Operational impact:** Script-block logs can be large and may capture secrets embedded in scripts. Size the PowerShell Operational log appropriately and restrict who can read it.

**Cyber security professional:** PowerShell is the dominant 'living off the land' tool in Windows intrusions. Script Block Logging (event 4104) records de-obfuscated code as it executes, and Transcription records full session input and output. Together they provide high-fidelity detection content for AU-2/AU-12 and SI-4. Removing PowerShell 2.0 prevents downgrade attacks that bypass these logs and AMSI.

**ATT&CK:** T1059.001 Command and Scripting Interpreter: PowerShell; T1059.005 Command and Scripting Interpreter: Visual Basic; T1562.003 Impair Defenses: Impair Command History Logging

### Data-at-Rest Encryption

*Encrypts disks so data is unreadable if the device is lost or stolen.* (15 rules across all STIGs as the primary topic.)

**General audience:** This scrambles everything stored on the computer's drive so it can only be read after the right key or PIN is entered at startup. If someone steals the laptop or pulls out the hard drive, all they get is gibberish. It's like keeping your documents in a locked safe instead of a cardboard box.

**System administrator (RHEL):** RHEL uses LUKS (dm-crypt) for block-device encryption, normally set up at install time. Retrofitting encryption to an existing root volume generally requires a rebuild or offline re-encryption ('cryptsetup reencrypt'). Verify with 'lsblk -f' or 'cryptsetup status'.

**System administrator (Ubuntu):** Ubuntu uses LUKS (dm-crypt) for block-device encryption, normally chosen at install time ('Encrypt the new Ubuntu installation'). Retrofitting encryption to an existing root volume generally requires a rebuild. Verify with 'lsblk -f' or 'cryptsetup status <mapping>'.

**System administrator (Windows):** Windows uses BitLocker, controlled by Group Policy under Administrative Templates >> Windows Components >> BitLocker Drive Encryption (registry HKLM\SOFTWARE\Policies\Microsoft\FVE). Verify with 'manage-bde -status'. Escrow recovery keys to AD DS or Entra ID before enforcing PIN requirements.

**Operational impact:** Requiring a pre-boot PIN means unattended reboots (patch windows, remote power-cycles) stop at the PIN prompt unless Network Unlock is deployed. Plan key escrow and helpdesk recovery procedures before rollout.

**Cyber security professional:** Full-volume encryption protects confidentiality when an adversary gains physical possession of storage, an attack path that bypasses every OS-level access control. Pre-boot authentication (TPM + PIN) defends against cold-boot, DMA and TPM-sniffing attacks that defeat TPM-only configurations. Maps primarily to SC-28 (Protection of Information at Rest). Assess key escrow and recovery procedures as well, because an unrecoverable key is an availability risk.

**ATT&CK:** T1005 Data from Local System; T1200 Hardware Additions; T1552 Unsecured Credentials

### Unneeded Kernel Modules & Protocols

*Prevents loading of rarely-used kernel modules and network protocols.* (15 rules across all STIGs as the primary topic.)

**General audience:** The core of the operating system can load optional add-ons on demand, including some that are rarely used and not well tested. This rule simply removes the ability to load add-ons you'll never need, like boarding up doors in a building that nobody uses, so there are fewer ways in.

**System administrator (RHEL):** Create /etc/modprobe.d/<name>.conf containing 'install <module> /bin/false' (prevents loading) and 'blacklist <module>' (prevents auto-loading by alias). Check with 'modprobe -n -v <module>' and 'lsmod | grep <module>'. Unload any currently loaded module with 'modprobe -r'.

**System administrator (Ubuntu):** Create /etc/modprobe.d/<name>.conf containing 'install <module> /bin/false' (prevents loading) and 'blacklist <module>' (prevents auto-loading by alias). Check with 'modprobe -n -v <module>' and 'lsmod | grep <module>'. Unload any currently loaded module with 'modprobe -r'.

**System administrator (Windows):** Windows equivalent: disable unused drivers and services, and use WDAC/HVCI driver blocklists.

**Operational impact:** Confirm that no workload needs the module (for example, SCTP is used by some telecom applications and CAN by vehicle and industrial interfaces) before blocking it.

**Cyber security professional:** Linux auto-loads kernel modules on demand. An unprivileged user opening an SCTP, TIPC, CAN or ATM socket, or mounting an unusual file system, can load rarely audited kernel code that has a history of exploitable bugs. Blocking modules that aren't needed shrinks the kernel attack surface available for local privilege escalation (CM-7 least functionality).

**ATT&CK:** T1068 Exploitation for Privilege Escalation; T1547.006 Boot or Logon Autostart Execution: Kernel Modules and Extensions

### Mandatory Access & Application Control

*Enforces SELinux, fapolicyd, AppLocker or WDAC allowlisting.* (9 rules across all STIGs as the primary topic.)

**General audience:** Instead of trying to spot every bad program, the computer keeps a list of approved programs and only those are allowed to run, while each program is kept to its own lane. It's like a guest list at an event: if you're not on the list, you don't get in, no matter how convincing you look.

**System administrator (RHEL):** On RHEL, set SELinux in /etc/selinux/config ('SELINUX=enforcing', 'SELINUXTYPE=targeted') and verify with 'getenforce' and 'sestatus'. Fix labels with 'restorecon -Rv' and troubleshoot denials with 'ausearch -m AVC' or 'sealert'. fapolicyd ('systemctl enable --now fapolicyd') uses rules in /etc/fapolicyd/rules.d/ and the trust database. Start with 'permissive = 1' to gather data, then enforce.

**System administrator (Ubuntu):** Ubuntu uses AppArmor rather than SELinux. Make sure the apparmor package is installed and enabled ('systemctl enable --now apparmor'), and check loaded profiles and their modes with 'aa-status'. Put profiles into enforce mode with 'aa-enforce /etc/apparmor.d/<profile>'. Application allowlisting beyond AppArmor needs an approved third-party tool.

**System administrator (Windows):** On Windows, AppLocker policies are under Security Settings >> Application Control Policies, which requires the Application Identity service. WDAC policies are deployed through Intune, ConfigMgr or GPO. Run in audit mode first and review the event logs.

**Operational impact:** Turning on enforcement without a learning period will block legitimate software. Use permissive or audit mode, analyze the logs, build rules, then enforce. Never disable SELinux to 'fix' an application. Fix the label or policy instead.

**Cyber security professional:** Discretionary permissions can't stop a compromised process from doing whatever its user can do. Mandatory access control such as SELinux confines each service to its policy, which contains exploitation of daemons. Application allowlisting (fapolicyd, AppLocker, WDAC) implements CM-7(5) (authorized software, deny-by-default) and AC-3(3) (mandatory access control), defeating most commodity malware and unauthorized tools. These are among the highest-value preventive controls in the baseline.

**ATT&CK:** T1204.002 User Execution: Malicious File; T1059 Command and Scripting Interpreter; T1068 Exploitation for Privilege Escalation

### Secure Configuration Baseline

*A general secure-configuration requirement of the baseline.* (9 rules across all STIGs as the primary topic.)

**General audience:** This is one of the many "house rules" that together make the computer harder to break into. On its own it might close only a small gap, but hundreds of small gaps closed together make a big difference, like checking every window in the house is shut, not just the front door.

**System administrator (RHEL):** Apply the change as described in the fix text, then confirm it with the check procedure. Where a setting can be set in several places (a main config file and drop-ins), check that no later file overrides it. Automate with the DISA/SCAP content or Ansible (RHEL System Roles / the DISA-provided Ansible and OpenSCAP 'stig' profile) to prevent drift.

**System administrator (Ubuntu):** Apply the change as described in the fix text, then confirm it with the check procedure. Where a setting can be set in several places (a main config file and drop-ins), check that no later file overrides it. Automate with the DISA SCAP content or Ubuntu Security Guide ('usg fix disa_stig', available with Ubuntu Pro) to prevent drift.

**System administrator (Windows):** Apply the change through Group Policy where possible (the DISA STIG GPO package provides importable GPOs) rather than editing the registry by hand, so it is enforced and auditable. Confirm with the check procedure and 'gpresult /h'.

**Operational impact:** Test in a non-production environment first and record any functional impact. If the setting can't be applied, document the deviation and its mitigation with the ISSO.

**Cyber security professional:** This requirement is part of the secure configuration baseline (CM-6 configuration settings, with CM-7 least functionality where applicable). Individually it may close a narrow weakness. Collectively, baseline settings remove the default-insecure states that attackers rely on, and deviations must be documented and risk-accepted in the system's POA&M or as an approved exception.

### Backup & Recovery

*Supports recoverability of system and security-relevant data.* (4 rules across all STIGs as the primary topic.)

**General audience:** This helps make sure important data and settings can be restored if something goes wrong, whether that's a hardware failure, a mistake or a ransomware attack. It's like keeping a spare house key and copies of important documents somewhere safe.

**System administrator (RHEL):** On RHEL, verify the enterprise backup agent and schedules, and protect backup media and repositories with restrictive permissions and encryption.

**System administrator (Ubuntu):** On Ubuntu, verify the enterprise backup agent and schedules, and protect backup media and repositories with restrictive permissions and encryption.

**System administrator (Windows):** On Windows, review the backup tooling and the 'Back up files and directories' and 'Restore files and directories' user rights (Administrators only). Protect the directory services restore mode (DSRM) password on DCs and the system state backups.

**Operational impact:** Restricting backup privileges may require dedicated, monitored service accounts for the backup product.

**Cyber security professional:** Backups are the last line of defense against ransomware and destructive attacks (CP-9 system backup, CP-10 recovery). Backup data and credentials must be protected at the same level as production (CP-9(8) cryptographic protection) and tested for restorability. Restricting who can back up and restore files matters because SeBackupPrivilege bypasses file ACLs.

**ATT&CK:** T1490 Inhibit System Recovery; T1486 Data Encrypted for Impact

## Severity categories

- **High priority (CAT I)**: CAT I: any vulnerability whose exploitation will directly and immediately result in loss of confidentiality, availability or integrity. *In plain terms:* If this setting is wrong, an attacker could directly and immediately gain access, take control, or cause serious damage. These are fixed first.
- **Medium priority (CAT II)**: CAT II: any vulnerability whose exploitation has a potential to result in loss of confidentiality, availability or integrity. *In plain terms:* If this setting is wrong, it could help an attacker gain access, cause damage, or hide what they did. Most rules fall into this category.
- **Low priority (CAT III)**: CAT III: any vulnerability whose existence degrades measures to protect against loss of confidentiality, availability or integrity. *In plain terms:* This setting adds an extra layer of protection. A gap here on its own is less likely to cause harm, but it weakens the overall defenses.

## Using the STIG Explorer application

- **Local:** open `STIG_Explorer/web/index.html` in a browser. No install or network is needed.
- **Container:** `docker compose up -d` (or `podman compose up -d`) in `STIG_Explorer/`, then browse to http://localhost:8080. The container also serves a JSON search API at `/api/search?q=...`.
- **Refreshing content:** `python -m stig_explorer.build --fetch --docs` downloads the newest DISA releases and regenerates the data and these documents.
