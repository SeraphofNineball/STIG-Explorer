"""Security topic knowledge base used to explain STIG rules at three levels.

Each rule is matched (by its title, then its fix/check text) to one or two
topics. A topic supplies the reusable explanation for that *class* of
control; the rule itself supplies the specific setting, DISA rationale,
CCI/NIST mapping and check/fix procedures.

Levels:
    pro      Cyber Security Professional - threat model, ATT&CK, assessment notes
    admin    System Administrator        - mechanism, where it lives, operational impact
    generic  General audience            - plain language with an everyday analogy

`admin` and `impact` may be a str or a {"linux": str, "windows": str} dict.
`match` is tried against the rule title; `fallback` against fix+check text.
Order matters: the first matching topic becomes the primary topic.
"""

from __future__ import annotations

import re

TOPICS: list[dict] = [
    # ------------------------------------------------------------------
    {
        "id": "banner",
        "name": "Logon Banner & Consent Notice",
        "short": "Displays the DoD notice-and-consent banner before access.",
        "match": r"notice and consent|banner|Standard Mandatory (DoD|DoW)|legal notice|logon message|message (title|text) for users",
        "attack": [],
        "pro": "A notice-and-consent banner is a legal and deterrence control rather than a technical barrier. It establishes that users have no expectation of privacy, which supports monitoring, incident response and prosecution, and it satisfies AC-8 (System Use Notification). Assessors verify the exact approved DoD text, that it appears for every access path (console, GUI, SSH and other remote sessions), and that the user must acknowledge it before the session continues.",
        "admin": {
            "linux": "On RHEL the banner is typically set in /etc/issue (console and SSH pre-auth via the sshd 'Banner' directive) and in the GNOME login screen via dconf ('banner-message-enable' and 'banner-message-text'). The text must match the DoD standard banner exactly, including line breaks where the check text calls for them.",
            "windows": "On Windows the banner is configured through Security Options: 'Interactive logon: Message title for users attempting to log on' and 'Interactive logon: Message text for users attempting to log on' (registry LegalNoticeCaption / LegalNoticeText under HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).",
        },
        "impact": "No functional impact. Automated logons and kiosk workflows will need to acknowledge the banner, and some scanners compare the text byte-for-byte, so copy it from the STIG rather than retyping it.",
        "generic": "Before anyone can sign in, the computer shows a warning message saying the system belongs to the government, that activity is monitored, and that using it means you agree to that. Think of it like the \"this area is under video surveillance\" sign at the entrance to a building: it doesn't lock the door, but it makes the rules clear and discourages misuse.",
    },
    {
        "id": "disk_encryption",
        "name": "Data-at-Rest Encryption",
        "short": "Encrypts disks so data is unreadable if the device is lost or stolen.",
        "match": r"BitLocker|data at rest|encrypt\w* .*(drive|disk|partition|volume|storage)|LUKS|full[- ]disk|pre-boot authentication|confidentiality and integrity of information at rest",
        "attack": [("T1005", "Data from Local System"), ("T1200", "Hardware Additions"), ("T1552", "Unsecured Credentials")],
        "pro": "Full-volume encryption protects confidentiality when an adversary gains physical possession of storage, an attack path that bypasses every OS-level access control. Pre-boot authentication (TPM + PIN) defends against cold-boot, DMA and TPM-sniffing attacks that defeat TPM-only configurations. Maps primarily to SC-28 (Protection of Information at Rest). Assess key escrow and recovery procedures as well, because an unrecoverable key is an availability risk.",
        "admin": {
            "linux": "RHEL uses LUKS (dm-crypt) for block-device encryption, normally set up at install time. Retrofitting encryption to an existing root volume generally requires a rebuild or offline re-encryption ('cryptsetup reencrypt'). Verify with 'lsblk -f' or 'cryptsetup status'.",
            "windows": "Windows uses BitLocker, controlled by Group Policy under Administrative Templates >> Windows Components >> BitLocker Drive Encryption (registry HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE). Verify with 'manage-bde -status'. Escrow recovery keys to AD DS or Entra ID before enforcing PIN requirements.",
        },
        "impact": "Requiring a pre-boot PIN means unattended reboots (patch windows, remote power-cycles) stop at the PIN prompt unless Network Unlock is deployed. Plan key escrow and helpdesk recovery procedures before rollout.",
        "generic": "This scrambles everything stored on the computer's drive so it can only be read after the right key or PIN is entered at startup. If someone steals the laptop or pulls out the hard drive, all they get is gibberish. It's like keeping your documents in a locked safe instead of a cardboard box.",
    },
    {
        "id": "smartcard_pki",
        "name": "Smart Card / PKI & Multifactor Authentication",
        "short": "Requires certificate-based (CAC/PIV) or multifactor authentication.",
        "match": r"smart ?card|multifactor|multi-factor|\bPKI\b|certificat|\bCAC\b|\bPIV\b|Root CA|trust anchor|pam_pkcs11|\bOCSP\b|\bCRL\b|certification path|\btoken|External Certification Authority|\bECA\b|opensc|pcsc|ccid",
        "attack": [("T1078", "Valid Accounts"), ("T1110", "Brute Force"), ("T1556", "Modify Authentication Process")],
        "pro": "Certificate-based multifactor authentication removes reusable shared secrets from the authentication path, which neutralizes password spraying, credential stuffing and most phishing. The trust store controls which CAs can issue identities the system accepts, so installing only DoD-approved roots (and removing untrusted or cross-certified ones) is an integrity control on authentication itself. Relevant controls: IA-2(1)/(2)/(12), IA-5(2) (PKI-based authentication: path validation and revocation checking), SC-17.",
        "admin": {
            "linux": "On RHEL, smart card login is handled by SSSD with 'pam_cert_auth = True', the certificate trust store configured in sssd.conf / /etc/sssd/pki/sssd_auth_ca_db.pem, and certificate mapping rules (matchrule/maprule). Revocation checking is configured with 'certificate_verification' (OCSP). authselect features such as 'with-smartcard' wire SSSD into PAM.",
            "windows": "On Windows the relevant settings are the Trusted Root / Intermediate certificate stores (deployed with the DoD InstallRoot tool or GPO) and 'Untrusted Certificates' for the cross-certificates DISA requires removing. Smart card enforcement is set per account or through 'Interactive logon: Require Windows Hello for Business or smart card'. Verify with certlm.msc or 'Get-ChildItem Cert:\\LocalMachine\\Root'.",
        },
        "impact": "Mis-mapped certificates or stale CA bundles lock users out. Stage CA updates before old certificates expire, test revocation checking (OCSP/CRL reachability) on isolated networks, and keep a documented break-glass account.",
        "generic": "Instead of (or in addition to) a password, you prove who you are with something you physically carry, such as a government ID card (CAC) with a chip in it, plus a PIN. Someone who learns your PIN still can't get in without the card. It's like a bank requiring both your debit card and your PIN at the ATM.",
    },
    {
        "id": "fips_crypto",
        "name": "Approved Cryptography (FIPS 140)",
        "short": "Restricts encryption, hashing and key exchange to approved, strong algorithms.",
        "match": r"\bFIPS\b|crypto(graphic)?[- ]polic|cipher|message authentication code|\bMACs?\b|key exchange|\bTLS\b|\bSSL\b|(DoD|DoW)-approved (encryption|cryptograph)|approved cryptograph|encryption algorithm|hashing algorithm|strong (encryption|crypto)|\bRNG\b|random number|entropy|128-bit encryption",
        "attack": [("T1040", "Network Sniffing"), ("T1557", "Adversary-in-the-Middle"), ("T1600", "Weaken Encryption")],
        "pro": "Federal systems must use FIPS 140-validated cryptographic modules (SC-13). Weak or legacy algorithms (MD5, SHA-1 MACs, CBC-mode ciphers, RC4, DES/3DES, small DH groups) enable downgrade, decryption or forgery attacks against data in transit (SC-8, SC-8(1)). The control is only as strong as its weakest negotiated option, so assessors look at the full allowed list, not just the preferred algorithm. Note that FIPS mode validates the module, not the protocol configuration, so both must be checked.",
        "admin": {
            "linux": "RHEL centralizes crypto settings in system-wide crypto policies: 'fips-mode-setup --enable' (RHEL 8) or 'fips=1' on the kernel command line at install time (RHEL 9/10), then 'update-crypto-policies --set FIPS'. Back-end files under /etc/crypto-policies/back-ends/ (openssh, opensslcnf, bind, gnutls and others) are generated from the policy, and individual services such as sshd must be pointed at them rather than hard-coding algorithms. Verify with 'fips-mode-setup --check' and 'update-crypto-policies --show'.",
            "windows": "On Windows, 'System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing' (HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy\\Enabled) restricts Schannel and CNG to FIPS-approved algorithms. Related settings cover Kerberos encryption types and NTLM session security.",
        },
        "impact": {
            "linux": "Enabling FIPS mode can break applications that use non-approved algorithms (MD5 for non-security checksums, older Java code, legacy VPN or SSH clients). Enable it at install time where possible, because switching an existing RHEL 9/10 system into FIPS mode is not supported for production. Test interoperating systems before rollout.",
            "ubuntu": "Enabling FIPS mode can break applications that use non-approved algorithms (MD5 for non-security checksums, older Java code, legacy VPN or SSH clients). FIPS packages require an Ubuntu Pro subscription and a reboot into the FIPS kernel, and the FIPS kernel may lag behind the general kernel's hardware enablement. Test interoperating systems before rollout.",
            "windows": "Enabling FIPS mode can break applications that use non-approved algorithms (MD5 for non-security checksums, older .NET code, legacy VPN or RDP clients). Test interoperating systems and line-of-business applications before rollout.",
        },
        "generic": "Encryption is how computers scramble information so eavesdroppers can't read it. Some older scrambling methods have been \"cracked\" and are no longer safe. This rule makes the computer use only methods the U.S. government has tested and approved, like requiring modern, certified locks instead of old ones that a locksmith can easily pick.",
    },
    {
        "id": "ssh",
        "name": "SSH Remote Administration",
        "short": "Hardens the SSH service used for remote command-line access.",
        "match": r"\bSSH\b|sshd|OpenSSH|\.shosts|\.rhosts|shosts\.equiv|hosts\.equiv",
        "attack": [("T1021.004", "Remote Services: SSH"), ("T1110", "Brute Force"), ("T1098.004", "Account Manipulation: SSH Authorized Keys")],
        "pro": "SSH is the primary remote administration channel on Linux and therefore a high-value target. Hardening reduces the attack surface: no root or empty-password logins, no host-based trust (rhosts) or user environment injection, strict file-mode checks, idle-session termination, and approved cryptography only. These settings support AC-17 (Remote Access), AC-12, IA-2 and SC-8. Also check authorized_keys sprawl and key lifecycle, which no STIG setting fully covers.",
        "admin": {
            "linux": "sshd reads /etc/ssh/sshd_config, and on RHEL 9/10 also drop-ins under /etc/ssh/sshd_config.d/ that are processed in lexical order, where the first value obtained wins. Put STIG settings in an early-sorting drop-in (e.g. 00-stig.conf) so a vendor file can't silently override them. Validate syntax with 'sshd -t', check the effective configuration with 'sshd -T | grep -i <keyword>', then 'systemctl reload sshd'.",
            "windows": "For OpenSSH on Windows, configuration lives in %ProgramData%\\ssh\\sshd_config. Restart the 'sshd' service after changes.",
        },
        "impact": "Keep an existing session open while you reload sshd so a typo can't lock you out. Disabling root login requires named admin accounts plus sudo. Idle timeouts (ClientAliveInterval/CountMax) will disconnect long-running interactive sessions, so use tmux or screen for those.",
        "generic": "SSH is the secure \"remote control\" administrators use to manage the computer over the network by typing commands. This rule tightens how that remote control works: who may use it, how they prove their identity, and how idle connections are closed. It's like making sure the building's service entrance has a good lock and isn't propped open.",
    },
    {
        "id": "account_lockout",
        "name": "Account Lockout",
        "short": "Locks accounts after repeated failed logon attempts.",
        "match": r"lockout|lock(ed)? out|faillock|unsuccessful (logon|login|log on) attempts|consecutive (invalid|failed|unsuccessful)|bad logon|invalid logon attempts|account lockout",
        "attack": [("T1110.001", "Brute Force: Password Guessing"), ("T1110.003", "Brute Force: Password Spraying")],
        "pro": "Lockout thresholds turn online password guessing from an unlimited search into a handful of attempts per window (AC-7). The trade-off is denial of service: an attacker who knows usernames can deliberately lock out accounts, which is why DoD pairs a low threshold (3) with an administrator-unlock or timed-unlock requirement. Lockout does nothing against offline cracking of stolen hashes or against password spraying that stays below the threshold, so it complements, rather than replaces, password strength and MFA.",
        "admin": {
            "linux": "RHEL 8.2+ uses pam_faillock configured in /etc/security/faillock.conf (deny, fail_interval, unlock_time, even_deny_root, dir, audit, silent) and wired into system-auth and password-auth by authselect ('authselect enable-feature with-faillock'). Inspect with 'faillock --user <name>' and reset with 'faillock --user <name> --reset'. Pointing 'dir' at a persistent path such as /var/log/faillock keeps lockouts across reboots.",
            "windows": "Windows configures this under Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy (threshold, duration, reset counter). For domain accounts it is set in the Default Domain Policy or a Fine-Grained Password Policy, and local policy affects only local accounts.",
        },
        "impact": "Service accounts with stale cached credentials (mapped drives, scheduled tasks, mobile mail clients) can trigger repeated lockouts. Identify the lockout source (Windows Event ID 4740; faillock and audit logs on Linux) before loosening the threshold.",
        "generic": "If someone types the wrong password a few times in a row, the account is temporarily locked so they can't keep guessing. It's like a phone that freezes after several wrong passcodes, which stops a thief from trying every possible combination.",
    },
    {
        "id": "password_complexity",
        "name": "Password Strength & Complexity",
        "short": "Sets minimum length and character-mix rules for passwords.",
        "match": r"password.*(complex|character|length|upper-?case|lower-?case|numeric|special|dictionary|different|repeating|consecutive|classes)|minlen|pwquality|minclass|maxrepeat|maxclassrepeat|difok|dictcheck|password filter|password-complexity|PIN length|PIN complexity",
        "attack": [("T1110.002", "Brute Force: Password Cracking"), ("T1110.001", "Brute Force: Password Guessing")],
        "pro": "Length and composition rules raise the cost of both online guessing and offline cracking of captured hashes (IA-5(1)). DoD still requires a 15-character minimum with character-class rules, while NIST SP 800-63B now favors length plus breached-password screening over composition rules. Where the two conflict, the STIG governs for DoD systems. Note that complexity rules apply only when a password is changed, so assess the age of existing passwords too.",
        "admin": {
            "linux": "RHEL enforces this through pam_pwquality, configured in /etc/security/pwquality.conf or a drop-in under /etc/security/pwquality.conf.d/ (minlen, dcredit/ucredit/lcredit/ocredit as negative numbers meaning 'at least N', minclass, maxrepeat, maxclassrepeat, difok, dictcheck). The pam_pwquality module must appear in the password stack of system-auth and password-auth. Test with 'pwscore' or by changing a test user's password.",
            "windows": "Windows sets this in Account Policies >> Password Policy ('Minimum password length', 'Password must meet complexity requirements'). Domain-wide values come from the Default Domain Policy or Fine-Grained Password Policies (PSOs). Lengths above 14 require the 'Relax minimum password length limits' setting on newer builds.",
        },
        "impact": "Takes effect at each user's next password change. Communicate the new requirements beforehand, and check that provisioning scripts and self-service reset portals can generate compliant passwords.",
        "generic": "This sets the rules for how strong a password must be: long enough, and mixing capitals, lowercase letters, numbers and symbols. Short or simple passwords can be guessed by computers in seconds. A long, varied password is like a key with many unique notches that's much harder to copy.",
    },
    {
        "id": "password_lifecycle",
        "name": "Password Age, History & Reuse",
        "short": "Controls how often passwords change and prevents reusing old ones.",
        "match": r"password.*(lifetime|age|\bdays?\b|history|reuse|remembered|generations|expir|change.*(once|per)|minimum.*(time|period))|PASS_MAX_DAYS|PASS_MIN_DAYS|maximum password|minimum password age",
        "attack": [("T1078", "Valid Accounts"), ("T1110.004", "Brute Force: Credential Stuffing")],
        "pro": "Maximum age bounds the useful lifetime of a compromised credential. Minimum age plus history prevent users from cycling straight back to a known password, which would defeat the history check (IA-5(1)(d)/(e)). The trend in current guidance is to prefer event-driven rotation (on suspected compromise) over periodic rotation, but the DoD baseline values remain enforceable requirements.",
        "admin": {
            "linux": "On RHEL, defaults for new accounts come from /etc/login.defs (PASS_MAX_DAYS, PASS_MIN_DAYS), while existing accounts must be updated individually with 'chage -M/-m <days> <user>' (review with 'chage -l <user>'). History is enforced by pam_pwhistory ('remember = 5' in /etc/security/pwhistory.conf or on the module line).",
            "windows": "Windows sets this in Account Policies >> Password Policy: 'Maximum password age', 'Minimum password age', 'Enforce password history'. Domain values come from the Default Domain Policy or PSOs.",
        },
        "impact": "Changing login.defs does not retroactively update existing accounts, so remember to run chage for current users. Exclude non-interactive service accounts from expiry only through a documented exception (or use gMSAs on Windows).",
        "generic": "This makes people change passwords every so often and stops them from simply switching back to a password they used recently. If a password was quietly stolen, it eventually stops working, a bit like changing the locks periodically in case someone copied a key.",
    },
    {
        "id": "credential_storage",
        "name": "Credential Storage & Password Hashing",
        "short": "Ensures passwords are stored only as strong one-way hashes.",
        "match": r"encrypted representation|password hash|hash(es|ing)? .*password|password.*(hash|stored|reversible|SHA512|SHA-512|rounds)|LAN Manager hash|\bLM hash|reversible encryption|cach(e|ed|ing) (of )?(logon|credential|domain)|ENCRYPT_METHOD|crypt_style|SHA_CRYPT|Credential Manager|store.*(passwords|credentials)|plain ?text password|clear ?text password",
        "attack": [("T1003", "OS Credential Dumping"), ("T1110.002", "Brute Force: Password Cracking"), ("T1552", "Unsecured Credentials")],
        "pro": "When a host is compromised, stored credential material is the attacker's path to lateral movement. Weak or reversible storage (LM hashes, reversible encryption, low-iteration hashes, excessive cached domain logons) turns a single compromise into credential recovery for many accounts. IA-5(1)(c) requires that only cryptographically protected passwords be stored and transmitted. Strong salted, iterated hashing such as SHA-512 crypt with sufficient rounds increases offline cracking cost.",
        "admin": {
            "linux": "On RHEL, hashes are stored in /etc/shadow. The algorithm for new passwords comes from ENCRYPT_METHOD (and SHA_CRYPT_MIN_ROUNDS) in /etc/login.defs, 'crypt_style' in /etc/libuser.conf, and the pam_unix module options. Existing hashes are upgraded only when users change their passwords. Check the hash prefix in /etc/shadow ($6$ = SHA-512).",
            "windows": "Relevant Windows settings include 'Network security: Do not store LAN Manager hash value on next password change' (NoLMHash), 'Store passwords using reversible encryption' (Disabled), and 'Interactive logon: Number of previous logons to cache' (CachedLogonsCount).",
        },
        "impact": "Reducing cached logons can prevent laptop users from signing in when they are off the network. Disabling LM hashes affects only very old clients (pre-Windows 2000 era).",
        "generic": "Computers shouldn't store your actual password. Instead they store a scrambled \"fingerprint\" of it that can't be turned back into the password. This rule makes sure that fingerprint is created with a strong method, so that even if someone steals the file, they can't easily work out everyone's passwords.",
    },
    {
        "id": "privileged_accounts",
        "name": "Built-in & Privileged Account Hardening",
        "short": "Restricts root/Administrator/Guest accounts and empty passwords.",
        "match": r"root (login|logon|account|access)|log(in|on) (directly )?as root|\bdirect(ly)? .*root|built-in (administrator|guest)|administrator account|guest account|rename|PermitRootLogin|blank password|empty password|null password|nullok|no password|accounts? .*(UID|user ID) (of )?0|UID 0|local administrator account|LAPS|administrator password|separate accounts",
        "attack": [("T1078.001", "Valid Accounts: Default Accounts"), ("T1078.003", "Valid Accounts: Local Accounts"), ("T1110", "Brute Force")],
        "pro": "Well-known accounts (root, Administrator, Guest) are guaranteed to exist with predictable names, which makes them ideal targets. Blocking direct logon forces attribution through named accounts (IA-2, AC-6(2)). Removing empty-password acceptance eliminates trivial access, and unique local admin passwords (LAPS) break pass-the-hash lateral movement across a fleet. Assess the effective result across every access path: console, SSH, RDP and network logon.",
        "admin": {
            "linux": "On RHEL, root logon is controlled through sshd ('PermitRootLogin no'), /etc/securetty (where present), and PAM. Empty passwords are blocked by removing 'nullok' from pam_unix in system-auth and password-auth and by setting 'PermitEmptyPasswords no' for sshd. Only root should have UID 0 ('awk -F: \"$3==0\" /etc/passwd').",
            "windows": "On Windows these are Security Options ('Accounts: Rename administrator account', 'Accounts: Guest account status', 'Accounts: Limit local account use of blank passwords to console logon only') plus LAPS for unique, rotated local administrator passwords.",
        },
        "impact": "Make sure at least one named administrator account with sudo or admin rights works before disabling root or Administrator logon paths. Renaming the built-in Administrator can break scripts that reference it by name.",
        "generic": "Every computer comes with a few built-in \"master\" accounts whose names everyone knows. This rule makes those accounts harder to abuse, for example by not letting anyone log in directly as the master account and never allowing accounts with no password. It's like not leaving the master key labelled \"MASTER KEY\" hanging by the front door.",
    },
    {
        "id": "account_management",
        "name": "Account Lifecycle Management",
        "short": "Disables inactive, temporary and unauthorized accounts.",
        "match": r"(account|identifier)s?\b.*(inactiv|35 days|disabled? after|expire|temporary|emergency|unique|shared|unnecessary|unauthorized|must be (removed|disabled))|inactive (account|user)|unique (user|account|identif)|duplicate (UID|user|group)|\bUIDs?\b|\bGIDs?\b|interactive users? .*(home|valid)|home director|local (user )?accounts?|group accounts?|shared accounts?|password.*not.*expire|user (and|or) group (account )?administration",
        "attack": [("T1078", "Valid Accounts"), ("T1136", "Create Account"), ("T1098", "Account Manipulation")],
        "pro": "Dormant, orphaned and shared accounts are prime persistence and initial-access vectors because nobody notices their use. AC-2 (Account Management) and its enhancements (AC-2(2) temporary/emergency account removal, AC-2(3) disable inactive accounts) require automated lifecycle enforcement. IA-2 and IA-4 require unique identifiers so actions can be attributed to individuals. Assessors typically sample accounts against an authoritative roster.",
        "admin": {
            "linux": "On RHEL, inactivity is enforced with 'INACTIVE=35' in /etc/default/useradd ('useradd -D -f 35') for new accounts and 'chage -I' for existing ones. Temporary accounts get an expiry date ('chage -E'). Check /etc/passwd and /etc/group for duplicate UIDs and GIDs ('pwck', 'grpck') and that every interactive user has a valid, owned home directory.",
            "windows": "On Windows, use 'Search-ADAccount -AccountInactive -TimeSpan 35' for domain accounts. For local accounts, review 'Get-LocalUser' (LastLogon, PasswordExpires) and disable or delete accounts that aren't needed. Shared accounts require ISSO-documented justification.",
        },
        "impact": "Before you automatically disable inactive accounts, confirm that service, break-glass and seasonal-user accounts are inventoried and either exempted with documentation or monitored.",
        "generic": "Every person should have their own account, and accounts that nobody is using (people who left, temporary contractors, test accounts) should be turned off. Forgotten accounts are like old keys still floating around after someone moves out. You never know who might use them.",
    },
    {
        "id": "ntlm_kerberos",
        "platforms": ("windows",),
        "name": "Windows Authentication Protocols (NTLM, Kerberos, LSA)",
        "short": "Hardens NTLM/Kerberos and protects LSASS credential material.",
        "match": r"\bNTLM|LAN ?Manager authentication|LanMan authentication|Kerberos|WDigest|\bLSA\b|LSASS|Credential Guard|Local Security Authority|credential(s)? delegat|Remote Credential Guard|session security|PKU2U|encryption types|NTLMv2|Restricted Admin|protected users|remote host allows delegation|SAM ",
        "attack": [("T1003.001", "OS Credential Dumping: LSASS Memory"), ("T1550.002", "Use Alternate Authentication Material: Pass the Hash"), ("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay"), ("T1558", "Steal or Forge Kerberos Tickets")],
        "pro": "Windows authentication protocols are central to most domain compromise chains. Legacy LM/NTLMv1 responses can be cracked or relayed. WDigest leaves cleartext passwords in LSASS memory. Weak Kerberos encryption types (RC4/DES) enable Kerberoasting and downgrade attacks. Credential Guard and LSA protection (RunAsPPL) isolate secrets from credential-dumping tools. These settings implement IA-2(8) (replay resistance), IA-5(1)(c), SC-8 and SC-23 (session authenticity). Validate the domain-wide impact with NTLM auditing before enforcing restrictions.",
        "admin": {
            "windows": "Most of these are Security Options under Local Policies, plus MS Security Guide templates (SecGuide.admx shipped with the STIG GPO package). Key settings include 'Network security: LAN Manager authentication level' (LmCompatibilityLevel = 5), 'Network security: Configure encryption types allowed for Kerberos', 'Minimum session security for NTLM SSP', WDigest 'UseLogonCredential' = 0, and Credential Guard via Device Guard >> 'Turn On Virtualization Based Security'. Verify with 'gpresult /h' or the registry paths shown in the check.",
            "linux": "On Linux these relate to Kerberos (krb5.conf) and SSSD settings. Disable weak enctypes and GSSAPI and Kerberos authentication in sshd unless they are required.",
        },
        "impact": "Enforcing NTLMv2-only or AES-only Kerberos can break legacy appliances, older NAS devices, multifunction printers and non-Windows clients. Run NTLM and Kerberos auditing (event IDs 4624/4776/4768/4769) first to inventory dependencies. Credential Guard is incompatible with some VPN clients and with unconstrained delegation.",
        "generic": "When you log into a Windows network, your computer and the server trade secret \"handshakes\" to prove who you are. Older handshakes are easy for attackers to fake or steal. This rule switches off the old, weak handshakes and protects the part of memory where Windows keeps your sign-in secrets, like retiring an old ID badge design that was easy to forge.",
    },
    {
        "id": "smb_anonymous",
        "name": "File Sharing (SMB) & Anonymous Access",
        "short": "Requires SMB signing and blocks anonymous enumeration and access.",
        "match": r"\bSMB|server message block|LanmanServer|LanmanWorkstation|named pipes|anonymous|null session|\bshares?\b|insecure guest|digitally (sign|encrypt)|signing|Everyone permissions|enumerat\w+ (of )?(SAM|shares|accounts)|SID/Name translation|unauthenticated RPC|RPC clients|restrict(ed)? (clients allowed to make )?remote calls to SAM|unencrypted password .* third-party SMB",
        "attack": [("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay"), ("T1135", "Network Share Discovery"), ("T1087", "Account Discovery"), ("T1021.002", "Remote Services: SMB/Windows Admin Shares")],
        "pro": "SMB is the backbone of Windows file and administrative traffic and a principal lateral-movement channel. Unsigned SMB enables NTLM relay attacks. Anonymous (null session) access and SAM/share enumeration give unauthenticated attackers reconnaissance data such as user lists and group memberships. SMBv1 lacks modern protections and was the propagation vector for WannaCry and NotPetya. These settings support AC-3, AC-14 (actions without identification), SC-8 and CM-7.",
        "admin": {
            "windows": "Mostly Security Options: 'Microsoft network client/server: Digitally sign communications (always)' (RequireSecuritySignature), 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' (RestrictAnonymous), 'Let Everyone permissions apply to anonymous users', 'Restrict anonymous access to Named Pipes and Shares', 'Network access: Restrict clients allowed to make remote calls to SAM'. SMBv1 is removed with 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'. Check with 'Get-SmbServerConfiguration'.",
            "linux": "On RHEL, Samba equivalents are 'server signing = mandatory', 'restrict anonymous = 2' and 'server min protocol = SMB2' in smb.conf.",
        },
        "impact": "Mandatory signing adds CPU overhead on high-throughput file servers (usually negligible on modern hardware) and can break very old clients and some NAS devices. Restricting anonymous access can affect legacy apps that rely on null sessions.",
        "generic": "Computers on a network share files with each other using a system called SMB. This rule makes every file-sharing conversation carry a tamper-proof \"seal\" and stops strangers who haven't signed in from browsing the list of users and shared folders. It's like requiring visitors to sign in at the front desk before they can read the staff directory.",
    },
    {
        "id": "user_rights",
        "platforms": ("windows",),
        "name": "Windows User Rights Assignment",
        "short": "Limits which accounts hold powerful Windows privileges.",
        "match": r"user right|right must only be assigned|must only be assigned to|privileges? .*(must only|assigned to)|\"[^\"]+\" (user )?right",
        "attack": [("T1134", "Access Token Manipulation"), ("T1003", "OS Credential Dumping"), ("T1078", "Valid Accounts")],
        "pro": "User rights (privileges) such as SeDebugPrivilege, SeImpersonatePrivilege, SeBackupPrivilege, SeTcbPrivilege and SeLoadDriverPrivilege each give a direct path to SYSTEM-level compromise or credential theft. Logon rights (network, interactive, RDP, batch, service) define which accounts can authenticate through which channel. Enforcing least privilege here implements AC-6 / AC-6(10) and limits blast radius when a lower-privileged account is compromised. Pay particular attention to 'Deny' rights for privileged domain accounts on lower-tier systems, which enforce an administrative tiering model.",
        "admin": {
            "windows": "Configured at Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment. These are not registry values: they are stored in the local security database and applied from GptTmpl.inf in a GPO. Review the effective assignment with 'secedit /export /cfg c:\\temp\\secpol.inf /areas USER_RIGHTS' or the Local Security Policy console. An empty but defined setting means 'no one'.",
            "linux": "On Linux the closest equivalents are sudoers rules, Linux capabilities, and PAM access controls.",
        },
        "impact": "Removing service accounts from rights such as 'Log on as a service' or 'Impersonate a client after authentication' can stop applications (SQL Server, IIS app pools, backup agents). Document required application accounts as approved exceptions before enforcing.",
        "generic": "Windows has a list of special powers, such as \"shut down the computer\", \"look inside other programs' memory\" or \"log in remotely\", and decides which accounts get each one. This rule makes sure only the right people, usually administrators, hold the powerful ones. It's like a hospital where only surgeons are allowed into the operating room.",
    },
    {
        "id": "elevation",
        "name": "Privilege Elevation (UAC / sudo)",
        "short": "Controls how standard users and admins elevate to administrative rights.",
        "match": r"User Account Control|\bUAC\b|elevat|\bsudo|sudoers|\bsu\b|wheel|privilege(d)? (escalat|elevat)|nonprivileged users .*(execut|prevent)|reauthenticat|authenticate .*privilege|run as|Admin Approval Mode|privileged functions|installation options|Windows Installer|always install",
        "attack": [("T1548.002", "Abuse Elevation Control: Bypass UAC"), ("T1548.003", "Abuse Elevation Control: Sudo and Sudo Caching"), ("T1068", "Exploitation for Privilege Escalation")],
        "pro": "Elevation controls make privilege use deliberate, authenticated and auditable (AC-6(1)/(2)/(9)/(10), IA-11 re-authentication). UAC's secure-desktop prompt resists UI spoofing and input injection by malware running in the user's session. sudo restrictions (no NOPASSWD, no '!authenticate', short timestamp_timeout, no blanket ALL grants) prevent silent escalation by any process running as an admin user. Every elevation event should produce an audit record.",
        "admin": {
            "linux": "On RHEL, sudo policy lives in /etc/sudoers and /etc/sudoers.d/ (always edit with 'visudo', validate with 'visudo -c'). STIG items include removing NOPASSWD and !authenticate, setting 'Defaults timestamp_timeout=0', and restricting 'ALL ALL=(ALL) ALL'. 'su' is restricted to the wheel group with pam_wheel in /etc/pam.d/su.",
            "windows": "UAC settings are Security Options named 'User Account Control: ...' (registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System: EnableLUA, ConsentPromptBehaviorAdmin, ConsentPromptBehaviorUser, FilterAdministratorToken, EnableInstallerDetection, EnableSecureUIAPaths, EnableVirtualization).",
        },
        "impact": "Turning off password-less sudo affects automation such as Ansible and cron jobs. Use dedicated automation accounts with tightly scoped command lists and documented exceptions. Disabling UAC (EnableLUA = 0) is not acceptable and also breaks Store/UWP apps.",
        "generic": "Even administrators work day-to-day without full power, and the system asks them to confirm, often by re-entering a password, before doing anything that could change important settings. That way, a harmful program can't quietly use admin power behind their back. It's like a bank requiring a second signature for large withdrawals.",
    },
    {
        "id": "audit_storage",
        "name": "Audit Log Capacity, Offloading & Failure Handling",
        "short": "Ensures audit logs have space, are sent off-host and alert on failure.",
        "match": r"(audit|event|security|application|system) log (file )?size|audit (record )?storage|off-?load|remote (log|logging|server|system)|rsyslog|syslog|log (server|aggregation)|space_left|disk_full|disk_error|audit\w* .*(capacity|is full|processing failure|storage volume)|audit (failure|fails|processing)|audispd|audit .*plugin|overflow|alert .*(audit|SA|ISSO|ISSM)|journald?|one week's worth|week's worth|centralized (log|review)|log (forwarding|transfer)",
        "attack": [("T1070", "Indicator Removal"), ("T1562.006", "Impair Defenses: Indicator Blocking")],
        "pro": "Logs that roll over, fill the disk or exist only on the compromised host can't support incident response. Attackers routinely clear or flood local logs. AU-4 (storage capacity), AU-4(1) (transfer to alternate storage), AU-5 (response to processing failures) and AU-9(2) (backup onto a separate system) require sized local storage, real-time off-host forwarding, and defined behavior (alert, halt or single-user) when audit capability is lost. Validate end-to-end delivery at the SIEM, not just the client configuration.",
        "admin": {
            "linux": "On RHEL, auditd capacity and failure behavior are set in /etc/audit/auditd.conf (space_left, space_left_action, admin_space_left(_action), disk_full_action, disk_error_action, max_log_file(_action), action_mail_acct). Off-loading uses rsyslog (omfwd with TLS via gtls/ossl stream drivers) or the audisp-remote / audit 'remote' plugin. Put /var/log/audit on its own partition so it can't starve the root file system. Restart with 'service auditd restart', because systemctl is blocked for auditd.",
            "windows": "On Windows, event log sizes are set under Administrative Templates >> Windows Components >> Event Log Service >> Application/Security/System >> 'Specify the maximum log file size (KB)'. Forward events with Windows Event Forwarding (WEF) or a SIEM agent. Retention behavior is configured in the same policy node.",
        },
        "impact": "Actions such as 'halt' or 'single' on disk-full prioritize integrity over availability and can take a production system down. Agree the action with the ISSO/AO and monitor free space proactively. Larger local logs consume disk; forwarding requires network connectivity and certificates for TLS.",
        "generic": "The computer keeps a \"security diary\" of important events. This rule makes sure the diary has enough pages, that a copy is sent to a separate, safe location, and that someone is alerted if the diary fills up or stops working. It's like a store's security cameras recording to an off-site server so a thief can't simply take the tape.",
    },
    {
        "id": "audit_protection",
        "name": "Audit Log & Tool Protection",
        "short": "Protects audit logs, configuration and tools from tampering.",
        "match": r"audit (log|tool|information|configuration|rules?)s? .*(owned|permission|mode|protect|unauthorized|immutable)|audit tools|log (files?|directory) .*(owned|group-owned|mode|permission)|event log.*(permission|access)|loginuid-immutable|\bimmutable\b|audit logs? (must|directory)|cryptographic mechanisms to protect the integrity of audit tools",
        "attack": [("T1070.002", "Indicator Removal: Clear Linux or Mac System Logs"), ("T1070.001", "Indicator Removal: Clear Windows Event Logs"), ("T1562.012", "Impair Defenses: Disable or Modify Linux Audit System")],
        "pro": "If a non-privileged user, or an attacker running as one, can read, alter or delete audit data or reconfigure the audit subsystem, the audit trail loses its evidentiary value. AU-9 (protection of audit information) together with AU-9(3) (cryptographic protection) and AU-9(4) (access by subset of privileged users) require restrictive ownership and modes on logs and tools, integrity verification of audit binaries (via AIDE), and immutable audit rules ('-e 2') so the rule set can't be changed without a reboot.",
        "admin": {
            "linux": "On RHEL, audit logs live under /var/log/audit/ (mode 0600 or 0640, owned by root, group per log_group). Audit tools are /sbin/auditctl, aureport, ausearch, autrace, auditd, rsyslogd and augenrules (mode 0755, owned by root). '-e 2' at the end of the rules makes the configuration immutable until reboot, and '--loginuid-immutable' prevents processes from changing their audit login UID.",
            "windows": "On Windows, event log file permissions are on %SystemRoot%\\System32\\winevt\\Logs\\*.evtx. The default ACL (Eventlog service, SYSTEM, Administrators) must not be broadened. The 'Manage auditing and security log' user right must be limited to Administrators.",
        },
        "impact": "With '-e 2', any later audit rule change requires a reboot to take effect, so schedule audit rule updates in maintenance windows.",
        "generic": "The security diary is only useful if nobody can secretly edit or tear pages out of it. This rule locks down who can read or change the logs and the tools that manage them. It's like keeping the security camera footage in a locked room that only a couple of trusted people can enter.",
    },
    {
        "id": "audit_events",
        "name": "Security Event Auditing",
        "short": "Records security-relevant events (logons, privilege use, changes).",
        "match": r"\baudit|generate (an )?audit record|must log|log(s|ging)? (of )?(all )?(successful|unsuccessful|attempts|use|events?)|record (time stamps|events)|account management events|privileged (activities|functions|commands)",
        "attack": [("T1562.002", "Impair Defenses: Disable Windows Event Logging"), ("T1562.012", "Impair Defenses: Disable or Modify Linux Audit System"), ("T1070", "Indicator Removal")],
        "pro": "Event auditing provides the detection and forensic record for nearly every other control. The STIG event set (logon/logoff, account and group management, privilege use, policy changes, use of privileged commands, permission changes, module loading, file deletion) implements AU-2 / AU-12 (event logging and generation), AU-3 (content) and AC-2(4) (automated audit of account actions). Coverage gaps translate directly into blind spots: an attacker's privilege escalation or persistence step that isn't logged can't be detected or reconstructed.",
        "admin": {
            "linux": "On RHEL, auditd rules are placed in /etc/audit/rules.d/*.rules and compiled into /etc/audit/audit.rules by 'augenrules --load'. Syscall rules use '-a always,exit -F arch=b64 -S <syscall>'. Command rules use '-F path=<binary> -F perm=x -F auid>=1000 -F auid!=unset -k <key>'. Watches use '-w <path> -p wa -k <key>'. Supply both b32 and b64 rules where the STIG shows them. Verify the loaded rules with 'auditctl -l' and search events with 'ausearch -k <key>'.",
            "windows": "On Windows, use Advanced Audit Policy Configuration (Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration). Also set 'Audit: Force audit policy subcategory settings to override audit policy category settings' (SCENoApplyLegacyAuditPolicy = 1), or legacy category settings may override them. Verify with 'auditpol /get /category:*'.",
        },
        "impact": "More audit rules mean more log volume and some CPU overhead on busy systems, particularly syscall rules on file-heavy workloads. Make sure log sizing and forwarding can handle the volume (see the audit storage rules).",
        "generic": "This tells the computer to write down important security events in its diary, such as who logged in, who tried and failed, and who changed a setting or used admin powers. If something goes wrong, investigators can look back and see exactly what happened and who did it, much like a building's visitor sign-in log.",
    },
    {
        "id": "memory_protection",
        "name": "Kernel & Memory Exploit Mitigations",
        "short": "Enables OS defenses that make software exploits harder (ASLR, DEP, etc.).",
        "match": r"Data Execution Prevention|\bDEP\b|SEHOP|\bASLR\b|address space layout|randomiz|exploit protection|Structured Exception|virtualization[- ]based|\bVBS\b|\bHVCI\b|hypervisor|kernel\.|ptrace|\bbpf\b|dmesg|kptr|kexec|core dump|coredump|vsyscall|page[_ ]poison|slub|\bpti\b|\bsysrq\b|perf_event|user namespace|yama|Spectre|Meltdown|\bNX\b|ExecShield|memory (protection|integrity)|kernel (stack|pointer|image|lockdown|parameter)|BPF JIT|hardlinks|symlinks|protected_|init_on_free|unprivileged_userns|Early Launch|allocator|use-after-free|heap termination",
        "attack": [("T1068", "Exploitation for Privilege Escalation"), ("T1055", "Process Injection"), ("T1014", "Rootkit"), ("T1203", "Exploitation for Client Execution")],
        "pro": "These mitigations don't remove vulnerabilities. They raise the cost and lower the reliability of exploiting them. ASLR, DEP/NX and SEHOP break classic memory-corruption techniques. Restricting ptrace, kernel pointer exposure, dmesg, unprivileged BPF and kexec removes common local-privilege-escalation primitives and information leaks. Hypervisor-enforced code integrity (HVCI) and VBS protect the kernel itself. These support SI-16 (memory protection), SC-39 (process isolation) and CM-6 baseline configuration.",
        "admin": {
            "linux": "On RHEL, kernel tunables are set in /etc/sysctl.d/*.conf (applied with 'sysctl --system' and verified with 'sysctl <key>'). Remember that a later file or /etc/sysctl.conf can override an earlier drop-in, and the STIG check typically greps all locations for conflicts. Boot parameters (e.g. 'vsyscall=none', 'page_poison=1', 'pti=on', 'slub_debug=P', 'audit=1') are set with 'grubby --update-kernel=ALL --args=...'. Core dumps are controlled through /etc/systemd/coredump.conf and 'ulimit -c'.",
            "windows": "On Windows, set these through Exploit Protection (system DEP, SEHOP, ASLR: 'Get-ProcessMitigation -System'), the 'Turn On Virtualization Based Security' policy under Device Guard, and the MS Security Guide 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' policy.",
        },
        "impact": "Restricting ptrace and dmesg affects debuggers (gdb, strace) for non-root users. Disabling core dumps removes crash diagnostics. HVCI can block older or unsigned drivers, so check driver compatibility first. Most sysctl changes are immediate, while boot parameters require a reboot.",
        "generic": "Hackers often break in by tricking a program into running their own instructions. These settings turn on built-in defenses that shuffle where things sit in memory and refuse to run code from places it shouldn't come from. It's like a bank regularly moving the vault around and refusing to accept instructions written on deposit slips.",
    },
    {
        "id": "removable_media",
        "name": "Removable Media, Peripherals & Wireless",
        "short": "Restricts USB storage, AutoPlay, Bluetooth, wireless and other peripherals.",
        "match": r"\bUSB|usbguard|removable|AutoPlay|AutoRun|cd-?rom|\bDVD|bluetooth|wireless|wi-?fi|\bWLAN|camera|microphone|thunderbolt|firewire|IEEE 1394|\bDMA\b|portable device|non-volume devices|usb-storage|nonessential .*(hardware|peripheral)|unauthorized hardware",
        "attack": [("T1091", "Replication Through Removable Media"), ("T1052.001", "Exfiltration Over USB"), ("T1200", "Hardware Additions")],
        "pro": "Removable media and peripheral interfaces bypass network-layer defenses. They enable malware introduction (AutoRun worms, BadUSB, HID injection), data exfiltration, and DMA attacks via Thunderbolt or FireWire. Wireless radios add unmanaged network paths. These settings implement MP-7 (media use), AC-18/AC-19 (wireless and mobile device access) and CM-7 (least functionality) and should be paired with device-control allowlisting (USBGuard, Windows device installation restrictions).",
        "admin": {
            "linux": "On RHEL, kernel modules are blocked by adding 'install usb-storage /bin/false' and 'blacklist usb-storage' to /etc/modprobe.d/*.conf (similar entries for bluetooth and firewire-core). USBGuard ('dnf install usbguard', policy in /etc/usbguard/rules.conf, generated with 'usbguard generate-policy') allowlists permitted devices. Wireless interfaces are disabled with 'nmcli radio all off'.",
            "windows": "On Windows, AutoPlay and AutoRun are under Administrative Templates >> Windows Components >> AutoPlay Policies (NoDriveTypeAutoRun = 0xFF, NoAutorun = 1). Device installation restrictions are under System >> Device Installation, and DMA protection under Kernel DMA Protection.",
        },
        "impact": "Blocking USB storage affects users who move data on thumb drives, so provide an approved transfer method. Make sure USBGuard policies allow keyboards, mice and smart card readers before enforcing, or you may lose console input.",
        "generic": "USB sticks, Bluetooth and Wi-Fi are convenient, but they're also easy ways for a virus to sneak in or for data to sneak out. This rule turns off or tightly controls these connections. It's like a secure office that doesn't let visitors plug unknown devices into its computers.",
    },
    {
        "id": "kernel_modules",
        "name": "Unneeded Kernel Modules & Protocols",
        "short": "Prevents loading of rarely-used kernel modules and network protocols.",
        "platforms": ("linux",),
        "match": r"kernel module|loadable module|modprobe|blacklist|cramfs|squashfs|\bATM\b|\bCAN\b protocol|\bSCTP\b|\bTIPC\b|\budf\b|\bhfs|\bjffs|freevxfs|rds protocol",
        "attack": [("T1068", "Exploitation for Privilege Escalation"), ("T1547.006", "Boot or Logon Autostart Execution: Kernel Modules and Extensions")],
        "pro": "Linux auto-loads kernel modules on demand. An unprivileged user opening an SCTP, TIPC, CAN or ATM socket, or mounting an unusual file system, can load rarely audited kernel code that has a history of exploitable bugs. Blocking modules that aren't needed shrinks the kernel attack surface available for local privilege escalation (CM-7 least functionality).",
        "admin": {
            "linux": "Create /etc/modprobe.d/<name>.conf containing 'install <module> /bin/false' (prevents loading) and 'blacklist <module>' (prevents auto-loading by alias). Check with 'modprobe -n -v <module>' and 'lsmod | grep <module>'. Unload any currently loaded module with 'modprobe -r'.",
            "windows": "Windows equivalent: disable unused drivers and services, and use WDAC/HVCI driver blocklists.",
        },
        "impact": "Confirm that no workload needs the module (for example, SCTP is used by some telecom applications and CAN by vehicle and industrial interfaces) before blocking it.",
        "generic": "The core of the operating system can load optional add-ons on demand, including some that are rarely used and not well tested. This rule simply removes the ability to load add-ons you'll never need, like boarding up doors in a building that nobody uses, so there are fewer ways in.",
    },
    {
        "id": "network_stack",
        "name": "Network Stack Hardening",
        "short": "Hardens IP/ICMP behavior and disables risky name-resolution protocols.",
        "match": r"\bICMP|\bredirects?\b|source[- ]rout|forward|\bIPv4|\bIPv6|net\.ipv|reverse[- ]path|rp_filter|\bSYN\b|\bTCP\b|router advertisement|martian|broadcast|NetBIOS|\bLLMNR|multicast name|\bWPAD|promiscuous|network interface|\bDNS\b|name resolution|\bmDNS|hardened UNC|\bproxy|NoNameReleaseOnDemand|IP address|bridge|tunnel|insecure (logons|guest)|internet connection sharing|network bridge|Teredo|ISATAP|6to4|non-domain networks|simultaneous connections",
        "attack": [("T1557", "Adversary-in-the-Middle"), ("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay"), ("T1040", "Network Sniffing"), ("T1498", "Network Denial of Service")],
        "pro": "Host network-stack defaults favor interoperability over safety. Accepting ICMP redirects or source-routed packets lets an on-path attacker reroute traffic. IP forwarding turns a host into an unintended router between security zones. Multicast name resolution (LLMNR, NBT-NS, mDNS) is trivially poisoned to capture NTLM hashes. Reverse-path filtering and SYN cookies blunt spoofing and resource-exhaustion attacks. These settings support SC-5, SC-7 (boundary protection) and CM-7.",
        "admin": {
            "linux": "On RHEL, set these with sysctl drop-ins in /etc/sysctl.d/ (net.ipv4.conf.all/default.accept_redirects = 0, send_redirects = 0, accept_source_route = 0, ip_forward = 0, rp_filter = 1, tcp_syncookies = 1, icmp_echo_ignore_broadcasts = 1, and IPv6 equivalents). Apply them with 'sysctl --system'. Both 'all' and 'default' must be set so that new interfaces inherit the values. DNS resolvers are set through NetworkManager or /etc/resolv.conf.",
            "windows": "On Windows, set these through MSS (Legacy) templates included with the STIG GPO package (DisableIPSourceRouting, EnableICMPRedirect, NoNameReleaseOnDemand) and Network >> DNS Client >> 'Turn off multicast name resolution' (EnableMulticast = 0). Hardened UNC Paths requires mutual authentication and integrity for \\\\*\\SYSVOL and \\\\*\\NETLOGON.",
        },
        "impact": "Hosts that legitimately route (VPN concentrators, container and Kubernetes nodes, libvirt hosts) need IP forwarding and must document the exception. Disabling LLMNR and NetBIOS requires working DNS for all name lookups.",
        "generic": "These settings change how the computer handles network traffic at a low level, for example ignoring suspicious \"take a detour\" messages and not answering \"who is this?\" broadcasts that attackers can fake. It's like a mail room that refuses packages with forged return addresses and won't hand mail to anyone who just shouts a name.",
    },
    {
        "id": "firewall",
        "name": "Host Firewall",
        "short": "Requires an active host firewall with a deny-by-default policy.",
        "match": r"firewall|firewalld|nftables|iptables|packet filter|ports, protocols|\bPPSM\b|deny-all|inbound (connections|exceptions|rules)|outbound connections|network traffic .*(allow|deny)",
        "attack": [("T1562.004", "Impair Defenses: Disable or Modify System Firewall"), ("T1021", "Remote Services"), ("T1046", "Network Service Discovery")],
        "pro": "A host firewall enforces deny-by-default, allow-by-exception at the endpoint (SC-7(5)) and contains lateral movement even when the perimeter is breached or the host sits on a flat network. Exposed ports must match the system's PPSM registration (CM-7(1)). Remote-management exceptions should be scoped to authorized management hosts rather than 'any'. Check that the firewall service can't be stopped by non-administrators and that rule changes are audited.",
        "admin": {
            "linux": "On RHEL, use firewalld (systemctl enable --now firewalld) with nftables as the backend (FirewallBackend=nftables in /etc/firewalld/firewalld.conf). Set the default zone to drop or deny and add only the required services and ports ('firewall-cmd --permanent --add-service=...', then '--reload'). Review with 'firewall-cmd --list-all-zones'.",
            "windows": "On Windows, use Windows Defender Firewall with Advanced Security. Turn it on for the Domain, Private and Public profiles with inbound set to block by default. Scope management rules (RDP, WinRM, SMB) to the management subnets. Verify with 'Get-NetFirewallProfile' and 'Get-NetFirewallRule'.",
        },
        "impact": "An over-restrictive default can cut off management or application traffic. Make changes from the console, or stage them with a timed rollback ('firewall-cmd --timeout').",
        "generic": "A firewall is a gatekeeper that decides which network connections are allowed in and out of the computer. This rule makes sure the gatekeeper is switched on and turns away anything that isn't on the approved list, like a security guard who only lets in people with an appointment.",
    },
    {
        "id": "software_minimization",
        "name": "Least Functionality: Remove Unneeded Software",
        "short": "Removes or disables software, features and services that aren't required.",
        "match": r"must not (have|be) .*(install|enabled|running)|must not be installed|(is|are) not installed|uninstall|remove(d)? .*(package|software|feature)|(package|feature).*remov|unnecessary (software|services|programs)|least functionality|\b(TFTP|telnet|rsh|ypserv|sendmail|gssproxy|iprutils|tuned|abrt|quagga|vsftpd|Simple TCP|SNMP|Fax|PNRP|Peer Name|Games|Xbox|SMBv1|SMB 1|SMB1|PowerShell 2|Internet Information|IIS|nfs-utils|avahi|cups|Microsoft FTP|Windows Media|xorg-x11-server)",
        "attack": [("T1190", "Exploit Public-Facing Application"), ("T1210", "Exploitation of Remote Services"), ("T1059", "Command and Scripting Interpreter")],
        "pro": "Every installed package, role and feature is potential attack surface, and some (telnet, rsh, TFTP, SMBv1, PowerShell 2.0) are inherently insecure or allow security controls to be bypassed. For example, PowerShell 2.0 bypasses script-block logging and AMSI. CM-7 (least functionality) and CM-7(1)/(2) require removing what isn't mission-necessary. Removal also reduces patch burden and false positives in vulnerability scans.",
        "admin": {
            "linux": "On RHEL, remove packages with 'dnf remove <pkg>' and verify with 'rpm -q <pkg>' (expect 'package <pkg> is not installed'). Watch for dependency cascades in the dnf transaction summary before confirming.",
            "windows": "On Windows Server, remove roles and features with 'Uninstall-WindowsFeature <Name>' or through Server Manager. On client OSes, use 'Disable-WindowsOptionalFeature -Online -FeatureName <Name>'. Verify with 'Get-WindowsFeature | Where Installed' or 'Get-WindowsOptionalFeature -Online'.",
        },
        "impact": "Check that no application depends on the component before removing it (e.g. legacy scripts using PowerShell 2.0, tools that shell out to telnet or ftp). Keep a record of what was removed so it can be restored if a mission requirement is identified.",
        "generic": "Every program on a computer is another possible way in for an attacker. This rule removes software the system doesn't need, especially old programs known to be unsafe. It's like clearing clutter out of a house: fewer things lying around means fewer things that can be broken or misused.",
    },
    {
        "id": "remote_access",
        "name": "Remote Desktop & Remote Management",
        "short": "Hardens RDP, WinRM and other remote-management channels.",
        "match": r"Remote Desktop|\bRDP\b|Terminal Services|\bRDS\b|\bWinRM\b|Windows Remote Management|remote assistance|remote (access|session|connection|management|shell)|\bVNC\b|\bX11\b|Basic authentication|unencrypted traffic|Digest authentication|RunAs credentials|drive redirection|password saving|client connection encryption|always prompt (client )?for passwords?",
        "attack": [("T1021.001", "Remote Services: Remote Desktop Protocol"), ("T1021.006", "Remote Services: Windows Remote Management"), ("T1563", "Remote Service Session Hijacking"), ("T1040", "Network Sniffing")],
        "pro": "Remote-management protocols give interactive or programmatic control of a host and are a favored vector for both ransomware operators and insiders. Requirements include encrypted transport, no Basic/Digest authentication or unencrypted WinRM traffic, always prompting for credentials, no saved RDP passwords, no drive redirection, and session time limits. These implement AC-17 (remote access), AC-17(2) (confidentiality and integrity via encryption), SC-8 and AC-12 (session termination).",
        "admin": {
            "windows": "On Windows, RDP settings are under Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host (Security / Device and Resource Redirection / Session Time Limits), and WinRM settings under Windows Components >> Windows Remote Management (WinRM Client / WinRM Service). Verify WinRM with 'winrm get winrm/config'.",
            "linux": "On RHEL, X11 forwarding ('X11Forwarding no' in sshd), VNC servers and cockpit are the main remote-access paths to restrict.",
        },
        "impact": "Disabling drive and clipboard redirection affects admin convenience. WinRM restrictions can break management tools that use Basic auth over HTTP (some older configuration-management and monitoring products), so move those to Kerberos or HTTPS.",
        "generic": "Administrators can control computers from far away, as if they were sitting at the keyboard. This rule makes sure those remote connections are encrypted, require a proper sign-in every time, and can't be used to copy files around carelessly. It's like requiring a video-verified, recorded call before anyone can give orders over the phone.",
    },
    {
        "id": "powershell",
        "platforms": ("windows",),
        "name": "PowerShell & Scripting Security",
        "short": "Enables PowerShell logging and restricts script hosts.",
        "match": r"PowerShell|script block|transcription|Windows Script Host|\bscripting\b|\bWSH\b",
        "attack": [("T1059.001", "Command and Scripting Interpreter: PowerShell"), ("T1059.005", "Command and Scripting Interpreter: Visual Basic"), ("T1562.003", "Impair Defenses: Impair Command History Logging")],
        "pro": "PowerShell is the dominant 'living off the land' tool in Windows intrusions. Script Block Logging (event 4104) records de-obfuscated code as it executes, and Transcription records full session input and output. Together they provide high-fidelity detection content for AU-2/AU-12 and SI-4. Removing PowerShell 2.0 prevents downgrade attacks that bypass these logs and AMSI.",
        "admin": {
            "windows": "On Windows, configure these under Administrative Templates >> Windows Components >> Windows PowerShell: 'Turn on PowerShell Script Block Logging' (HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging EnableScriptBlockLogging = 1) and 'Turn on PowerShell Transcription'. Logs go to Microsoft-Windows-PowerShell/Operational. Write transcripts to a protected, centrally collected location.",
            "linux": "Not applicable to Linux, where shell history and auditd execve rules serve a similar purpose.",
        },
        "impact": "Script-block logs can be large and may capture secrets embedded in scripts. Size the PowerShell Operational log appropriately and restrict who can read it.",
        "generic": "PowerShell is a powerful tool for automating tasks on Windows, which also makes it a favorite of hackers. This rule makes the computer keep a detailed record of every PowerShell command that runs, like a CCTV camera pointed at the most powerful tool in the workshop.",
    },
    {
        "id": "antimalware",
        "name": "Anti-Malware & Reputation Protection",
        "short": "Keeps antivirus, SmartScreen and malware defenses enabled and current.",
        "match": r"Defender|anti-?virus|anti-?malware|SmartScreen|malicious code|malware|\bvirus|Attack Surface Reduction|\bASR\b|potentially unwanted|\bPUA\b|Early Launch Antimalware|\bELAM\b|host[- ]based (intrusion|security)|\bHBSS\b|\bENS\b|Endpoint Security",
        "attack": [("T1562.001", "Impair Defenses: Disable or Modify Tools"), ("T1204", "User Execution"), ("T1566", "Phishing")],
        "pro": "Signature and behavioral anti-malware, together with reputation services such as SmartScreen, address commodity and opportunistic threats at the endpoint (SI-3 malicious code protection, SI-3(2) automatic updates). DoD typically requires an approved enterprise endpoint-security suite. The STIG check confirms that a capable product is installed, running and updating, and that users can't bypass warnings.",
        "admin": {
            "windows": "On Windows, configure Microsoft Defender Antivirus under Administrative Templates >> Windows Components >> Microsoft Defender Antivirus, and SmartScreen under Windows Components >> File Explorer and Microsoft Edge. Verify with 'Get-MpComputerStatus' (AMServiceEnabled, AntivirusSignatureLastUpdated). If a third-party DoD-approved product is deployed, Defender may run in passive mode.",
            "linux": "On RHEL, use the enterprise-approved endpoint product (e.g. Trellix/ENSL). Verify that the agent service is active and its definitions are current.",
        },
        "impact": "Real-time scanning adds I/O overhead. Define vetted exclusions for databases and build directories only with ISSO approval and document them.",
        "generic": "This keeps the computer's virus scanner switched on and up to date, and warns people before they open files or websites known to be dangerous. It's the digital equivalent of a smoke detector with fresh batteries.",
    },
    {
        "id": "patching",
        "name": "Patching & Supported Software",
        "short": "Requires vendor-supported OS versions and current security updates.",
        "match": r"vendor[- ]supported|supported (release|version)|\bpatch|security (patches|updates)|updates? (must|are|be) (installed|applied)|end of (life|support)|software updates|up to date|previous versions|clean_requirements_on_remove|servicing|Windows Update|\bWSUS|flaw remediation",
        "attack": [("T1190", "Exploit Public-Facing Application"), ("T1068", "Exploitation for Privilege Escalation"), ("T1210", "Exploitation of Remote Services")],
        "pro": "Known, unpatched vulnerabilities remain the most common initial-access and privilege-escalation vector. Running an unsupported release means new vulnerabilities will never be fixed. SI-2 (flaw remediation) and SA-22 (unsupported system components) require timely patching per organizational timelines (IAVM compliance in DoD) and replacement of end-of-life components. Unsupported OS findings are CAT I because they can't be mitigated by configuration alone.",
        "admin": {
            "linux": "On RHEL, patch from approved repositories with 'dnf update' (or 'dnf update --security'). Review history with 'dnf history' and pending errata with 'dnf updateinfo list'. Setting 'clean_requirements_on_remove=True' in /etc/dnf/dnf.conf removes orphaned dependencies when software is removed. Check the release with 'cat /etc/redhat-release' against Red Hat's life-cycle page.",
            "windows": "On Windows, patch through WSUS, ConfigMgr, Intune or Windows Update for Business. Check installed updates with 'Get-HotFix' and the OS build with 'winver' against Microsoft's lifecycle page.",
        },
        "impact": "Patching requires maintenance windows and sometimes reboots. Test critical applications against updates in a staging environment, but don't let testing stretch beyond IAVM deadlines.",
        "generic": "Software makers regularly release fixes for security holes they discover. This rule requires installing those fixes and only running versions that are still supported. It's like getting the recall repair on your car: skip it, and the known problem stays there for anyone to take advantage of.",
    },
    {
        "id": "integrity",
        "name": "Software & File Integrity Verification",
        "short": "Verifies package signatures and detects unauthorized file changes.",
        "match": r"\bgpg|signature|digitally signed|signed (packages|software)|repositor|\bAIDE\b|file integrity|integrity (check|verif|tool)|rpm -V|verif\w+ .*(hash|cryptographic)|unsigned|tamper|baseline .*(change|configuration)|changes to (the )?(baseline|security configuration)|cryptographic hash|extended attributes|\bACLs? .*AIDE|unauthorized (changes|software)",
        "attack": [("T1195", "Supply Chain Compromise"), ("T1554", "Compromise Host Software Binary"), ("T1014", "Rootkit")],
        "pro": "Signature verification ensures only vendor-authentic software is installed (CM-14 signed components, SI-7 software and information integrity). File-integrity monitoring such as AIDE detects unauthorized modification of binaries and configuration after the fact (SI-7(1), CM-3(5)), catching rootkits, backdoored binaries and configuration drift. The value of FIM depends on protecting the baseline database off-host and acting on alerts.",
        "admin": {
            "linux": "On RHEL, repositories must have 'gpgcheck=1' (/etc/dnf/dnf.conf and /etc/yum.repos.d/*.repo) and 'localpkg_gpgcheck=1', with Red Hat GPG keys imported ('rpm -q gpg-pubkey'). AIDE is configured in /etc/aide.conf (rules should include acl, xattrs and sha512). Initialize with 'aide --init' and move the new database into place. Schedule 'aide --check' daily (cron or systemd timer) with notification to the SA/ISSO.",
            "windows": "On Windows, use WDAC/AppLocker for signature enforcement, 'sfc /verifyonly' for system file verification, and the enterprise FIM product.",
        },
        "impact": "AIDE reports every legitimate change too, so re-baseline after approved patching and keep the database read-only or off-host. Internal repositories must sign their packages, or clients will refuse them.",
        "generic": "This makes the computer check a digital \"seal\" on software before installing it, and keep a fingerprint of important files so it can notice if anyone changes them. It's like checking that a medicine bottle's safety seal is intact, and noticing straight away if someone has tampered with it.",
    },
    {
        "id": "app_control",
        "name": "Mandatory Access & Application Control",
        "short": "Enforces SELinux, fapolicyd, AppLocker or WDAC allowlisting.",
        "match": r"SELinux|security context|fapolicyd|application (whitelist|allowlist|control)|AppLocker|\bWDAC\b|Device Guard|code integrity|deny-all, permit-by-exception|mandatory access|\benforcing\b|targeted policy|security label|allowlist|whitelist|authorized software",
        "attack": [("T1204.002", "User Execution: Malicious File"), ("T1059", "Command and Scripting Interpreter"), ("T1068", "Exploitation for Privilege Escalation")],
        "pro": "Discretionary permissions can't stop a compromised process from doing whatever its user can do. Mandatory access control such as SELinux confines each service to its policy, which contains exploitation of daemons. Application allowlisting (fapolicyd, AppLocker, WDAC) implements CM-7(5) (authorized software, deny-by-default) and AC-3(3) (mandatory access control), defeating most commodity malware and unauthorized tools. These are among the highest-value preventive controls in the baseline.",
        "admin": {
            "linux": "On RHEL, set SELinux in /etc/selinux/config ('SELINUX=enforcing', 'SELINUXTYPE=targeted') and verify with 'getenforce' and 'sestatus'. Fix labels with 'restorecon -Rv' and troubleshoot denials with 'ausearch -m AVC' or 'sealert'. fapolicyd ('systemctl enable --now fapolicyd') uses rules in /etc/fapolicyd/rules.d/ and the trust database. Start with 'permissive = 1' to gather data, then enforce.",
            "windows": "On Windows, AppLocker policies are under Security Settings >> Application Control Policies, which requires the Application Identity service. WDAC policies are deployed through Intune, ConfigMgr or GPO. Run in audit mode first and review the event logs.",
        },
        "impact": "Turning on enforcement without a learning period will block legitimate software. Use permissive or audit mode, analyze the logs, build rules, then enforce. Never disable SELinux to 'fix' an application. Fix the label or policy instead.",
        "generic": "Instead of trying to spot every bad program, the computer keeps a list of approved programs and only those are allowed to run, while each program is kept to its own lane. It's like a guest list at an event: if you're not on the list, you don't get in, no matter how convincing you look.",
    },
    {
        "id": "file_permissions",
        "name": "File & Directory Permissions",
        "short": "Restricts ownership and permissions on sensitive files and directories.",
        "match": r"\b(owned|group-owned|ownership)\b|mode of|\bmode (of )?\"?\d{3,4}|have (a )?mode|permissions?|world[- ]writable|sticky bit|setuid|setgid|\bSUID|\bSGID|access control list|\bumask|unowned|valid (owner|group)|must be (owned|group)|file system objects|\bACLs?\b",
        "attack": [("T1222", "File and Directory Permissions Modification"), ("T1574", "Hijack Execution Flow"), ("T1548.001", "Abuse Elevation Control: Setuid and Setgid")],
        "pro": "Permissive ownership or modes on credentials (shadow, SSH host keys), libraries, system binaries, cron and boot configuration, and log files allow tampering, credential theft and execution-flow hijacking. This is AC-3 / AC-6 least privilege applied at the file-system layer, plus CM-5(6) (privilege to change software libraries). Unowned files and world-writable directories without the sticky bit are common persistence and escalation footholds.",
        "admin": {
            "linux": "On RHEL, use 'stat -c \"%a %U %G %n\" <path>' to check mode and ownership, and 'chmod', 'chown' and 'chgrp' to fix them. Find problems with 'find / -xdev -nouser -o -nogroup' and 'find / -xdev -type d -perm -0002 ! -perm -1000'. Default permissions for new files come from umask (077 in /etc/login.defs and the shell profiles). 'rpm --setperms <pkg>' restores packaged defaults.",
            "windows": "On Windows, check NTFS ACLs with 'icacls <path>' or 'Get-Acl'. The STIG specifies baseline ACLs for system folders, registry hives and event logs. Don't broaden the default ACLs on %SystemRoot%, Program Files or HKLM\\SECURITY.",
        },
        "impact": "Tightening permissions can break applications that read their configuration as a non-root user. Prefer group-based access over loosening the mode, and re-check after package updates, which can reset modes.",
        "generic": "Every file on a computer has a label saying who owns it and who can read or change it. This rule makes sure sensitive files, such as the list of password fingerprints or system settings, can only be touched by the right people. It's like keeping personnel files in a locked HR cabinet rather than on the break-room table.",
    },
    {
        "id": "filesystem_mounts",
        "name": "File System Layout & Mount Options",
        "short": "Separates partitions and restricts execution/device files via mount options.",
        "match": r"separate (file system|partition)|\bmount|nodev|nosuid|noexec|/tmp|/var/tmp|/dev/shm|file system|partition|autofs|automount|\bNFS\b|tmp\.mount|/home|/var/log",
        "attack": [("T1068", "Exploitation for Privilege Escalation"), ("T1499", "Endpoint Denial of Service")],
        "pro": "Separate partitions keep runaway logs or user data from exhausting the root file system, which is an availability and audit-integrity concern (AU-4, SC-5). Mount options remove whole classes of attack. 'nodev' blocks device files, 'nosuid' neutralizes planted SUID binaries, and 'noexec' prevents execution from world-writable locations such as /tmp and /dev/shm, a common staging area for exploits (CM-6, CM-7).",
        "admin": {
            "linux": "On RHEL, partitions are defined at install time (/home, /tmp, /var, /var/log, /var/log/audit, /var/tmp). Changing them later generally needs LVM work or a rebuild. Mount options go in /etc/fstab (e.g. 'defaults,nodev,nosuid,noexec') and are applied with 'mount -o remount <mountpoint>'. Verify with 'findmnt -no OPTIONS <mountpoint>'. Disable autofs ('systemctl disable --now autofs') unless it's required.",
            "windows": "On Windows, NTFS is required for all local volumes. Separate data volumes are an availability practice.",
        },
        "impact": "'noexec' on /tmp can break installers and tools that extract and run helpers there. Set TMPDIR to an alternate location for those. Re-partitioning a running system is disruptive, so build the layout into the kickstart profile instead.",
        "generic": "The computer's storage is divided into separate sections, like rooms in a house. This rule keeps certain rooms separate so one can't overflow into the others, and marks rooms such as the \"temporary storage\" area as places where programs aren't allowed to run. It's like a garage where you can store things but nobody is allowed to live.",
    },
    {
        "id": "boot_security",
        "name": "Boot Process & Console Security",
        "short": "Protects the boot loader, firmware and recovery/console paths.",
        "match": r"boot ?loader|\bGRUB|grub2|\bUEFI|Secure Boot|\bBIOS|single[- ]user|rescue|emergency (mode|target|service)|maintenance mode|boot (password|mode)|\bTPM\b|Trusted Platform|kdump|Ctrl-Alt-Del|Ctrl-Alt-Delete|CtrlAltDel|graphical (user interface|target) .*(default|boot)|default target|debug-shell|systemd target|power button|reboot|shutdown|superusers? name",
        "attack": [("T1542", "Pre-OS Boot"), ("T1542.003", "Pre-OS Boot: Bootkit"), ("T1529", "System Shutdown/Reboot")],
        "pro": "Anyone with console or hypervisor access can interrupt the boot process to edit kernel parameters (e.g. 'init=/bin/bash'), boot into single-user or rescue mode, or load an untrusted boot loader, bypassing all OS authentication. A boot-loader password, authenticated rescue modes and UEFI Secure Boot close this path (AC-3, CM-6, SI-7(9) boot process integrity). Disabling Ctrl-Alt-Del and similar console actions prevents accidental or malicious reboots (availability).",
        "admin": {
            "linux": "On RHEL, set the GRUB2 superuser password with 'grub2-setpassword' (stored hashed in /boot/grub2/user.cfg or /boot/efi/EFI/redhat/user.cfg) and set a unique superuser name in /etc/grub.d/01_users. Rescue and emergency modes must require root authentication (sulogin in rescue.service and emergency.service). Mask Ctrl-Alt-Del with 'systemctl mask ctrl-alt-del.target' and 'CtrlAltDelBurstAction=none' in systemd's system.conf. Mask debug-shell. kdump is disabled unless it's needed.",
            "windows": "On Windows, Secure Boot and the TPM are verified with 'Confirm-SecureBootUEFI' and 'Get-Tpm'. Firmware must be UEFI, not Legacy BIOS. Boot-time protection also comes from BitLocker and the Early Launch Antimalware policy.",
        },
        "impact": "Store the boot-loader password in the system's credential vault, because you'll need it for kernel-parameter troubleshooting. Converting Legacy BIOS installs to UEFI generally requires MBR2GPT or a rebuild.",
        "generic": "While a computer is starting up, before the normal sign-in screen appears, there are special \"maintenance doors\" that can skip the usual security. This rule puts locks on those doors and makes sure the computer only starts with trusted software, like making sure nobody can hot-wire a car by tampering with it before the key is turned.",
    },
    {
        "id": "time_sync",
        "name": "Time Synchronization",
        "short": "Synchronizes system clocks with authoritative DoD time sources.",
        "match": r"\bNTP\b|chrony|timesync|time (source|server|service)|authoritative time|\bclock|synchroniz\w+ .*(time|clock)|time ?stamps?|time zone|\bUTC\b|\bGMT\b|W32Time",
        "attack": [("T1070.006", "Indicator Removal: Timestomp")],
        "pro": "Accurate, synchronized time underpins log correlation across systems, Kerberos authentication (5-minute skew tolerance), certificate validity checks and forensic timelines (AU-8, AU-8(1) synchronization with an authoritative source, AU-8(2) secondary source). Time sources should be authenticated where possible and restricted to client mode, so the host can't be abused as an NTP amplifier.",
        "admin": {
            "linux": "On RHEL, chronyd is configured in /etc/chrony.conf: use 'server <DoD-time-source> iburst maxpoll 16', 'port 0' (don't act as a server) and 'cmdport 0'. Verify with 'chronyc sources -v' and 'timedatectl'. Time stamps should map to UTC/GMT.",
            "windows": "On Windows, domain members sync from the domain hierarchy (NT5DS). The PDC emulator must point to an authoritative source using Administrative Templates >> System >> Windows Time Service >> Time Providers >> 'Configure Windows NTP Client'. Verify with 'w32tm /query /status'.",
        },
        "impact": "Large clock corrections can confuse running applications. chrony slews gradually by default. Make sure the time servers are reachable through the firewall (UDP 123).",
        "generic": "This keeps the computer's clock exactly in step with an official time source. That might sound minor, but security logs from different computers can only be pieced together if every clock agrees, and some sign-in systems refuse to work when clocks drift. It's like making sure all the witnesses' watches show the same time.",
    },
    {
        "id": "session_lock",
        "name": "Session Lock & Inactivity Timeout",
        "short": "Locks or ends idle sessions and conceals the screen.",
        "match": r"session lock|screen ?saver|lock(s)? (the )?(session|screen|workstation)|inactiv\w*.*(lock|session|terminat|logoff|log off|disconnect|minutes)|idle|lock-delay|lock-enabled|machine inactivity|\bTMOUT|session.*terminat|terminate .*session|ClientAlive|smart card removal|conceal|publicly viewable|picture-uri|session time limit|automatically (lock|log)",
        "attack": [("T1078", "Valid Accounts")],
        "pro": "Unattended, unlocked sessions are an opportunistic access path for insiders and visitors, so physical access becomes logical access. AC-11 (device lock, 15 minutes in DoD), AC-11(1) (pattern-hiding displays) and AC-12 (session termination) require automatic locking that the user can't override, re-authentication to unlock, and concealment of on-screen content. Smart-card removal locking extends this to CAC workflows.",
        "admin": {
            "linux": "On RHEL, set GNOME locking through dconf in /etc/dconf/db/local.d/ (org/gnome/desktop/session idle-delay=uint32 900, org/gnome/desktop/screensaver lock-enabled=true, lock-delay=uint32 5) and lock each key in /etc/dconf/db/local.d/locks/ so users can't override it. Then run 'dconf update'. For terminals, set TMOUT=900 (readonly) in /etc/profile.d/. Network and SSH sessions use ClientAliveInterval/CountMax and systemd-logind StopIdleSessionSec.",
            "windows": "On Windows, set 'Interactive logon: Machine inactivity limit' (InactivityTimeoutSecs <= 900) and 'Interactive logon: Smart card removal behavior' (Lock Workstation). Personalization policies prevent the lock screen from showing slide shows or camera access.",
        },
        "impact": "Users running long unattended interactive jobs may be disconnected. Kiosk or operations displays that must stay visible need a documented exception and compensating physical controls.",
        "generic": "If you walk away from the computer and forget to lock it, it will lock itself after a short time (15 minutes for DoD) and hide what was on the screen. Anyone who sits down then has to sign in again. It's like a car that locks its doors automatically when you walk away.",
    },
    {
        "id": "logon_interface",
        "name": "Logon Screen & Desktop Settings",
        "short": "Controls what the logon screen and desktop reveal or allow.",
        "match": r"graphical|\bGNOME|\bdconf|\bGDM\b|display manager|X Windows|\bxorg|login screen|logon screen|user list|automatic (login|logon)|AutomaticLogin|restart button|lock screen|camera|slide ?show|notifications?|toast|last (user|logged)|display .*(user|name)|enumerate (local )?(users|administrator)|Ctrl\+Alt\+Del|CTRL\+ALT\+DEL|sign-in options|password reveal|picture password|PIN sign-in|convenience PIN|Windows Hello|facial|biometric|anti-spoofing",
        "attack": [("T1087", "Account Discovery"), ("T1078", "Valid Accounts")],
        "pro": "The logon surface can leak information (usernames, the last logged-on user, local administrator lists) that cuts an attacker's effort in half, and convenience features (automatic logon, picture passwords, convenience PINs, password reveal buttons) weaken authentication assurance. These settings reduce information disclosure (AC-14, IA-6 authenticator feedback) and keep interactive logon on approved authenticators.",
        "admin": {
            "linux": "On RHEL, GDM and GNOME settings are managed through dconf databases in /etc/dconf/db/{gdm,local}.d/ with matching locks, followed by 'dconf update'. Examples include disable-user-list, disable-restart-buttons, and 'AutomaticLoginEnable=false' in /etc/gdm/custom.conf. If no GUI is required, remove the GNOME and X packages and set 'systemctl set-default multi-user.target'.",
            "windows": "On Windows, use Security Options such as 'Interactive logon: Don't display last signed-in' and 'Do not require CTRL+ALT+DEL' (Disabled). Administrative Templates >> System >> Logon covers enumerating local users, convenience PIN and picture password. Credential User Interface >> 'Do not display the password reveal button' handles the reveal button.",
        },
        "impact": "Users will need to type their username in full and can't use convenience sign-in methods. Hiding restart buttons on the logon screen means console users need credentials to reboot.",
        "generic": "This decides what the sign-in screen shows and which shortcuts are allowed. For example, it hides the list of usernames, doesn't show who signed in last, and turns off \"sign in automatically\". It's like a hotel front desk that won't tell a stranger which room a guest is in.",
    },
    {
        "id": "privacy_cloud",
        "name": "Telemetry, Cloud & Consumer Features",
        "short": "Limits data sharing with vendors and disables consumer/cloud features.",
        "match": r"telemetry|diagnostic data|Cortana|Microsoft accounts?|consumer|Microsoft Store|Windows Store|Store app|wizard|providers|Internet (communication|download)|print(ing)? over HTTP|print driver|Windows Spotlight|OneDrive|\bcloud|advertising|Copilot|\bRecall\b|web search|search .*(web|location)|feedback|Customer Experience|Error Reporting|inventory|location|app (access|permissions)|\bEdge\b|Internet Explorer|browser|Windows Ink|\bGame|Xbox|\bsync|activity history|clipboard|\bBing|content (delivery|suggestion)|third-party (cookie|suggestion|content)|news and interests|Widgets|online (tips|identit)|Delivery Optimization|Wi-Fi Sense|Insider|preview builds|indexing|encrypted files|attachments|Windows Ink|Messaging|Phone Link|tips|voice|Preview pane",
        "attack": [("T1567", "Exfiltration Over Web Service"), ("T1213", "Data from Information Repositories")],
        "pro": "Consumer-oriented and cloud-connected features can move government data (documents, typed input, location, diagnostic dumps containing memory contents) to vendor or third-party services outside the authorization boundary. Disabling or restricting them supports SC-7 (boundary protection), AC-20 (use of external systems), CM-7 and privacy controls, and removes unvetted functionality from the baseline.",
        "admin": {
            "windows": "On Windows these are mostly Administrative Templates under Windows Components (Data Collection and Preview Builds, Cloud Content, Search, Store, OneDrive, Windows Error Reporting, App Privacy) and the Microsoft Edge templates. Verify the registry values under HKLM\\SOFTWARE\\Policies\\Microsoft\\... as shown in each check.",
            "linux": "On RHEL, the equivalents are disabling the ABRT crash reporter, Insights client data sharing, and GNOME online accounts if they're not approved.",
        },
        "impact": "Users lose consumer conveniences such as Store apps, Microsoft-account sign-in and web results in search. Enterprise management may need a minimum telemetry level (e.g. for Windows Update for Business reports), so align the value with the STIG's allowed options.",
        "generic": "Modern computers like to \"phone home\", sending usage data to the manufacturer, syncing to personal cloud accounts, or showing ads and suggestions. This rule turns those features off or down so government information stays inside the government's systems, like not letting a delivery driver wander through the office and take notes.",
    },
    {
        "id": "pam_identity",
        "platforms": ("linux",),
        "name": "Authentication Stack (PAM, SSSD, Directory)",
        "short": "Configures PAM/SSSD authentication modules and identity sources.",
        "match": r"\bPAM\b|pam_|pluggable authentication|\bSSSD|\bsssd|\bLDAP|nsswitch|authselect|offline credentials|cached authenticator|identification and authentication (system|module)|authenticat\w+ .*(module|cache)|delay .*(logon|login) prompts|FAIL_DELAY|login\.defs|CREATE_HOME|lastlog|last (successful )?(logon|login)|number of concurrent sessions|maxlogins",
        "attack": [("T1556.003", "Modify Authentication Process: Pluggable Authentication Modules"), ("T1110", "Brute Force")],
        "pro": "PAM and SSSD define how every Linux authentication decision is made. Misordered or optional modules silently bypass controls such as faillock, pwquality and pwhistory. Credential caching lifetimes trade availability against revocation latency, so a revoked account keeps working offline until its cache expires. These settings support IA-2, IA-5(13) (expiration of cached authenticators), AC-7, AC-9 (previous logon notification) and AC-10 (concurrent session control).",
        "admin": {
            "linux": "On RHEL, PAM stacks live in /etc/pam.d/ (system-auth, password-auth, login, sshd, su). Manage them through authselect profiles ('authselect select sssd with-faillock with-mkhomedir ...', 'authselect current'), because authselect overwrites hand edits. Custom changes belong in a custom profile ('authselect create-profile'). SSSD is configured in /etc/sssd/sssd.conf and conf.d/ (mode 0600, owned by root), and you restart sssd after changes. Concurrent session limits are set in /etc/security/limits.conf ('* hard maxlogins 10').",
            "windows": "On Windows, the domain authentication stack is governed by Kerberos/NTLM policy and the netlogon secure channel settings.",
        },
        "impact": "PAM mistakes can lock everyone out, including root. Test changes from a second, still-open root session, and keep console access available.",
        "generic": "Behind the sign-in screen is a chain of checks: the password is right, the account isn't locked, the password isn't expired, and so on. This rule makes sure every check in that chain is present and in the correct order, like making sure every guard at a multi-checkpoint entrance is at their post.",
    },
    {
        "id": "domain_services",
        "platforms": ("windows",),
        "name": "Active Directory & Domain Controller Security",
        "short": "Hardens domain controllers, LDAP, secure channel and directory objects.",
        "match": r"domain controller|Active Directory|\bAD\b|\bLDAP|directory (service|data|object)|\bNTDS|SYSVOL|krbtgt|domain (account|member|trust|join|level)|machine account|secure channel|Group Policy objects?|dsHeuristics|\btrusts?\b|forest|schema|\bDSRM|PKI certificates.*server|Computer account password|AdminSDHolder|Enterprise Admins|Domain Admins",
        "attack": [("T1003.006", "OS Credential Dumping: DCSync"), ("T1484", "Domain or Tenant Policy Modification"), ("T1558", "Steal or Forge Kerberos Tickets"), ("T1557", "Adversary-in-the-Middle")],
        "pro": "Domain controllers hold the keys to every domain identity, so DC compromise is total enterprise compromise. Requirements cover LDAP signing and channel binding (anti-relay), secure-channel signing and sealing, machine-account password rotation, protection of NTDS/SYSVOL/GPO permissions, restricting who can administer and log on to DCs, and directory auditing. These implement AC-3, AC-6, SC-8, SC-23 and AU-2 for the identity tier. Assess them alongside the administrative tiering model.",
        "admin": {
            "windows": "On Windows, the relevant Security Options include 'Domain controller: LDAP server signing requirements' (Require signing), 'Domain member: Digitally encrypt or sign secure channel data (always)' and 'Domain member: Maximum machine account password age' (30 days). DC-specific checks review permissions on NTDS (%SystemRoot%\\NTDS), SYSVOL and GPOs, and AD object auditing (SACLs). Use 'dcdiag', 'repadmin /showrepl' and ADSI Edit or 'Get-Acl AD:' to verify.",
            "linux": "On RHEL, the counterparts are realmd/SSSD domain join settings and the 'ldap_id_use_start_tls' and 'ldap_tls_reqcert' options.",
        },
        "impact": "Enforcing LDAP signing or channel binding breaks clients and appliances that use simple binds over unsigned LDAP. Check Directory Service event 2889 to find them before enforcing.",
        "generic": "In an organization, a few central servers (domain controllers) keep the master list of every user, password and permission. This rule adds extra protection to those servers and the conversations other computers have with them. It's like guarding the room that holds the master key cabinet more tightly than any other room in the building.",
    },
    {
        "id": "services",
        "name": "System Services & Daemons",
        "short": "Enables required security services and disables risky ones.",
        "match": r"(?<!Desktop )(?<!TCP/IP )\bservices?\b|daemon|systemctl|\bsocket|\bmask|enabled and active|must be (running|active|enabled)|\bcron|\bat\b daemon|rsyslog service|auditd service|postfix|\bmail\b|debug",
        "attack": [("T1543", "Create or Modify System Process"), ("T1210", "Exploitation of Remote Services")],
        "pro": "Security functions such as auditd, firewalld, sshd's hardened configuration, fapolicyd and USBGuard only protect the system while their services are running. Conversely, every listening or socket-activated service is reachable attack surface. CM-7 (least functionality) and AU/SI controls require the security services to be enabled and the non-essential ones disabled or masked so they can't be started indirectly.",
        "admin": {
            "linux": "On RHEL, use 'systemctl enable --now <unit>' for required services and 'systemctl disable --now <unit>' plus 'systemctl mask <unit>' for prohibited ones. Masking prevents a service from being started manually or as a dependency. Check with 'systemctl is-enabled <unit>' and 'systemctl is-active <unit>', and remember the matching .socket units.",
            "windows": "On Windows, set the service startup type through Group Policy (System Services) or 'Set-Service -StartupType Disabled'. Check with 'Get-Service <name> | Select Status, StartType'.",
        },
        "impact": "Before masking a service, confirm nothing depends on it ('systemctl list-dependencies --reverse <unit>').",
        "generic": "Computers run many background programs (\"services\") all the time. This rule makes sure the important security ones are always running and the unneeded or risky ones are switched off, like keeping the alarm system armed while unplugging the appliances you don't use.",
    },
    {
        "id": "backup_recovery",
        "name": "Backup & Recovery",
        "short": "Supports recoverability of system and security-relevant data.",
        "match": r"backup|recovery|restore|system restore|shadow cop|volume shadow|\bDSRM\b|contingency",
        "attack": [("T1490", "Inhibit System Recovery"), ("T1486", "Data Encrypted for Impact")],
        "pro": "Backups are the last line of defense against ransomware and destructive attacks (CP-9 system backup, CP-10 recovery). Backup data and credentials must be protected at the same level as production (CP-9(8) cryptographic protection) and tested for restorability. Restricting who can back up and restore files matters because SeBackupPrivilege bypasses file ACLs.",
        "admin": {
            "windows": "On Windows, review the backup tooling and the 'Back up files and directories' and 'Restore files and directories' user rights (Administrators only). Protect the directory services restore mode (DSRM) password on DCs and the system state backups.",
            "linux": "On RHEL, verify the enterprise backup agent and schedules, and protect backup media and repositories with restrictive permissions and encryption.",
        },
        "impact": "Restricting backup privileges may require dedicated, monitored service accounts for the backup product.",
        "generic": "This helps make sure important data and settings can be restored if something goes wrong, whether that's a hardware failure, a mistake or a ransomware attack. It's like keeping a spare house key and copies of important documents somewhere safe.",
    },
    # Fallback - must stay last.
    {
        "id": "general_config",
        "name": "Secure Configuration Baseline",
        "short": "A general secure-configuration requirement of the baseline.",
        "match": r".",
        "attack": [],
        "pro": "This requirement is part of the secure configuration baseline (CM-6 configuration settings, with CM-7 least functionality where applicable). Individually it may close a narrow weakness. Collectively, baseline settings remove the default-insecure states that attackers rely on, and deviations must be documented and risk-accepted in the system's POA&M or as an approved exception.",
        "admin": {
            "linux": "Apply the change as described in the fix text, then confirm it with the check procedure. Where a setting can be set in several places (a main config file and drop-ins), check that no later file overrides it. Automate with the DISA/SCAP content or Ansible (RHEL System Roles / the DISA-provided Ansible and OpenSCAP 'stig' profile) to prevent drift.",
            "windows": "Apply the change through Group Policy where possible (the DISA STIG GPO package provides importable GPOs) rather than editing the registry by hand, so it is enforced and auditable. Confirm with the check procedure and 'gpresult /h'.",
        },
        "impact": "Test in a non-production environment first and record any functional impact. If the setting can't be applied, document the deviation and its mitigation with the ISSO.",
        "generic": "This is one of the many \"house rules\" that together make the computer harder to break into. On its own it might close only a small gap, but hundreds of small gaps closed together make a big difference, like checking every window in the house is shut, not just the front door.",
    },
]

TOPIC_BY_ID = {t["id"]: t for t in TOPICS}

# Title patterns that unambiguously determine the primary topic, checked before
# the ordered list (avoids e.g. "mount /var/log/audit nodev" landing in auditing).
FORCE: list[tuple[str, str]] = [
    (r"\bgpgcheck|signature|digitally signed|cryptographic(ally)? verif", "integrity"),
    (r"\buser right\b|\bright must only be assigned", "user_rights"),
    (r"\b(nodev|nosuid|noexec)\b|separate (file system|partition)", "filesystem_mounts"),
    (r"must not (have .*)?(be )?installed|must not have .* installed|(is|are) not installed", "software_minimization"),
    (r"protect\w* .*(audit|logon UIDs)|audit (tools|rules?|configuration) .*(unauthorized|protect|owned|mode)"
     r"|(audit|log) (log )?(file|files|directory|directories)s? .*(owned|group-owned|mode|permission)"
     r"|audit (log )?(directory|directories|files?) must|/etc/audit/?\"? must be (owned|group-owned)", "audit_protection"),
    (r"\bLDAP\b.*(signing|channel binding)|^domain controllers? must|Active Directory .*(object|audit|permission)", "domain_services"),
    (r"(prompt|prompted) .*(password|authenticat).*(wake|resume|sleep)|(wake|wakes|resume)s? from sleep"
     r"|smart card removal|removal (option|behavior)|lock-on-removal|when the smart card is removed", "session_lock"),
]
_FORCE = [(re.compile(rx, re.I), tid) for rx, tid in FORCE]
_COMPILED = [(t, re.compile(t["match"], re.I)) for t in TOPICS]


def classify(title: str, body: str, platform: str, limit: int = 2) -> list[str]:
    """Return up to `limit` topic ids, primary first."""
    hits: list[str] = []
    for rx, tid in _FORCE:
        if rx.search(title):
            hits.append(tid)
            break
    for topic, rx in _COMPILED:
        if topic["id"] == "general_config" or platform not in topic.get("platforms", (platform,)):
            continue
        if rx.search(title) and topic["id"] not in hits:
            hits.append(topic["id"])
        if len(hits) >= limit:
            break
    if "user_rights" in hits and "services" in hits:
        hits.remove("services")  # "Local Service"/"Network Service" are account names, not services
    if not hits:
        # Fallback: the fix text, minus command prefixes that mention sudo.
        body = re.sub(r"\$\s*sudo\s+", "$ ", body)
        for topic, rx in _COMPILED:
            if topic["id"] == "general_config" or platform not in topic.get("platforms", (platform,)):
                continue
            if rx.search(body):
                hits.append(topic["id"])
                break
    return hits or ["general_config"]


def topic_text(topic: dict, field: str, platform: str, family: str = "") -> str:
    """Topic text for an OS family (rhel/ubuntu/windows), falling back to the platform."""
    v = topic.get(field, "")
    if isinstance(v, dict):
        return v.get(family) or v.get(platform) or next(iter(v.values()), "")
    return v


# ---------------------------------------------------------------------------
# Plain-language glossary used in the Generic level.
# ---------------------------------------------------------------------------

GLOSSARY: list[tuple[str, str, str]] = [
    # (regex, term, plain definition)
    (r"\bSTIG", "STIG", "Security Technical Implementation Guide: DoD's official checklist of security settings for a product."),
    (r"\bCCI\b", "CCI", "Control Correlation Identifier: a DoD number that ties a specific setting back to a NIST security requirement."),
    (r"\bSSH\b|sshd", "SSH", "Secure Shell: an encrypted way to control a computer remotely by typing commands."),
    (r"\bFIPS", "FIPS 140", "A U.S. government standard for testing and approving encryption software."),
    (r"\bPAM\b|pam_", "PAM", "Pluggable Authentication Modules: the Linux component that checks passwords and other sign-in requirements."),
    (r"\bSSSD|sssd", "SSSD", "A Linux service that connects the computer to a central user directory and handles sign-ins."),
    (r"SELinux", "SELinux", "Security-Enhanced Linux: a strict rulebook that limits what each program is allowed to touch, even if it's running as an administrator."),
    (r"\baudit|auditd", "Audit log", "A tamper-resistant diary of security-relevant events on the computer."),
    (r"sysctl|kernel\.", "Kernel parameter", "A low-level switch that changes how the core of the operating system behaves."),
    (r"\bsudo", "sudo", "A Linux command that lets an approved user temporarily act with administrator power."),
    (r"\broot\b", "root", "The all-powerful administrator account on Linux."),
    (r"\bUAC\b|User Account Control", "UAC", "User Account Control: the Windows pop-up that asks for confirmation before something makes system-wide changes."),
    (r"\bSMB|server message block", "SMB", "Server Message Block: the protocol Windows uses for file and printer sharing."),
    (r"NTLM|LAN Manager", "NTLM / LAN Manager", "Older Windows sign-in methods that are weaker than modern Kerberos."),
    (r"Kerberos", "Kerberos", "The ticket-based sign-in system used by Windows domains and some Linux systems."),
    (r"BitLocker", "BitLocker", "Windows' built-in tool for encrypting the whole hard drive."),
    (r"\bTPM\b|Trusted Platform", "TPM", "Trusted Platform Module: a security chip on the motherboard that safely stores encryption keys."),
    (r"Group Policy|\bGPO", "Group Policy", "The central way Windows administrators push settings to many computers at once."),
    (r"registry|Registry", "Registry", "Windows' internal database of settings."),
    (r"\bRDP\b|Remote Desktop", "Remote Desktop (RDP)", "A way to see and control a Windows computer's screen from another computer."),
    (r"WinRM|Windows Remote Management", "WinRM", "A Windows service that lets administrators run commands on a computer over the network."),
    (r"PowerShell", "PowerShell", "A powerful Windows command-line and scripting tool."),
    (r"\bDEP\b|Data Execution Prevention", "DEP", "Data Execution Prevention: stops programs running code from memory areas meant only for data."),
    (r"\bASLR\b|address space layout", "ASLR", "Address Space Layout Randomization: shuffles where programs sit in memory so attacks are harder to aim."),
    (r"\bICMP", "ICMP", "Internet Control Message Protocol: network 'status' messages, such as the ones the ping command uses."),
    (r"IPv4|IPv6|\bIP\b", "IP", "Internet Protocol: the addressing system that routes data between computers."),
    (r"firewall", "Firewall", "A filter that decides which network connections are allowed in or out."),
    (r"\bAIDE\b", "AIDE", "Advanced Intrusion Detection Environment: a tool that detects changes to important files."),
    (r"\bgpg|GPG", "GPG signature", "A digital seal proving a software package really came from the vendor and wasn't altered."),
    (r"\bdconf|GNOME", "GNOME / dconf", "The Linux desktop environment and its settings database."),
    (r"\bGRUB|boot ?loader", "Boot loader (GRUB)", "The small program that starts the operating system when the computer powers on."),
    (r"\bUEFI|Secure Boot", "UEFI / Secure Boot", "Modern computer firmware and its feature that only lets trusted software start the computer."),
    (r"\bLDAP", "LDAP", "A protocol for looking up users and groups in a central directory."),
    (r"Active Directory|domain controller", "Active Directory", "Microsoft's central directory of users, computers and permissions for an organization."),
    (r"\bDoD\b|\bDoW\b", "DoD / DoW", "Department of Defense (renamed Department of War in recent DISA publications)."),
    (r"smart ?card|\bCAC\b|\bPIV\b", "Smart card / CAC", "A government ID card with a chip that is used, together with a PIN, to sign in."),
    (r"\bPKI\b|certificat", "PKI / certificates", "Public Key Infrastructure: the system of digital ID certificates and trusted issuers."),
    (r"\bNTP\b|chrony", "NTP / chrony", "Network Time Protocol: how computers keep their clocks accurate over the network."),
    (r"\bUSB", "USB", "The common plug used for thumb drives, keyboards and many other devices."),
    (r"fapolicyd|AppLocker|WDAC", "Application allowlisting", "Only programs on an approved list are allowed to run."),
    (r"\bumask", "umask", "The default permission setting given to newly created files."),
    (r"\bLSASS|\bLSA\b", "LSA / LSASS", "The Windows component that handles sign-ins and holds sign-in secrets in memory."),
    (r"telemetry", "Telemetry", "Usage and diagnostic data a product sends back to its maker."),
    (r"\bCAT I\b|\bCAT II\b|\bCAT III\b", "CAT I / II / III", "DISA's severity levels: CAT I is the most serious, CAT III the least."),
]
_GLOSSARY_RX = [(re.compile(rx), term, d) for rx, term, d in GLOSSARY]


def glossary_terms(text: str, limit: int = 4) -> list[dict]:
    out, seen = [], set()
    for rx, term, d in _GLOSSARY_RX:
        if term in seen:
            continue
        if rx.search(text):
            out.append({"term": term, "definition": d})
            seen.add(term)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Ubuntu-specific system administrator guidance. Topics not listed here use the
# generic "linux" text, which applies to both RHEL and Ubuntu.
# ---------------------------------------------------------------------------

UBUNTU_ADMIN: dict[str, str] = {
    "fips_crypto": "Ubuntu provides FIPS 140-validated modules through Ubuntu Pro: 'pro enable fips-updates' (or 'fips'), then reboot into the FIPS kernel. Verify with 'cat /proc/sys/crypto/fips_enabled' (expect 1). sshd ciphers, MACs and key exchange algorithms are set explicitly in /etc/ssh/sshd_config, because Ubuntu has no RHEL-style system-wide crypto-policies.",
    "account_lockout": "Ubuntu 22.04/24.04 use pam_faillock, configured in /etc/security/faillock.conf (deny, fail_interval, unlock_time, audit, silent, dir) and referenced from /etc/pam.d/common-auth (preauth/authfail lines) and common-account. Older releases used pam_tally2. Inspect with 'faillock --user <name>' and reset with 'faillock --user <name> --reset'.",
    "password_complexity": "Install libpam-pwquality ('apt-get install libpam-pwquality'), set minlen, dcredit/ucredit/lcredit/ocredit, difok, dictcheck and enforcing in /etc/security/pwquality.conf, and make sure /etc/pam.d/common-password calls pam_pwquality.so (with retry=3). Ubuntu manages the PAM stack with 'pam-auth-update'.",
    "credential_storage": "Ubuntu stores hashes in /etc/shadow. Set ENCRYPT_METHOD SHA512 in /etc/login.defs and make sure the pam_unix line in /etc/pam.d/common-password uses sha512 (with an appropriate rounds value). Existing hashes are only upgraded when users next change their passwords.",
    "privileged_accounts": "Lock the root password ('passwd -l root') so administrators work through sudo, set 'PermitRootLogin no' and 'PermitEmptyPasswords no' for sshd, and remove 'nullok' from pam_unix in /etc/pam.d/common-auth and common-password so empty passwords are rejected.",
    "software_minimization": "Remove packages with 'apt-get remove --purge <pkg>' (purge also deletes their configuration files) and verify with 'dpkg -l | grep <pkg>'. Check what else 'apt' plans to remove before confirming the transaction.",
    "patching": "Patch from approved repositories with 'apt-get update && apt-get upgrade' (or 'unattended-upgrades' for automatic security updates). Review pending updates with 'apt list --upgradable'. Check the release with 'lsb_release -a' against Canonical's support lifecycle; an Ubuntu Pro subscription extends security maintenance (ESM).",
    "integrity": "APT verifies repository signatures with the keys in /etc/apt/trusted.gpg.d/ and per-source 'signed-by' keyrings, so never add '[trusted=yes]' or '--allow-unauthenticated'. Install AIDE with 'apt-get install aide aide-common', initialize with 'aideinit', and configure rules in /etc/aide/aide.conf. A daily check runs from /etc/cron.daily/dailyaidecheck. 'dpkg --verify' checks installed files against package checksums.",
    "app_control": "Ubuntu uses AppArmor rather than SELinux. Make sure the apparmor package is installed and enabled ('systemctl enable --now apparmor'), and check loaded profiles and their modes with 'aa-status'. Put profiles into enforce mode with 'aa-enforce /etc/apparmor.d/<profile>'. Application allowlisting beyond AppArmor needs an approved third-party tool.",
    "file_permissions": "Check mode and ownership with 'stat -c \"%a %U %G %n\" <path>' and fix them with 'chmod', 'chown' and 'chgrp'. Find unowned files with 'find / -xdev -nouser -o -nogroup'. Default permissions for new files come from UMASK in /etc/login.defs. 'dpkg --verify' highlights packaged files that have changed.",
    "boot_security": "Create a GRUB superuser password hash with 'grub-mkpasswd-pbkdf2' and add 'set superusers=\"<name>\"' and 'password_pbkdf2 <name> <hash>' to /etc/grub.d/40_custom (or 00_header), then run 'update-grub'. Kernel parameters go in GRUB_CMDLINE_LINUX in /etc/default/grub, followed by 'update-grub'. Disable Ctrl-Alt-Delete with 'systemctl mask ctrl-alt-del.target' and 'systemctl daemon-reload'.",
    "memory_protection": "Set kernel tunables in /etc/sysctl.d/*.conf and apply them with 'sysctl --system'. Boot parameters are added to GRUB_CMDLINE_LINUX in /etc/default/grub, followed by 'update-grub' and a reboot. Disable core dumps through /etc/security/limits.conf ('* hard core 0') and /etc/systemd/coredump.conf.",
    "firewall": "Ubuntu uses UFW (Uncomplicated Firewall) as the front end to nftables or iptables. Install and enable it with 'apt-get install ufw' and 'ufw enable', set default-deny with 'ufw default deny incoming', and allow only the required services ('ufw allow <port>/<proto>', or 'ufw limit ssh' for rate limiting). Review with 'ufw status verbose'.",
    "pam_identity": "Ubuntu's PAM stacks are /etc/pam.d/common-auth, common-account, common-password and common-session. They are regenerated by 'pam-auth-update' from profiles in /usr/share/pam-configs/, so persistent changes belong in a custom profile there or must be re-checked after package updates. SSSD (if used) is configured in /etc/sssd/sssd.conf (mode 0600, owned by root).",
    "smartcard_pki": "Ubuntu uses libpam-pkcs11 and opensc-pkcs11 for CAC/PIV login: a pam_pkcs11.so line in /etc/pam.d/common-auth, certificate mapping and OCSP/CRL policy in /etc/pam_pkcs11/pam_pkcs11.conf, and DoD CA certificates installed under /etc/ssl/certs (or /usr/local/share/ca-certificates followed by 'update-ca-certificates').",
    "logon_interface": "On Ubuntu, GDM3 settings live in /etc/gdm3/ (for example 'AutomaticLoginEnable=false' in /etc/gdm3/custom.conf), and GNOME policy is managed through dconf databases in /etc/dconf/db/local.d/ with locks, followed by 'dconf update'. If no GUI is required, remove the desktop packages and set 'systemctl set-default multi-user.target'.",
    "session_lock": "Set GNOME locking through dconf (org/gnome/desktop/screensaver lock-enabled=true, org/gnome/desktop/session idle-delay=uint32 900) with matching locks, followed by 'dconf update'. For console sessions, install 'vlock' so users can lock a terminal, and set TMOUT=900 (readonly) in /etc/profile.d/. SSH idle termination uses ClientAliveInterval/CountMax.",
    "audit_storage": "auditd capacity and failure behavior are set in /etc/audit/auditd.conf (space_left, space_left_action, disk_full_action, action_mail_acct). Off-load with audisp-remote (package audispd-plugins, configured in /etc/audit/audisp-remote.conf or plugins.d/au-remote.conf) or forward with rsyslog. Install auditd with 'apt-get install auditd audispd-plugins'.",
    "removable_media": "Block USB storage with 'install usb-storage /bin/false' and 'blacklist usb-storage' in /etc/modprobe.d/*.conf, and check with 'modprobe -n -v usb-storage'. Disable wireless interfaces with 'nmcli radio all off' or by blacklisting their driver modules. USBGuard is available from the Ubuntu archive ('apt-get install usbguard').",
    "disk_encryption": "Ubuntu uses LUKS (dm-crypt) for block-device encryption, normally chosen at install time ('Encrypt the new Ubuntu installation'). Retrofitting encryption to an existing root volume generally requires a rebuild. Verify with 'lsblk -f' or 'cryptsetup status <mapping>'.",
    "ssh": "sshd reads /etc/ssh/sshd_config and, on 22.04 and later, drop-ins in /etc/ssh/sshd_config.d/*.conf, which are included at the top of the main file so their values take precedence (first value wins). Validate with 'sshd -t', check the effective configuration with 'sshd -T | grep -i <keyword>', then 'systemctl reload ssh' (the unit is named 'ssh' on Ubuntu).",
    "time_sync": "Ubuntu uses chrony (or systemd-timesyncd by default on some releases). For chrony, configure /etc/chrony/chrony.conf with 'server <DoD-time-source> iburst maxpoll 16' and 'makestep 1 -1', and disable systemd-timesyncd so the two don't conflict. Verify with 'chronyc sources -v' and 'timedatectl'.",
    "privacy_cloud": "On Ubuntu, the equivalents are disabling Apport crash reporting ('systemctl disable --now apport'), the 'ubuntu-report' and popularity-contest data collection, MOTD news ('ENABLED=0' in /etc/default/motd-news), and GNOME online accounts if they're not approved.",
    "general_config": "Apply the change as described in the fix text, then confirm it with the check procedure. Where a setting can be set in several places (a main config file and drop-ins), check that no later file overrides it. Automate with the DISA SCAP content or Ubuntu Security Guide ('usg fix disa_stig', available with Ubuntu Pro) to prevent drift.",
}

# Topics whose Linux guidance applies to Ubuntu unchanged except for the OS name.
_SAME_ON_UBUNTU = ["banner", "password_lifecycle", "account_management", "smb_anonymous", "elevation",
                   "audit_protection", "audit_events", "network_stack", "filesystem_mounts", "services",
                   "backup_recovery", "antimalware", "remote_access"]

for _tid, _txt in UBUNTU_ADMIN.items():
    _t = TOPIC_BY_ID[_tid]
    if not isinstance(_t["admin"], dict):
        _t["admin"] = {"linux": _t["admin"], "windows": _t["admin"]}
    _t["admin"]["ubuntu"] = _txt

for _tid in _SAME_ON_UBUNTU:
    _t = TOPIC_BY_ID[_tid]
    _t["admin"]["ubuntu"] = re.sub(r"\bOn RHEL\b", "On Ubuntu", _t["admin"]["linux"])

# The generic Linux text above is RHEL-specific; expose it under "rhel" too so
# lookups by OS family find it (Ubuntu topics without an override fall back to "linux").
for _t in TOPICS:
    if isinstance(_t["admin"], dict) and "linux" in _t["admin"]:
        _t["admin"].setdefault("rhel", _t["admin"]["linux"])
