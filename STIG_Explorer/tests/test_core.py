"""Unit tests for STIG Explorer parsing, extraction, classification and search.

Run from STIG_Explorer/:  python -m unittest discover -s tests
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from stig_explorer import build, explain, settings, topics  # noqa: E402

WIN_RULE = {
    "check": """If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymous

Value Type: REG_DWORD
Value: 0x00000001 (1)""",
    "fix": 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> '
           'Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM '
           'accounts and shares" to "Enabled".',
}

UR_RULE = {
    "check": "",
    "fix": "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> "
           "Local Policies >> User Rights Assignment >> Add workstations to domain to include only the following "
           "accounts or groups:\n\n- Administrators",
}

LINUX_RULE = {
    "check": "$ sudo sysctl kernel.unprivileged_bpf_disabled",
    "fix": """Configure RHEL 9 to prevent privilege escalation through the kernel by disabling access to the bpf system call.

Create the drop-in file if it does not already exist:

$ sudo vi /etc/sysctl.d/99-kernel_unprivileged_bpf_disabled.conf

Add the following line to the file:
kernel.unprivileged_bpf_disabled = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system""",
}

AIDE_RULE = {
    "check": "",
    "fix": """Install AIDE, initialize it, and perform a manual check.

$ sudo dnf install aide

$ sudo /usr/sbin/aide --init
Example output:

Start timestamp: 2026-07-13 11:49:19 -0400 (AIDE 0.19.2)
New AIDE database written to /var/lib/aide/aide.db.new.gz
 SHA256    : StfQ7hBYTf83ZEBRy7I+ufhA4Ewhdpsg""",
}


class SettingsTests(unittest.TestCase):
    def test_registry_and_gpo(self):
        s = settings.extract(WIN_RULE, "windows")
        reg = [x for x in s if x["type"] == "registry"]
        gpo = [x for x in s if x["type"] == "gpo"]
        self.assertEqual(reg[0]["target"], "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa")
        self.assertEqual(reg[0]["name"], "RestrictAnonymous")
        self.assertIn("REG_DWORD", reg[0]["value"])
        self.assertTrue(gpo[0]["name"].startswith("Network access: Do not allow anonymous"))
        self.assertEqual(gpo[0]["value"], '"Enabled"')

    def test_user_rights_members(self):
        gpo = settings.extract(UR_RULE, "windows")[0]
        self.assertEqual(gpo["name"], "Add workstations to domain")
        self.assertEqual(gpo["value"], "Only: Administrators")

    def test_sysctl(self):
        s = settings.extract(LINUX_RULE, "linux")
        sc = [x for x in s if x["type"] == "sysctl"]
        self.assertEqual(sc[0]["name"], "kernel.unprivileged_bpf_disabled")
        self.assertEqual(sc[0]["value"], "1")
        self.assertTrue(sc[0]["target"].startswith("/etc/sysctl.d/"))

    def test_example_output_ignored(self):
        s = settings.extract(AIDE_RULE, "linux")
        self.assertIn({"type": "package", "target": "dnf", "name": "aide", "value": "Installed"}, s)
        self.assertFalse([x for x in s if x["type"] == "config"], s)


class Rhel7FormatTests(unittest.TestCase):
    def test_root_prompt_commands(self):
        rule = {"check": "", "fix": "Install the package:\n\n     # yum install aide\n\n"
                "Edit the file:\n\n     # Set this to true to lock the screen\n     lock-enabled=true\n\n"
                "# systemctl enable --now auditd"}
        s = settings.extract(rule, "linux")
        self.assertIn({"type": "package", "target": "yum", "name": "aide", "value": "Installed"}, s)
        self.assertTrue(any(x["type"] == "service" and x["name"] == "auditd" for x in s))
        self.assertFalse(any(x["name"].startswith("Set this") for x in s))

    def test_versionless_title(self):
        self.assertEqual(explain.plain_title("The Red Hat Enterprise Linux operating system must audit all uses "
                                             "of the semanage command."),
                         "This computer must audit all uses of the semanage command.")

    def test_root_prompt_check_commands(self):
        self.assertEqual(explain.check_commands("Check with:\n\n# grep -i maxpoll /etc/ntp.conf\n# This is prose"),
                         ["grep -i maxpoll /etc/ntp.conf"])


class TopicTests(unittest.TestCase):
    def cls(self, title, platform="linux"):
        return topics.classify(title, "", platform)

    def test_primary_topics(self):
        self.assertEqual(self.cls("RHEL 9 must audit all uses of the chmod command.")[0], "audit_events")
        self.assertEqual(self.cls("RHEL 8 must mount /var/log/audit with the nodev option.")[0], "filesystem_mounts")
        self.assertEqual(self.cls("RHEL 9 audit tools must be owned by root.")[0], "audit_protection")
        self.assertEqual(self.cls("The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.",
                                  "windows")[0], "smb_anonymous")
        self.assertEqual(self.cls('The "Profile single process" user right must only be assigned to the '
                                  'Administrators group.', "windows")[0], "user_rights")
        self.assertEqual(self.cls("RHEL 9 must not have the telnet-server package installed.")[0],
                         "software_minimization")

    def test_fallback(self):
        self.assertEqual(topics.classify("Something entirely unrelated.", "", "linux"), ["general_config"])

    def test_every_topic_has_three_levels(self):
        for t in topics.TOPICS:
            for f in ("pro", "admin", "generic", "impact", "name", "short"):
                self.assertTrue(t.get(f), f"{t['id']} missing {f}")


class ExplainTests(unittest.TestCase):
    def test_plain_title(self):
        self.assertEqual(explain.plain_title("RHEL 9 must disable core dumps for all users."),
                         "This computer must disable core dumps for all users.")
        self.assertEqual(explain.plain_title("Windows Server 2022 password history must be configured to 24 passwords "
                                             "remembered."),
                         "This computer's password history must be configured to 24 passwords remembered.")
        self.assertEqual(explain.plain_title("A separate RHEL 8 filesystem must be used for /home."),
                         "A separate filesystem must be used for /home.")


@unittest.skipUnless(build.OUT.exists(), "data file not built")
class DataAndSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from stig_explorer import server
        cls.data = build.load()
        cls.idx = server.Index(cls.data)

    def test_data_integrity(self):
        d = self.data
        self.assertGreater(len(d["rules"]), 1000)
        for r in d["rules"]:
            self.assertIn(r["stig"], {s["key"] for s in d["stigs"]})
            for t in r["topics"]:
                self.assertIn(t, d["topics"])
            for c in r["ccis"]:
                self.assertIn(c, d["ccis"])

    def test_search_and_lookup(self):
        res = self.idx.search({"q": "RestrictAnonymous"})
        self.assertGreater(res["total"], 0)
        r = self.idx.rule(res["results"][0]["stig_id"])
        self.assertIsNotNone(r)

    def test_nist_prefix_is_exact(self):
        ids = self.idx.search({"nist": "AC-1", "limit": 500})
        for row in ids["results"]:
            rule = self.idx.rules[row["id"]]
            self.assertTrue(any(i.replace(" ", "").startswith("AC-1") and not i.replace(" ", "")[4:5].isdigit()
                                for i in rule["nist"]["rev5"]))

    def test_fts_injection_is_safe(self):
        res = self.idx.search({"q": 'ssh" OR * NEAR( ) :'})
        self.assertNotIn("error", res)


if __name__ == "__main__":
    unittest.main()


class ValidationTests(unittest.TestCase):
    def test_registry_commands(self):
        from stig_explorer import validate
        rule = dict(WIN_RULE, title="Anonymous enumeration of shares must be restricted.", platform="windows")
        rule["settings"] = settings.extract(rule, "windows")
        cmds = validate.commands(rule, "windows", "WIN_11", [])
        text = "\n".join(c["cmd"] for c in cmds)
        self.assertIn('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v "RestrictAnonymous"', text)
        self.assertIn("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'", text)

    def test_user_right_uses_secedit_constant(self):
        from stig_explorer import validate
        rule = dict(UR_RULE, title="Add workstations to domain user right.", platform="windows")
        rule["settings"] = settings.extract(rule, "windows")
        cmds = validate.commands(rule, "windows", "WIN_SERVER_2022", [])
        self.assertTrue(any("SeMachineAccountPrivilege" in c["cmd"] for c in cmds))

    def test_audit_policy_uses_auditpol(self):
        from stig_explorer import validate
        rule = {"title": "Audit logon failures.", "platform": "windows", "check": "",
                "fix": "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> "
                       "Advanced Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> Audit Logon "
                       'with "Failure" selected.'}
        rule["settings"] = settings.extract(rule, "windows")
        cmds = validate.commands(rule, "windows", "WIN_11", [])
        self.assertEqual(cmds[0]["cmd"], 'auditpol /get /subcategory:"Logon"')
        self.assertIn("Failure", cmds[0]["expect"])

    def test_linux_sysctl_and_package(self):
        from stig_explorer import validate
        rule = dict(LINUX_RULE, title="x", platform="linux")
        rule["settings"] = settings.extract(rule, "linux")
        cmds = [c["cmd"] for c in validate.commands(rule, "rhel", "RHEL_9", [])]
        self.assertIn("sysctl kernel.unprivileged_bpf_disabled", cmds)
        pkg = {"title": "x", "platform": "linux", "check": "", "fix": "$ sudo apt-get install aide",
               "settings": [{"type": "package", "target": "apt", "name": "aide", "value": "Installed"}]}
        self.assertTrue(validate.commands(pkg, "ubuntu", "UBUNTU_22_04", [])[0]["cmd"].startswith("dpkg -l aide"))

    def test_curated_windows(self):
        from stig_explorer import validate
        self.assertEqual(validate.windows_curated("Windows Server 2022 must have Secure Boot enabled.")[0]["cmd"],
                         "Confirm-SecureBootUEFI")


class RoleAndUbuntuTests(unittest.TestCase):
    def test_server_role(self):
        self.assertEqual(build.server_role({"stig_id": "WN22-DC-000010", "check": ""}), "dc")
        self.assertEqual(build.server_role({"stig_id": "WN22-MS-000010", "check": ""}), "ms")
        self.assertEqual(build.server_role({"stig_id": "WN22-SO-000010", "check": ""}), "both")

    def test_ubuntu_key_and_title(self):
        from stig_explorer import parse
        self.assertEqual(parse.stig_key("x", "Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide"),
                         "UBUNTU_22_04")
        self.assertEqual(parse.family_of("Canonical Ubuntu 22.04 LTS"), "ubuntu")
        self.assertEqual(explain.plain_title("Ubuntu 22.04 LTS must enforce a minimum 15-character password length."),
                         "This computer must enforce a minimum 15-character password length.")

    def test_ubuntu_admin_text(self):
        t = topics.TOPIC_BY_ID["firewall"]
        self.assertIn("UFW", topics.topic_text(t, "admin", "linux", "ubuntu"))
        self.assertIn("firewalld", topics.topic_text(t, "admin", "linux", "rhel"))
