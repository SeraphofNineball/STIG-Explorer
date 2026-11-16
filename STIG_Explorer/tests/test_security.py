"""Regression tests for security fixes made after the November 2026 review."""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from stig_explorer import build, fetch, parse, server


@unittest.skipUnless(shutil.which("node"), "Node.js is required for export-security tests")
class ScriptSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.web = build.ROOT / "web"

    def run_node(self, js: str) -> str:
        result = subprocess.run(["node", "-e", js, str(self.web)], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return result.stdout

    def test_allowlist_rejects_modifying_or_ambiguous_commands(self):
        self.run_node(r'''
const assert=require('node:assert/strict');
const S=require(process.argv[1]+'/scripts.js');
const ok=(shell,cmd)=>S.approvedCommand({shell,cmd});
assert.equal(ok('bash','sysctl kernel.randomize_va_space'), true);
assert.equal(ok('bash','sudo rpm -q openssh-server'), true);
assert.equal(ok('bash','systemctl is-enabled auditd'), true);
assert.equal(ok('bash','sudo cut -d: -f1,2 /etc/shadow'), false);
for (const cmd of ['touch /tmp/altered','sysctl -w kernel.randomize_va_space=0',
  'sysctl kernel.randomize_va_space; id', 'sysctl kernel.randomize_va_space\nid',
  'sudo rpm -q openssh-server$(id)', 'rm -rf /tmp/check', 'logger check',
  'sysctl kernel.randomize_va_space > /tmp/altered', 'sysctl kernel.randomize_va_space`id`',
  'sysctl kernel.randomize_va_space\u2028id', 'sudo grep root /etc/gshadow',
  'sysctl kernel.randomize_va_space\nSTIGX_EOF\nid']) assert.equal(ok('bash',cmd),false,cmd);
assert.equal(ok('powershell',"Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE' -Name 'UseTPMPIN' | Select-Object -ExpandProperty 'UseTPMPIN'"),true);
assert.equal(ok('powershell','Confirm-SecureBootUEFI'),true);
for (const cmd of ["Set-Content -Path C:\\marker -Value 1",'Get-ItemProperty; Remove-Item C:\\',
  'Get-Tpm; Start-Process calc.exe', 'Get-Tpm\nRemove-Item C:\\'])
  assert.equal(ok('powershell',cmd),false,cmd);
assert.equal(ok('cmd','auditpol /get /subcategory:"Credential Validation"'),true);
assert.equal(ok('cmd','reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE" /v "UseTPMPIN"'),true);
assert.equal(ok('cmd','reg query "HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE" /v "UseTPMPIN" & del C:\\x'),false);
''')

    def test_untrusted_header_and_heredoc_payloads_remain_data(self):
        output = self.run_node(r'''
const assert=require('node:assert/strict');
const S=require(process.argv[1]+'/scripts.js');
const meta={version:'1.0\nid\n#',generated:'today\n#>\nid'};
const base={platform:'linux',stig:'RHEL_9',vuln_id:'V-999',stig_id:'RHEL-999',
 severity:'low',title:'Example',validate:[{shell:'bash',cmd:'sysctl kernel.randomize_va_space',expect:'1'},
 {shell:'bash',cmd:'echo OK\nSTIGX_EOF\nid',expect:'no'}]};
const sh=S.bash([base],meta,'grep\nid\n#');
assert(sh.includes('check '));
assert(!sh.includes("<<'STIGX_EOF'"));
assert(!sh.split('\n').some(x=>/^id$/.test(x)));
assert(sh.includes('# Filter: grep id #'));
const win={...base,platform:'windows',stig:'WIN_11',validate:[{shell:'powershell',cmd:'Confirm-SecureBootUEFI',expect:'True'},
 {shell:'powershell',cmd:'Set-Content C:\\marker X\n#>\nid',expect:''}]};
const ps=S.powershell([win],meta,'hello\n#>\nid');
assert.equal((ps.match(/#>/g)||[]).length,2); // only the intended two block comment closings
assert(ps.includes('Filter: hello # > id'));
assert(!ps.includes('Set-Content C:\\marker X\n#>'));
const csv=require(process.argv[1]+'/security.js');
for(const s of ['=1+1','\t+SUM(1,2)','\r\n@SUM(A1)',' -3','\u0000=HYPERLINK("a")'])
  assert(csv.csvCell(s).startsWith('"\''),s);
assert.equal(csv.csvCell('ordinary, "quoted"'), '"ordinary, ""quoted"""');
process.stdout.write(sh);
''')
        with tempfile.TemporaryDirectory() as td:
            shell_file = Path(td) / "safe_export.sh"
            shell_file.write_text(output)
            subprocess.run(["bash", "-n", str(shell_file)], check=True)

    def test_shipped_shadow_checks_are_manual_only(self):
        self.run_node(r'''
const assert=require('node:assert/strict');
const fs=require('fs');const src=fs.readFileSync(process.argv[1]+'/data/stig_data.js','utf8');
const D=JSON.parse(src.slice(src.indexOf('{'),src.lastIndexOf('}')+1));
const S=require(process.argv[1]+'/scripts.js');
const matched=[];
for(const r of D.rules){
  const p=S.pick(r,r.platform);
  for(const v of p.runnable) assert(S.approvedCommand(v),v.cmd);
  for(const v of p.runnable) assert(!/\/etc\/shadow|\/etc\/gshadow/i.test(v.cmd),v.cmd);
  if((r.validate||[]).some(v=>/cut\s+-d\s*:\s+-f1,2\s+\/etc\/shadow/.test(v.cmd))){
    matched.push(r.vuln_id);
    assert(!p.runnable.some(v=>/\/etc\/shadow/.test(v.cmd)));
  }
}
assert.deepEqual(matched.sort(),['V-230232','V-258231','V-281221']);
''')


class ArchiveSecurityTests(unittest.TestCase):
    def test_bomb_is_rejected_without_decompressing(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.xml", b"A" * 600_000)
        with zipfile.ZipFile(io.BytesIO(data.getvalue())) as zf:
            with self.assertRaisesRegex(ValueError, "compression ratio"):
                list(parse._iter_zip(zf))

    def test_nested_depth_is_bounded(self):
        blob = b"<root />"
        for _ in range(parse.MAX_NESTED_ZIP_DEPTH + 2):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("nested.zip", blob)
            blob = buf.getvalue()
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td) / "archive.zip"
            archive.write_bytes(blob)
            with self.assertRaisesRegex(ValueError, "depth limit"):
                list(parse.iter_xml_blobs(archive))

    def test_xml_bytes_and_cumulative_count_are_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            (folder / "one.xml").write_bytes(b"a" * 25)
            with mock.patch.object(parse, "MAX_XML_BYTES", 20):
                with self.assertRaisesRegex(ValueError, "exceeds"):
                    list(parse.iter_xml_blobs(folder))
            (folder / "one.xml").write_bytes(b"<a/>")
            (folder / "two.xml").write_bytes(b"<b/>")
            with mock.patch.object(parse, "MAX_XML_FILES", 1):
                with self.assertRaisesRegex(ValueError, "file-count"):
                    list(parse.iter_xml_blobs(folder))

    def test_xml_rejects_entities_and_invalid_identifiers(self):
        with self.assertRaisesRegex(ValueError, "DTD"):
            parse.parse_cci_list(b'<!DOCTYPE root [<!ENTITY x "secret">]><root>&x;</root>')
        template = '''<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="bench">
<title>Red Hat Enterprise Linux 9 Security Technical Implementation Guide</title>
<Group id="{group}"><Rule id="rule-1" severity="{severity}">
<version>RHEL-09-000001</version><title>Test</title></Rule></Group></Benchmark>'''
        parse.parse_benchmark(template.format(group="V-200", severity="high").encode())
        with self.assertRaisesRegex(ValueError, "Invalid Group ID"):
            parse.parse_benchmark(template.format(group="bad&amp;quot; onclick=bad", severity="high").encode())
        with self.assertRaisesRegex(ValueError, "Unrecognized STIG severity"):
            parse.parse_benchmark(template.format(group="V-200", severity="bad&quot; onclick=bad").encode())


class ApiSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.idx = server.Index(build.load())

    def test_search_input_bounds(self):
        for params in ({"q": "a" * (server.MAX_QUERY_LENGTH + 1)},
                       {"tag": "x" * (server.MAX_FILTER_LENGTH + 1)},
                       {"offset": "100001"}):
            with self.assertRaises(ValueError):
                self.idx.search(params)
        self.assertGreater(self.idx.search({"q": "restrictanonymous"})["total"], 0)

    def test_rate_limiter(self):
        limiter = server.RateLimiter()
        ip = "test-client"
        for _ in range(server.RATE_LIMIT_PER_MINUTE):
            self.assertTrue(limiter.allow(ip))
        self.assertFalse(limiter.allow(ip))
        self.assertTrue(limiter.allow("another-client"))


class DownloadSecurityTests(unittest.TestCase):
    class FakeResponse(io.BytesIO):
        def __init__(self, data):
            super().__init__(data)
            self.headers = {"Content-Length": str(len(data))}

    def test_atomic_bounded_download_and_recorded_digest(self):
        payload = b"test ZIP bytes"
        with tempfile.TemporaryDirectory() as td:
            target = Path(td)
            with mock.patch.object(fetch.urllib.request, "urlopen", return_value=self.FakeResponse(payload)):
                out = fetch.download("test.zip", target, hashlib.sha256(payload).hexdigest())
            self.assertEqual(out.read_bytes(), payload)
            self.assertIn(hashlib.sha256(payload).hexdigest(), (target / "test.zip.sha256").read_text())
            self.assertFalse((target / "test.zip.part").exists())
            with mock.patch.object(fetch.urllib.request, "urlopen", return_value=self.FakeResponse(payload)):
                with self.assertRaisesRegex(ValueError, "verification failed"):
                    fetch.download("test.zip", target, "0" * 64)
            self.assertEqual(out.read_bytes(), payload)
            with mock.patch.object(fetch.urllib.request, "urlopen", return_value=self.FakeResponse(payload)):
                with mock.patch.object(fetch, "MAX_DOWNLOAD_BYTES", 5):
                    with self.assertRaisesRegex(ValueError, "maximum"):
                        fetch.download("too_large.zip", target)
            self.assertFalse((target / "too_large.zip.part").exists())
            with self.assertRaisesRegex(ValueError, "Unsafe download filename"):
                fetch.download("../bad.zip", target)


if __name__ == "__main__":
    unittest.main()
