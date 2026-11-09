#!/usr/bin/env python3
"""Testes do script de triagem SOC.

Executar:
    python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "06-soc-triage.py"


def load_module():
    spec = importlib.util.spec_from_file_location("soc_triage", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("não foi possível carregar 06-soc-triage.py")
    module = importlib.util.module_from_spec(spec)
    # Necessário para dataclasses resolverem o módulo em Python 3.14+.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SocTriageTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for directory in ("ftp", "smb", "dvwa", "nmap"):
            (self.root / directory).mkdir()

        (self.root / "ftp" / "02-ftp-medusa.log").write_text(
            "# Medusa v.2.3\n"
            "2026-11-09 18:03:50 ACCOUNT FOUND: [ftp] Host: 192.168.56.102 "
            "User: msfadmin Password: msfadmin [SUCCESS]\n",
            encoding="utf-8",
        )
        (self.root / "smb" / "04-smb-spray.log").write_text(
            "2026-11-09 18:03:57 ACCOUNT FOUND: [smbnt] Host: 192.168.56.102 "
            "User: msfadmin Password: msfadmin [SUCCESS (ADMIN$ - Access Allowed)]\n",
            encoding="utf-8",
        )
        (self.root / "smb" / "04-smb-brute.log").write_text(
            "2026-11-09 18:03:57 ACCOUNT FOUND: [smbnt] Host: 192.168.56.102 "
            "User: msfadmin Password: msfadmin [SUCCESS (ADMIN$ - Access Allowed)]\n",
            encoding="utf-8",
        )
        (self.root / "dvwa" / "05-dvwa-medusa.log").write_text(
            "2026-11-09 18:06:46 ACCOUNT FOUND: [web-form] Host: 192.168.56.102 "
            "User: admin Password: password [SUCCESS]\n",
            encoding="utf-8",
        )
        (self.root / "nmap" / "01-nmap-servicos.txt").write_text(
            "21/tcp open ftp vsftpd 2.3.4\n"
            "445/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)\n",
            encoding="utf-8",
        )
        (self.root / "smb" / "03-smb-users.txt").write_text(
            "msfadmin\nuser\nroot\n", encoding="utf-8"
        )
        (self.root / "smb" / "03-smb-shares.txt").write_text(
            "Sharename       Type      Comment\n"
            "---------       ----      -------\n"
            "tmp             Disk      oh noes!\n"
            "ADMIN$          IPC       IPC Service\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_redact_default(self):
        self.assertEqual(self.module.redact("msfadmin", False), "<redacted>")

    def test_redact_explicit_lab_mode(self):
        self.assertEqual(self.module.redact("msfadmin", True), "msfadmin")

    def test_parse_ftp_finding(self):
        findings = self.module.parse_medusa(
            self.root / "ftp" / "02-ftp-medusa.log", self.root, False
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.user, "msfadmin")
        self.assertEqual(finding.password, "<redacted>")
        self.assertEqual(finding.service, "FTP")
        self.assertEqual(finding.severity, "high")
        self.assertIn("T1110.001", finding.mitre)
        self.assertIn("T1078", finding.mitre)

    def test_parse_spray_finding_is_critical(self):
        findings = self.module.parse_medusa(
            self.root / "smb" / "04-smb-spray.log", self.root, False
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.technique, "Password spraying")
        self.assertEqual(finding.severity, "critical")
        self.assertIn("T1110.003", finding.mitre)

    def test_parse_nmap_risk(self):
        services = self.module.parse_nmap(self.root / "nmap" / "01-nmap-servicos.txt")
        self.assertEqual(len(services), 2)
        self.assertEqual(services[0]["port"], 21)
        self.assertIn("CVE-2011-2523", services[0]["risk"])

    def test_parse_enumeration(self):
        enumeration = self.module.parse_enumeration(self.root)
        self.assertEqual(enumeration["users_count"], 3)
        self.assertEqual(enumeration["shares"], ["tmp", "ADMIN$"])

    def test_integration_generates_safe_reports(self):
        out = self.root / "reports"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--source",
                str(self.root),
                "--out",
                str(out),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((out / "soc-triage.md").exists())
        self.assertTrue((out / "soc-triage.json").exists())
        self.assertTrue((out / "ai-triage-prompt.md").exists())

        payload = json.loads((out / "soc-triage.json").read_text(encoding="utf-8"))
        self.assertEqual(len(payload["findings"]), 4)
        self.assertTrue(all(f["password"] == "<redacted>" for f in payload["findings"]))

        markdown = (out / "soc-triage.md").read_text(encoding="utf-8")
        prompt = (out / "ai-triage-prompt.md").read_text(encoding="utf-8")
        self.assertNotIn("Password: msfadmin", markdown)
        self.assertNotIn("Password: msfadmin", prompt)
        self.assertIn("T1110.001", markdown)
        self.assertIn("T1110.003", markdown)


if __name__ == "__main__":
    unittest.main()
