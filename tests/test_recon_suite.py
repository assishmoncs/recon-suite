"""
tests/test_recon_suite.py

Comprehensive unit and end-to-end integration test suite for Recon Suite v3.0.
Runs completely offline using unittest.mock so it succeeds deterministically
in any CI or sandboxed environment.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import main
from modules import dns_bruteforce, http_probe, report, subdomains, utils


class TestUtilsValidation(unittest.TestCase):
    """Test RFC domain validation, strict subdomain boundary matching, and IP parsing."""

    def test_validate_domain_accepts_valid_domains(self) -> None:
        self.assertTrue(utils.validate_domain("example.com"))
        self.assertTrue(utils.validate_domain("sub.api.example.co.uk"))
        self.assertTrue(utils.validate_domain("  EXAMPLE-123.ORG  "))

    def test_validate_domain_rejects_invalid_domains(self) -> None:
        self.assertFalse(utils.validate_domain(""))
        self.assertFalse(utils.validate_domain("localhost"))
        self.assertFalse(utils.validate_domain("-example.com"))
        self.assertFalse(utils.validate_domain("example-.com"))
        self.assertFalse(utils.validate_domain("http://example.com"))
        self.assertFalse(utils.validate_domain("a" * 255 + ".com"))

    def test_is_valid_subdomain_fixes_suffix_boundary_bug(self) -> None:
        # True subdomains and root domain must pass
        self.assertTrue(utils.is_valid_subdomain("api.example.com", "example.com"))
        self.assertTrue(utils.is_valid_subdomain("*.dev.example.com", "example.com"))
        self.assertTrue(utils.is_valid_subdomain("example.com", "example.com"))

        # Suffix lookalikes (the v2 bug!) must be strictly rejected
        self.assertFalse(utils.is_valid_subdomain("badexample.com", "example.com"))
        self.assertFalse(utils.is_valid_subdomain("sub.notexample.com", "example.com"))
        self.assertFalse(utils.is_valid_subdomain("evil.com", "example.com"))

    def test_parse_nameservers(self) -> None:
        self.assertEqual(utils.parse_nameservers(None), [])
        self.assertEqual(
            utils.parse_nameservers("1.1.1.1, 8.8.8.8, 2606:4700:4700::1111"),
            ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"],
        )
        with self.assertRaises(ValueError):
            utils.parse_nameservers("1.1.1.1,not-an-ip")


class TestPassiveEnumeration(unittest.TestCase):
    """Test concurrent OSINT aggregation, boundary filtering, and source provenance."""

    @mock.patch("modules.subdomains._certspotter_lookup")
    @mock.patch("modules.subdomains._urlscan_lookup")
    @mock.patch("modules.subdomains._hackertarget_lookup")
    @mock.patch("modules.subdomains._alienvault_otx_lookup")
    @mock.patch("modules.subdomains._crtsh_lookup")
    def test_aggregate_passive_sources_tracks_provenance_per_host(
        self,
        mock_crt: mock.MagicMock,
        mock_otx: mock.MagicMock,
        mock_ht: mock.MagicMock,
        mock_urlscan: mock.MagicMock,
        mock_cs: mock.MagicMock,
    ) -> None:
        mock_crt.return_value = ["api.example.com", "portal.example.com"]
        mock_otx.return_value = ["api.example.com", "vpn.example.com"]
        mock_ht.return_value = []
        mock_urlscan.return_value = ["docs.example.com"]
        mock_cs.return_value = ["api.example.com"]

        source_map, label = subdomains._aggregate_passive_sources_detailed("example.com")
        self.assertEqual(
            source_map["api.example.com"],
            ["crt.sh", "AlienVault OTX", "CertSpotter"],
        )
        self.assertEqual(source_map["portal.example.com"], ["crt.sh"])
        self.assertEqual(source_map["vpn.example.com"], ["AlienVault OTX"])
        self.assertEqual(source_map["docs.example.com"], ["URLScan.io"])
        self.assertIn("crt.sh", label)
        self.assertIn("AlienVault OTX", label)
        self.assertIn("URLScan.io", label)

    @mock.patch("modules.subdomains.requests.get")
    def test_crtsh_lookup_filters_out_suffix_lookalike_domains(
        self, mock_get: mock.MagicMock
    ) -> None:
        mock_resp = mock.MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = [
            {"name_value": "*.api.example.com\nmail.example.com"},
            {"name_value": "fakeexample.com\nsub.badexample.com"},
        ]
        mock_get.return_value = mock_resp

        results = subdomains._crtsh_lookup("example.com")
        self.assertEqual(results, ["api.example.com", "mail.example.com"])


class TestDnsBruteforceAndHygiene(unittest.TestCase):
    """Test wildcard filtering, dangling CNAME detection, and unified enrichment."""

    def test_wordlist_fallbacks_for_missing_and_invalid_encoding(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_path = Path(tmpdir) / "does_not_exist.txt"
            self.assertEqual(
                dns_bruteforce._load_wordlist(missing_path),
                dns_bruteforce._DEFAULT_WORDS,
            )

            bad_enc_path = Path(tmpdir) / "bad.txt"
            bad_enc_path.write_bytes(b"\xff\xfe\x00\x00invalid-utf8")
            self.assertEqual(
                dns_bruteforce._load_wordlist(bad_enc_path),
                dns_bruteforce._DEFAULT_WORDS,
            )

    @mock.patch("modules.dns_bruteforce._resolve_detailed")
    def test_wildcard_dns_filtering_eliminates_catchall_false_positives(
        self, mock_resolve_detailed: mock.MagicMock
    ) -> None:
        # Simulate a domain where *.example.com resolves to 198.51.100.99,
        # while api.example.com resolves to a real dedicated IP 93.184.216.34.
        def fake_resolve(hostname: str, resolver: object = None) -> dict:
            if hostname == "api.example.com":
                return {
                    "ip": "93.184.216.34",
                    "ipv6": None,
                    "record_type": "A",
                    "cname_target": None,
                }
            return {
                "ip": "198.51.100.99",
                "ipv6": None,
                "record_type": "A",
                "cname_target": None,
            }

        mock_resolve_detailed.side_effect = fake_resolve

        with tempfile.TemporaryDirectory() as tmpdir:
            wl = Path(tmpdir) / "words.txt"
            wl.write_text("api\ndev\ntest\nadmin\n", encoding="utf-8")
            results = dns_bruteforce.brute_force(
                "example.com", wordlist_path=str(wl), max_workers=4
            )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["hostname"], "api.example.com")
        self.assertEqual(results[0]["ip"], "93.184.216.34")

    def test_check_dangling_cname_detects_unclaimed_cloud_aliases(self) -> None:
        # Unresolved CNAME to GitHub Pages -> flagged!
        warning = dns_bruteforce.check_dangling_cname(
            "abandoned-org.github.io", resolved_ip=None, resolved_ipv6=None
        )
        self.assertIsNotNone(warning)
        self.assertIn("GitHub Pages", warning or "")

        # Resolved CNAME -> healthy, no warning
        healthy = dns_bruteforce.check_dangling_cname(
            "active-org.github.io", resolved_ip="185.199.108.153", resolved_ipv6=None
        )
        self.assertIsNone(healthy)

    @mock.patch("modules.dns_bruteforce._resolve_detailed")
    def test_enrich_subdomains_merges_sources_and_flags_dangling_cname(
        self, mock_resolve_detailed: mock.MagicMock
    ) -> None:
        def fake_resolve(hostname: str, resolver: object = None) -> dict:
            if hostname == "docs.example.com":
                return {
                    "ip": None,
                    "ipv6": None,
                    "record_type": "CNAME",
                    "cname_target": "unclaimed-docs.github.io",
                }
            return {
                "ip": "93.184.216.50",
                "ipv6": "2606:2800:220:1::50",
                "record_type": "A",
                "cname_target": None,
            }

        mock_resolve_detailed.side_effect = fake_resolve

        passive_subs = ["api.example.com", "docs.example.com"]
        passive_map = {
            "api.example.com": ["crt.sh", "AlienVault OTX"],
            "docs.example.com": ["crt.sh"],
        }
        bf_results = [
            {
                "hostname": "api.example.com",
                "ip": "93.184.216.34",
                "ipv6": "",
                "record_type": "A",
                "cname_target": "",
            }
        ]

        enriched = dns_bruteforce.enrich_subdomains(
            domain="example.com",
            passive_subdomains=passive_subs,
            bruteforce_results=bf_results,
            passive_source_map=passive_map,
            max_workers=2,
        )
        by_host = {r["hostname"]: r for r in enriched}

        self.assertEqual(
            by_host["api.example.com"]["sources"],
            ["crt.sh", "AlienVault OTX", "DNS Brute-Force"],
        )
        self.assertEqual(by_host["docs.example.com"]["status"], "DANGLING_CNAME")
        self.assertIn("GitHub Pages", by_host["docs.example.com"]["hygiene_warning"])


class TestReportingAndEndToEndCLI(unittest.TestCase):
    """Test HTML, PDF, JSON, CSV report generation, snapshot diffing, and CLI workflow."""

    def test_all_report_formats_and_diffing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            prev_json = Path(tmpdir) / "baseline.json"
            prev_json.write_text(
                json.dumps(
                    {
                        "unified_assets": [
                            {"hostname": "api.example.com"},
                            {"hostname": "legacy.example.com"},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            current_subs = ["api.example.com", "new-portal.example.com"]
            diff = report.compute_diff(current_subs, str(prev_json))
            self.assertEqual(diff["added"], ["new-portal.example.com"])
            self.assertEqual(diff["removed"], ["legacy.example.com"])
            self.assertEqual(diff["unchanged"], ["api.example.com"])

            passive_map = {
                "api.example.com": ["crt.sh", "AlienVault OTX"],
                "new-portal.example.com": ["URLScan.io"],
            }
            bf_results = [
                {
                    "hostname": "api.example.com",
                    "ip": "93.184.216.34",
                    "record_type": "A",
                }
            ]

            html_path = report.generate_report(
                domain="example.com",
                passive_subdomains=current_subs,
                bruteforce_results=bf_results,
                output_dir=tmpdir,
                passive_source="crt.sh, AlienVault OTX, URLScan.io",
                passive_source_map=passive_map,
                diff_summary=diff,
            )
            html_text = Path(html_path).read_text(encoding="utf-8")
            self.assertIn("Unified Attack-Surface", html_text)
            self.assertIn("AlienVault OTX", html_text)
            self.assertIn("new-portal.example.com", html_text)
            self.assertIn("93.184.216.0/24", html_text)

            json_path = report.generate_json_report(
                domain="example.com",
                passive_subdomains=current_subs,
                bruteforce_results=bf_results,
                output_dir=tmpdir,
                passive_source_map=passive_map,
                diff_summary=diff,
            )
            parsed_json = json.loads(Path(json_path).read_text(encoding="utf-8"))
            self.assertEqual(parsed_json["schema_version"], "3.0")
            self.assertEqual(parsed_json["statistics"]["total_unique_subdomains"], 2)

            csv_path = report.generate_csv_report(
                domain="example.com",
                passive_subdomains=current_subs,
                bruteforce_results=bf_results,
                output_dir=tmpdir,
                passive_source_map=passive_map,
            )
            self.assertTrue(Path(csv_path).is_file())

            if report.PDF_AVAILABLE:
                pdf_path = report.generate_pdf_report(
                    domain="example.com",
                    passive_subdomains=current_subs,
                    bruteforce_results=bf_results,
                    output_dir=tmpdir,
                    passive_source_map=passive_map,
                )
                self.assertTrue(Path(pdf_path).is_file())
                self.assertGreater(Path(pdf_path).stat().st_size, 500)

    @mock.patch("modules.dns_bruteforce.audit_domain_dns")
    @mock.patch("modules.dns_bruteforce.enrich_subdomains")
    @mock.patch("modules.dns_bruteforce.brute_force")
    @mock.patch("modules.subdomains.enumerate_subdomains_detailed")
    def test_main_cli_end_to_end_all_formats(
        self,
        mock_enum: mock.MagicMock,
        mock_bf: mock.MagicMock,
        mock_enrich: mock.MagicMock,
        mock_audit: mock.MagicMock,
    ) -> None:
        mock_enum.return_value = (
            ["api.example.com"],
            "crt.sh",
            {"api.example.com": ["crt.sh"]},
        )
        mock_bf.return_value = [
            {"hostname": "api.example.com", "ip": "93.184.216.34", "record_type": "A"}
        ]
        mock_enrich.return_value = [
            {
                "hostname": "api.example.com",
                "ip": "93.184.216.34",
                "ipv6": "",
                "record_type": "A",
                "cname_target": "",
                "sources": ["crt.sh", "DNS Brute-Force"],
                "status": "RESOLVED",
                "hygiene_warning": "",
            }
        ]
        mock_audit.return_value = {
            "ns_records": ["ns1.example.com"],
            "mx_records": ["10 mail.example.com"],
            "spf_record": "v=spf1 -all",
            "dmarc_record": "v=DMARC1; p=reject",
            "caa_records": ['0 issue "letsencrypt.org"'],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            exit_code = main.main(
                [
                    "example.com",
                    "--output-dir",
                    tmpdir,
                    "--output-format",
                    "all",
                    "--nameservers",
                    "1.1.1.1,8.8.8.8",
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertTrue((Path(tmpdir) / "example.com.html").is_file())
            self.assertTrue((Path(tmpdir) / "example.com.json").is_file())
            self.assertTrue((Path(tmpdir) / "example.com.csv").is_file())
            if report.PDF_AVAILABLE:
                self.assertTrue((Path(tmpdir) / "example.com.pdf").is_file())


if __name__ == "__main__":
    unittest.main()
