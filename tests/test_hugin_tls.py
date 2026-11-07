"""Tests for Retrohunt Analyzer TLS handling."""

import contextlib
import io
import os
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hugin


class TestAnalyzerTLS(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.csv_path = os.path.join(self.temp_dir.name, "results.csv")
        with open(self.csv_path, "w", encoding="utf-8") as csv_file:
            csv_file.write("hash\n")

    def test_custom_ca_bundle_is_used_only_for_analyzer_request(self):
        ca_bundle = os.path.join(self.temp_dir.name, "organization-ca.pem")
        with open(ca_bundle, "w", encoding="ascii") as ca_file:
            ca_file.write("test CA")

        response = MagicMock(status_code=500, text="error")
        with patch("hugin.requests.post", return_value=response) as post:
            with contextlib.redirect_stdout(io.StringIO()):
                hugin.send_to_analyzer(self.csv_path, "https://analyzer.example", ca_bundle)

        self.assertEqual(post.call_args[1]["verify"], ca_bundle)

    def test_default_certificate_verification_remains_enabled(self):
        response = MagicMock(status_code=500, text="error")
        with patch("hugin.requests.post", return_value=response) as post:
            with contextlib.redirect_stdout(io.StringIO()):
                hugin.send_to_analyzer(self.csv_path, "https://analyzer.example")

        self.assertIs(post.call_args[1]["verify"], True)

    def test_ssl_error_prints_safe_actionable_help(self):
        output = io.StringIO()
        ssl_error = hugin.requests.exceptions.SSLError("certificate verify failed")

        with patch("hugin.requests.post", side_effect=ssl_error):
            with contextlib.redirect_stdout(output):
                hugin.send_to_analyzer(self.csv_path, "https://analyzer.example")

        text = output.getvalue()
        self.assertIn("TLS certificate verification failed", text)
        self.assertIn("RETROHUNT_ANALYZER_CA_BUNDLE", text)
        self.assertIn("Do not disable TLS certificate verification", text)
        self.assertNotIn("verify=False", text)

    def test_connection_error_keeps_generic_diagnostics_and_debug_traceback(self):
        output = io.StringIO()
        errors = io.StringIO()
        connection_error = hugin.requests.exceptions.ConnectionError("connection refused")

        with patch("hugin.requests.post", side_effect=connection_error):
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                hugin.send_to_analyzer(self.csv_path, "https://analyzer.example", debug=True)

        self.assertIn("Could not reach retrohunt-analyzer-service", output.getvalue())
        self.assertNotIn("TLS certificate verification failed", output.getvalue())
        self.assertIn("requests.exceptions.ConnectionError", errors.getvalue())

    def test_successful_html_report_is_written_and_reported(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zip_file:
            zip_file.writestr("report.html", b"<html>report</html>")

        response = MagicMock(status_code=200, content=archive.getvalue())
        output = io.StringIO()
        with patch("hugin.requests.post", return_value=response):
            with contextlib.redirect_stdout(output):
                hugin.send_to_analyzer(self.csv_path, "https://analyzer.example")

        report_path = os.path.join(self.temp_dir.name, "report.html")
        with open(report_path, "rb") as report:
            self.assertEqual(report.read(), b"<html>report</html>")
        self.assertIn("[+] Analyzer output saved: %s" % report_path, output.getvalue())

    def test_missing_ca_bundle_is_reported_before_request(self):
        output = io.StringIO()
        missing = os.path.join(self.temp_dir.name, "missing.pem")

        with patch("hugin.requests.post") as post:
            with contextlib.redirect_stdout(output):
                hugin.send_to_analyzer(self.csv_path, "https://analyzer.example", missing)

        post.assert_not_called()
        self.assertIn("CA bundle does not exist", output.getvalue())

    def test_main_forwards_ca_bundle_and_debug_flag(self):
        ca_bundle = os.path.join(self.temp_dir.name, "organization-ca.pem")
        config_path = os.path.join(self.temp_dir.name, "hugin.ini")
        with open(config_path, "w", encoding="utf-8") as config_file:
            config_file.write(
                "[DEFAULT]\n"
                "VT_PUBLIC_API_KEY = test-key\n"
                "PROXY = -\n"
                "RETROHUNT_ANALYZER_URL = https://analyzer.example\n"
                "RETROHUNT_ANALYZER_CA_BUNDLE = %s\n" % ca_bundle
            )

        with patch.object(sys, "argv", ["hugin.py", "-i", config_path, "--debug"]), \
                patch("hugin.connections.setProxy"), \
                patch("hugin.munin_vt.getRetrohuntResults", return_value=[]), \
                patch("hugin.writeCSVHeader"), \
                patch("hugin.send_to_analyzer") as send:
            with contextlib.redirect_stdout(io.StringIO()):
                hugin.main()

        send.assert_called_once_with(
            "retrohunt_results.csv",
            "https://analyzer.example",
            ca_bundle,
            True,
        )


if __name__ == "__main__":
    unittest.main()
