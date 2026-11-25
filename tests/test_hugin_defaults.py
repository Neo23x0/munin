"""Tests for the default CSV layout of hugin and the --no- flags that reverse it."""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hugin
import lib.munin_vt as munin_vt


HASH_COLUMNS = ["MD5", "SHA1", "SHA256"]
VT_DETECTION_COLUMNS = ["Threat Label", "Community Rules"]


def _match(rule, sha256):
    info = munin_vt.getEmptyInfo()
    info.update({"hash": sha256, "sha256": sha256, "md5": "m" * 32, "sha1": "s" * 40,
                 "matching_rule": rule, "comments": 0, "commenter": [],
                 "threat_label": "trojan.test", "community_rules": "Some_Rule"})
    return info


class TestHuginDefaultColumns(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.csv_path = os.path.join(self.temp_dir.name, "results.csv")
        self.ini_path = os.path.join(self.temp_dir.name, "test.ini")
        with open(self.ini_path, "w", encoding="utf-8") as ini_file:
            ini_file.write("[DEFAULT]\nVT_PUBLIC_API_KEY = dummy\nPROXY = -\n")

    def _header(self, extra_args):
        argv = ["hugin.py", "-r", "job-1", "-i", self.ini_path, "--csv-path", self.csv_path] + extra_args
        with patch.object(sys, "argv", argv), \
                patch("hugin.munin_vt.getRetrohuntResults", return_value=[_match("Alpha", "a" * 64)]), \
                patch("hugin.munin_vt.getRetrohuntJob", return_value=None), \
                patch("hugin.printResult"), \
                contextlib.redirect_stdout(io.StringIO()):
            hugin.main()
        with open(self.csv_path, encoding="utf-8") as csv_file:
            return csv_file.readline().rstrip("\n").split(";")

    def test_default_header(self):
        header = self._header([])
        self.assertIn("Lookup Hash", header)
        for column in HASH_COLUMNS:
            self.assertNotIn(column, header)
        for column in VT_DETECTION_COLUMNS:
            self.assertIn(column, header)

    def test_no_lookup_hash_only_keeps_hash_columns(self):
        header = self._header(["--no-lookup-hash-only"])
        for column in HASH_COLUMNS:
            self.assertIn(column, header)
        for column in VT_DETECTION_COLUMNS:
            self.assertIn(column, header)

    def test_no_include_vt_detections_drops_vt_columns(self):
        header = self._header(["--no-include-vt-detections"])
        for column in VT_DETECTION_COLUMNS:
            self.assertNotIn(column, header)
        for column in HASH_COLUMNS:
            self.assertNotIn(column, header)

    def test_all_no_flags_restore_previous_layout(self):
        header = self._header(["--no-lookup-hash-only", "--no-include-vt-detections", "--no-include-unmatched-rules"])
        for column in HASH_COLUMNS:
            self.assertIn(column, header)
        for column in VT_DETECTION_COLUMNS:
            self.assertNotIn(column, header)

    def test_positive_flags_are_still_accepted(self):
        header = self._header(["--lookup-hash-only", "--include-vt-detections", "--include-unmatched-rules"])
        self.assertEqual(header, self._header([]))


if __name__ == "__main__":
    unittest.main()
