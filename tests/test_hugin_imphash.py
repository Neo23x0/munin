"""Tests for dropping the Imphash column in hugin when no result has an imphash."""

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


def make_info(hash_value, imphash="-"):
    info = munin_vt.getEmptyInfo()
    info['hash'] = hash_value
    info['imphash'] = imphash
    info['matching_rule'] = "TestRule"
    return info


class TestImphashColumn(unittest.TestCase):
    def run_hugin(self, results):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = os.path.join(tmp, "out.csv")
            argv = ["hugin.py", "-r", "hunt", "-i", os.path.join(tmp, "missing.ini"), "--csv-path", csv_path]
            with patch.object(sys, "argv", argv), \
                    patch.object(munin_vt, "getRetrohuntResults", return_value=results), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                hugin.main()
            with open(csv_path, encoding="utf8") as fh:
                return fh.read().splitlines()

    def test_column_dropped_when_all_empty(self):
        results = [make_info("a" * 64), make_info("b" * 64, imphash=""), make_info("c" * 64, imphash=None)]
        lines = self.run_hugin(results)
        self.assertNotIn("Imphash", lines[0].split(";"))
        self.assertEqual(len(lines[0].split(";")), len(lines[1].split(";")))

    def test_column_dropped_when_key_missing(self):
        info = make_info("a" * 64)
        del info['imphash']
        lines = self.run_hugin([info])
        self.assertNotIn("Imphash", lines[0].split(";"))

    def test_column_kept_when_any_row_has_value(self):
        results = [make_info("a" * 64), make_info("b" * 64, imphash="0123456789abcdef0123456789abcdef")]
        lines = self.run_hugin(results)
        header = lines[0].split(";")
        self.assertIn("Imphash", header)
        idx = header.index("Imphash")
        self.assertEqual(lines[1].split(";")[idx], "-")
        self.assertEqual(lines[2].split(";")[idx], "0123456789abcdef0123456789abcdef")


if __name__ == "__main__":
    unittest.main()
