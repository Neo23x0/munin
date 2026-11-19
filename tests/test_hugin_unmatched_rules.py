"""Tests for adding rules without matches to the hugin CSV."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hugin
import lib.munin_vt as munin_vt


RULESET = r'''
import "pe"

rule Alpha : tag1 tag2 {
    strings:
        $a = "rule Fake {" // not a rule
        $b = "http://example.com"
    condition:
        $a or $b
}

private rule Helper { condition: true }
global rule Global_One { condition: Helper }
global private rule Hidden { condition: true }

// rule Commented_Line { condition: true }
/*
rule Commented_Block { condition: true }
*/

rule Beta { condition: true } rule Gamma { condition: Beta }
'''


class TestGetYaraRuleNames(unittest.TestCase):
    def test_extracts_non_private_rules_in_order(self):
        self.assertEqual(munin_vt.getYaraRuleNames(RULESET), ["Alpha", "Global_One", "Beta", "Gamma"])

    def test_empty_source(self):
        self.assertEqual(munin_vt.getYaraRuleNames(""), [])

    def test_escaped_quote_in_string(self):
        source = 'rule A { strings: $a = "x\\" rule B" condition: $a }'
        self.assertEqual(munin_vt.getYaraRuleNames(source), ["A"])


class TestGetRetrohuntJob(unittest.TestCase):
    def test_returns_attributes(self):
        attributes = {"status": "finished", "rules": "rule A { condition: true }"}
        response = MagicMock(ok=True, content=json.dumps({"data": {"attributes": attributes}}).encode())
        with patch("lib.munin_vt.requests.get", return_value=response) as get:
            self.assertEqual(munin_vt.getRetrohuntJob("job-1"), attributes)
        self.assertTrue(get.call_args[0][0].endswith("/retrohunt_jobs/job-1"))

    def test_error_response_returns_none(self):
        response = MagicMock(ok=False, status_code=404, content=b"not found")
        with patch("lib.munin_vt.requests.get", return_value=response):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertIsNone(munin_vt.getRetrohuntJob("job-1"))


def _match(rule, sha256):
    info = munin_vt.getEmptyInfo()
    info.update({"hash": sha256, "matching_rule": rule, "comments": 0, "commenter": []})
    return info


class TestHuginMain(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.csv_path = os.path.join(self.temp_dir.name, "results.csv")
        self.ini_path = os.path.join(self.temp_dir.name, "test.ini")
        with open(self.ini_path, "w", encoding="utf-8") as ini_file:
            ini_file.write("[DEFAULT]\nVT_PUBLIC_API_KEY = dummy\nPROXY = -\n")
        self.found = [_match("Alpha", "a" * 64), _match("Gamma", "c" * 64)]

    def _run(self, extra_args, job):
        argv = ["hugin.py", "-r", "job-1", "-i", self.ini_path, "--csv-path", self.csv_path] + extra_args
        stdout = io.StringIO()
        with patch.object(sys, "argv", argv), \
                patch("hugin.munin_vt.getRetrohuntResults", return_value=list(self.found)), \
                patch("hugin.munin_vt.getRetrohuntJob", return_value=job) as get_job, \
                patch("hugin.printResult") as print_result, \
                contextlib.redirect_stdout(stdout):
            hugin.main()
        with open(self.csv_path, encoding="utf-8") as csv_file:
            lines = csv_file.read().splitlines()
        return lines, stdout.getvalue(), get_job, print_result

    def test_unmatched_rules_are_appended_at_end(self):
        job = {"status": "finished", "rules": RULESET}
        lines, out, _, print_result = self._run(["--include-unmatched-rules"], job)

        header = lines[0].split(";")
        rule_col = header.index("Matching Rule")
        rows = [line.split(";") for line in lines[1:]]
        self.assertEqual([r[rule_col] for r in rows], ["Alpha", "Gamma", "Beta", "Global_One"])
        for row in rows:
            self.assertEqual(len(row), len(header))
        for row in rows[2:]:
            self.assertEqual([v for i, v in enumerate(row) if i != rule_col], [""] * (len(header) - 1))
        self.assertEqual(print_result.call_count, 2)
        self.assertIn("2 rule(s) without matches: Beta, Global_One", out)
        self.assertNotIn("not finished", out)

    def test_running_job_warns_but_adds_rows(self):
        job = {"status": "running", "progress": 42.5, "rules": RULESET}
        lines, out, _, _ = self._run(["--include-unmatched-rules"], job)
        self.assertIn("Retrohunt is not finished yet (status: running, progress: 42.5%)", out)
        self.assertEqual(len(lines), 5)

    def test_job_error_keeps_matches_only(self):
        lines, out, _, _ = self._run(["--include-unmatched-rules"], None)
        self.assertIn("Could not retrieve retrohunt job", out)
        self.assertEqual(len(lines), 3)

    def test_without_flag_job_is_not_queried(self):
        lines, _, get_job, _ = self._run([], {"status": "finished", "rules": RULESET})
        get_job.assert_not_called()
        self.assertEqual(len(lines), 3)


if __name__ == "__main__":
    unittest.main()
