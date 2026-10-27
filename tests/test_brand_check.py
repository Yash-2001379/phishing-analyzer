"""Tests for rule 5, the brand check. Uses only made-up emails in tests/emails/."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import report  # noqa: E402  (needs the path above first)

EMAILS = os.path.join(HERE, "emails")


def brand_findings(filename):
    """Score one test email and return only its brand findings (ATT&CK T1656)."""
    result = report.score_email(os.path.join(EMAILS, filename))
    return [(points, reason) for points, reason, tag in result["findings"] if tag == "T1656"]


class BrandCheckTests(unittest.TestCase):
    """Rule 5 should prefer a faked sender name over a brand in the subject."""

    def test_name_beats_earlier_subject_brand(self):
        """Subject says PayPal (early in BRANDS), name says Netflix (later). Name must win."""
        found = brand_findings("brand_name_and_subject.eml")
        self.assertEqual(len(found), 1)
        points, reason = found[0]
        self.assertEqual(points, 3)
        self.assertIn("Netflix", reason)

    def test_subject_still_counts_when_name_is_clean(self):
        """No brand in the name, so the subject check should still give +2."""
        found = brand_findings("brand_subject_only.eml")
        self.assertEqual(len(found), 1)
        points, reason = found[0]
        self.assertEqual(points, 2)
        self.assertIn("Paypal", reason)


if __name__ == "__main__":
    unittest.main()
