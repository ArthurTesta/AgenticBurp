import unittest
from models import AgentReport, Finding
from confirmation_gate import is_confirmable_class, apply_confirmation_suppression


class TestConfirmationGate(unittest.TestCase):
    def test_is_confirmable_class(self):
        self.assertTrue(is_confirmable_class("idor"))
        self.assertTrue(is_confirmable_class("Insecure Direct Object Reference"))
        self.assertTrue(is_confirmable_class("SQL_INJECTION"))
        self.assertTrue(is_confirmable_class("reflected xss"))
        self.assertTrue(is_confirmable_class("ssrf"))
        self.assertTrue(is_confirmable_class("xml_external_entity"))
        self.assertTrue(is_confirmable_class("jwt algorithm confusion"))
        self.assertTrue(is_confirmable_class("command injection (rce)"))
        self.assertTrue(is_confirmable_class("ssti"))
        self.assertTrue(is_confirmable_class("path_traversal"))
        self.assertTrue(is_confirmable_class("open_redirect"))

        # Non-confirmable classes (no active validation leg)
        self.assertFalse(is_confirmable_class("business_logic"))
        self.assertFalse(is_confirmable_class("information_disclosure"))
        self.assertFalse(is_confirmable_class("missing_security_headers"))
        self.assertFalse(is_confirmable_class(None))
        self.assertFalse(is_confirmable_class(""))

    def test_unconfirmed_idor_is_demoted(self):
        f = Finding(
            vulnerability_class="idor",
            confidence=0.85,
            severity="high",
            summary="User profile IDOR on /users/2",
            evidence="id=2",
            suggested_test="try id=3",
            basis="derived",
            confirmed=False,
        )
        report = AgentReport(agent="idor", model="test", findings=[f])

        demoted = apply_confirmation_suppression([report])
        self.assertEqual(demoted, 1)
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.original_severity, "high")
        self.assertLessEqual(f.confidence, 0.35)
        self.assertEqual(f.original_confidence, 0.85)
        self.assertEqual(f.review_verdict, "unconfirmed_hypothesis")
        self.assertTrue(f.summary.startswith("[Hypothesis] "))

    def test_confirmed_finding_is_not_demoted(self):
        f = Finding(
            vulnerability_class="idor",
            confidence=0.95,
            severity="high",
            summary="Confirmed user profile IDOR on /users/2",
            evidence="id=2",
            suggested_test="try id=3",
            basis="derived",
            confirmed=True,
        )
        report = AgentReport(agent="idor", model="test", findings=[f])

        demoted = apply_confirmation_suppression([report])
        self.assertEqual(demoted, 0)
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.confidence, 0.95)
        self.assertIsNone(f.original_severity)
        self.assertFalse(f.summary.startswith("[Hypothesis]"))

    def test_non_confirmable_class_is_untouched(self):
        f = Finding(
            vulnerability_class="business_logic",
            confidence=0.80,
            severity="medium",
            summary="Workflow skip on checkout",
            evidence="step=3",
            suggested_test="test",
            basis="derived",
            confirmed=False,
        )
        report = AgentReport(agent="business_logic", model="test", findings=[f])

        demoted = apply_confirmation_suppression([report])
        self.assertEqual(demoted, 0)
        self.assertEqual(f.severity, "medium")
        self.assertEqual(f.confidence, 0.80)


if __name__ == "__main__":
    unittest.main()
