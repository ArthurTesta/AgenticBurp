import unittest
from models import AgentReport, Finding
from confirmation_gate import is_confirmable_class, apply_confirmation_suppression, leg_tier


def _finding(vc, severity="high", confidence=0.85, confirmed=False):
    return Finding(vulnerability_class=vc, confidence=confidence, severity=severity,
                   summary=f"{vc} on /x", evidence="e", suggested_test="t",
                   basis="derived", confirmed=confirmed)


def _apply(finding, **kw):
    apply_confirmation_suppression([AgentReport(agent="a", model="test", findings=[finding])], **kw)
    return finding


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


class TestLegAwareThreeState(unittest.TestCase):
    def test_leg_tier(self):
        for live in ("idor", "SQL_INJECTION", "xxe", "jwt algorithm confusion", "path_traversal"):
            self.assertEqual(leg_tier(live), "live", live)
        for prov in ("reflected xss", "ssrf", "command injection", "ssti",
                     "open_redirect", "mass_assignment"):
            self.assertEqual(leg_tier(prov), "provisional", prov)
        for none in ("business_logic", "information_disclosure", "csrf", None, ""):
            self.assertEqual(leg_tier(none), "none", none)

    def test_refuted_live_class_demoted_to_low(self):
        f = _apply(_finding("sqli", severity="critical"))
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.original_severity, "critical")
        self.assertLessEqual(f.confidence, 0.35)
        self.assertEqual(f.review_verdict, "unconfirmed_hypothesis")
        self.assertTrue(f.summary.startswith("[Hypothesis] "))

    def test_unproven_provisional_class_capped_at_medium_not_low(self):
        # A provisional-leg class (leg not live-verified) is kept visible at
        # medium, not buried to low -- recall over a not-yet-trusted silence.
        f = _apply(_finding("reflected xss", severity="high", confidence=0.9))
        self.assertEqual(f.severity, "medium")
        self.assertEqual(f.original_severity, "high")
        self.assertLessEqual(f.confidence, 0.5)
        self.assertGreater(f.confidence, 0.35)  # NOT capped as hard as REFUTED
        self.assertEqual(f.review_verdict, "unproven_unverified_leg")
        self.assertTrue(f.summary.startswith("[Unconfirmed] "))

    def test_provisional_low_severity_unchanged(self):
        f = _apply(_finding("ssrf", severity="low", confidence=0.3))
        self.assertEqual(f.severity, "low")  # medium cap never RAISES severity

    def test_phase2_override_promotes_a_provisional_leg_to_refuted(self):
        # The Phase-2 seam: once ssti's leg is live-verified, passing it in the
        # live set flips its suppression from UNPROVEN(medium) to REFUTED(low).
        from confirmation_gate import LIVE_VERIFIED_MARKERS
        promoted = LIVE_VERIFIED_MARKERS | {"ssti"}
        f = _apply(_finding("ssti", severity="high"), live_verified_markers=promoted)
        self.assertEqual(f.severity, "low")
        self.assertEqual(f.review_verdict, "unconfirmed_hypothesis")

    def test_confirmed_untouched_regardless_of_tier(self):
        f = _apply(_finding("reflected xss", severity="high", confirmed=True))
        self.assertEqual(f.severity, "high")
        self.assertIsNone(f.review_verdict)


if __name__ == "__main__":
    unittest.main()
