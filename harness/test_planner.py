import unittest
from models import Finding, HttpExchange
from planner import plans_for_findings

class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.exchange = HttpExchange(url="https://example.test/item?id=7", method="GET")

    def test_class_automatically_maps_to_capability(self):
        f = Finding(vulnerability_class="idor", confidence=.6, severity="high", summary="possible IDOR", evidence="id", suggested_test="compare two identities", basis="derived")
        plans = plans_for_findings(self.exchange, [f])
        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].capability, "cross_identity_compare")
        self.assertEqual(plans[0].execution_plane, "burp")
        self.assertTrue(plans[0].requires_approval)

    def test_sqli_gets_sqlmap_plan_without_agent_knowing_tool_name(self):
        f = Finding(vulnerability_class="sqli", confidence=.8, severity="high", summary="possible SQLi", evidence="id", suggested_test="validate", basis="derived")
        plans = plans_for_findings(self.exchange, [f])
        self.assertEqual(plans[0].capability, "sql_injection_validation")
        self.assertEqual(plans[0].execution_plane, "local_tool")

    def test_plan_ids_are_stable(self):
        f = Finding(vulnerability_class="idor", confidence=.6, severity="high", summary="possible IDOR", evidence="id", suggested_test="compare", basis="derived")
        self.assertEqual(plans_for_findings(self.exchange, [f])[0].id, plans_for_findings(self.exchange, [f])[0].id)

    def test_hallucinated_sqlmap_hint_does_not_override_a_resolved_category(self):
        """
        Regression test for a real bug found live, against Juice Shop's
        PUT /api/BasketItems/<id>: a single exchange produced 9 findings
        across categories (idor, business_logic, xss, graphql, api_security),
        and the analyst's plan picker showed 7 near-identical
        "sql_injection_validation [local_tool]" buttons -- for an
        exchange with no SQL injection finding at all. Cause: several
        agents' findings carried "sqlmap" in validation_hints despite
        being correctly categorized as something else entirely (the
        prompt's worked example always shows "validation_hints":
        ["sqlmap"], regardless of context, and models copy it). The old
        code trusted that hint unconditionally, both via a direct
        append and via a separate dispatch-loop branch, regardless of
        the finding's own resolved category.
        """
        idor_with_bad_hint = Finding(
            vulnerability_class="Insecure Direct Object Reference (IDOR)",
            confidence=.5, severity="medium", summary="x", evidence="y",
            suggested_test="z", basis="derived", validation_hints=["sqlmap"],
        )
        plans = plans_for_findings(self.exchange, [idor_with_bad_hint])
        capabilities = [p.capability for p in plans]
        self.assertNotIn("sql_injection_validation", capabilities)
        self.assertIn("cross_identity_compare", capabilities)

        xss_with_bad_hint = Finding(
            vulnerability_class="Cross-site scripting (reflected)",
            confidence=.8, severity="medium", summary="x", evidence="y",
            suggested_test="z", basis="derived", validation_hints=["sqlmap"],
        )
        plans_xss = plans_for_findings(self.exchange, [xss_with_bad_hint])
        capabilities_xss = [p.capability for p in plans_xss]
        self.assertNotIn("sql_injection_validation", capabilities_xss)
        self.assertIn("reflection_context_validation", capabilities_xss)

    def test_real_sqli_finding_still_gets_sqlmap_plan_regardless_of_hint(self):
        """A genuine sqli finding must still get its plan whether or not
        the model also happened to include the (in this case correct)
        "sqlmap" hint -- the fix must not become so conservative it
        breaks the case it's meant to preserve."""
        with_hint = Finding(vulnerability_class="sqli", confidence=.9, severity="high",
                             summary="x", evidence="y", suggested_test="z", basis="derived",
                             validation_hints=["sqlmap"])
        without_hint = Finding(vulnerability_class="sqli", confidence=.9, severity="high",
                                summary="x", evidence="y", suggested_test="z", basis="derived")
        for f in (with_hint, without_hint):
            plans = plans_for_findings(self.exchange, [f])
            self.assertEqual([p.capability for p in plans], ["sql_injection_validation"])

    def test_unresolved_category_still_falls_back_to_sqlmap_hint(self):
        """The intended fallback survives: if the model's own category
        genuinely doesn't canonicalize to anything, its self-reported
        "sqlmap" hint is still the best available signal and should
        still be trusted -- this is not the case the fix targets."""
        f = Finding(vulnerability_class="some totally unrecognized phrase",
                    confidence=.5, severity="medium", summary="x", evidence="y",
                    suggested_test="z", basis="derived", validation_hints=["sqlmap"])
        plans = plans_for_findings(self.exchange, [f])
        self.assertEqual([p.capability for p in plans], ["sql_injection_validation"])

if __name__ == "__main__": unittest.main()
