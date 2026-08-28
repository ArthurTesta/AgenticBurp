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

if __name__ == "__main__": unittest.main()
