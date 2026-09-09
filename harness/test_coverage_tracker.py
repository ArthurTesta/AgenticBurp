"""Tests for coverage_tracker: turning a finished engagement into the auditable
identity × endpoint × check matrix (I1/I2/I5)."""
import unittest

import engagement
from coverage_tracker import CoverageTracker, build_coverage, endpoint_view
from coverage_model import CellStatus


class ClassMappingTests(unittest.TestCase):
    def setUp(self):
        self.t = CoverageTracker()

    def test_maps_canonical_and_freetext_classes(self):
        self.assertIn("WSTG-INPV-05", self.t.checks_for_class("sqli"))
        self.assertIn("WSTG-INPV-05", self.t.checks_for_class("SQL Injection"))
        # free-text access-control the canonicaliser returns None for
        self.assertIn("WSTG-ATHZ-04", self.t.checks_for_class("IDOR/BOLA"))
        self.assertTrue(self.t.checks_for_class("Broken Function-Level Authorization"))
        # mass assignment -> api_security check
        self.assertIn("WSTG-CONF-09", self.t.checks_for_class("mass_assignment"))

    def test_unknown_class_maps_to_nothing(self):
        self.assertEqual(self.t.checks_for_class("totally-made-up-class"), [])


def _state_with(endpoints):
    st = engagement.EngagementState(host="t.test")
    for method, path, kw in endpoints:
        ep = st._ep(method, path)
        ep.reachable_roles = kw.get("reachable_roles", [])
        ep.object_scoped = kw.get("object_scoped", "{id}" in path)
        for f in kw.get("findings", []):
            ep.add_finding(f)
    return st


class BuildTests(unittest.TestCase):
    def test_applicability_and_reachability(self):
        st = _state_with([
            ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),
        ])
        t = CoverageTracker()
        eps = endpoint_view(st)
        counts = t.build(eps, ["anonymous", "user", "admin"])
        # object-scoped -> IDOR check applicable
        cell = t.matrix.get("user", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertEqual(cell.status, CellStatus.PENDING)
        # anonymous never reached it -> skipped with a reachability reason
        cell_anon = t.matrix.get("anonymous", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertEqual(cell_anon.status, CellStatus.SKIPPED)
        self.assertIn("did not reach", cell_anon.reason)
        self.assertGreater(counts["not_applicable"], 0)

    def test_confirmed_finding_recorded(self):
        st = _state_with([
            ("GET", "/api/tickets/{id}", {
                "reachable_roles": ["user", "admin"],
                "findings": [{"vulnerability_class": "idor", "confirmed": True,
                              "severity": "high", "confidence": 0.9}]}),
        ])
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user", "admin"])
        t.record_findings_from_state(eps, ["user", "admin"])
        # attributed to the lowest-trust reacher (user)
        cell = t.matrix.get("user", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertEqual(cell.status, CellStatus.CONFIRMED)
        self.assertEqual(cell.severity, "high")

    def test_detected_but_unconfirmed_recorded(self):
        st = _state_with([
            ("GET", "/api/admin/users", {
                "reachable_roles": ["user"],
                "findings": [{"vulnerability_class": "Broken Function-Level Authorization",
                              "confirmed": False, "severity": "medium", "confidence": 0.5}]}),
        ])
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        t.record_findings_from_state(eps, ["user"])
        cell = t.matrix.get("user", "GET /api/admin/users", "WSTG-ATHZ-02")
        self.assertEqual(cell.status, CellStatus.DETECTED)

    def test_leg_attempt_marks_not_detected(self):
        st = _state_with([
            ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),
        ])
        t = CoverageTracker()
        eps = endpoint_view(st)
        t.build(eps, ["user"])
        # no finding, but the endpoint was investigated -> the cross_identity leg ran
        t.mark_leg_attempts({"GET /api/tickets/{id}"}, ["user"])
        cell = t.matrix.get("user", "GET /api/tickets/{id}", "WSTG-ATHZ-04")
        self.assertEqual(cell.status, CellStatus.NOT_DETECTED)

    def test_not_tested_has_reasons(self):
        st = _state_with([
            ("GET", "/api/tickets/{id}", {"reachable_roles": ["user"]}),
        ])
        report = build_coverage(st, [type("R", (), {"role": "user"})()],
                                investigated_keys=set())
        # every not-tested cell must carry a reason (the I5 audit guarantee)
        self.assertTrue(report["not_tested"])
        self.assertTrue(all(nt["reason"] for nt in report["not_tested"]))
        # summary keys present
        for k in ("total_cells", "confirmed", "detected", "not_applicable"):
            self.assertIn(k, report)


if __name__ == "__main__":
    unittest.main()
