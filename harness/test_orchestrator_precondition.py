"""Tests for the proactive, precondition-driven leg routing (HANDOVER_6 §4).

These cover the SHAPE routing -- which confirmation legs an endpoint's shape
warrants, independent of any agent label -- at the module level, so the routing
that `investigate_engagement` depends on is exercised without a live model. This
is deliberately the piece the historical "green tests, dead pipeline" failures
lived in: routing code that no test ever ran."""
import unittest

from models import HttpExchange
from role_crawl import RoleSession
from orchestrator import (
    shape_precondition_legs,
    shape_precondition_findings,
    _carries_jwt,
    _jwt_identity,
    _accepts_xml,
    _has_url_param,
    _has_injectable_param,
    _has_file_shape,
    _has_redirect_param,
)

# A structurally-valid JWT (header.payload.sig) the regex must recognise.
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo0fQ.c2lnbmF0dXJl"


def _ex(url="http://t/api/tickets/1", method="GET", headers=None, body=""):
    return HttpExchange(url=url, method=method, request_headers=headers or {},
                        request_body=body, response_status=None,
                        response_headers={}, response_body="")


class CarriesJwtTests(unittest.TestCase):
    def test_bearer_jwt_detected(self):
        self.assertTrue(_carries_jwt({"Authorization": f"Bearer {JWT}"}))

    def test_jwt_in_cookie_detected(self):
        self.assertTrue(_carries_jwt({"Cookie": f"session={JWT}"}))

    def test_non_jwt_bearer_not_detected(self):
        self.assertFalse(_carries_jwt({"Authorization": "Bearer opaque-token-abc123"}))

    def test_empty_headers(self):
        self.assertFalse(_carries_jwt({}))
        self.assertFalse(_carries_jwt(None))


class JwtIdentityTests(unittest.TestCase):
    def test_picks_lowest_trust_reachable_role_with_jwt(self):
        roles = [RoleSession("anonymous", {}),
                 RoleSession("user", {"Authorization": f"Bearer {JWT}"}),
                 RoleSession("admin", {"Authorization": f"Bearer {JWT}"})]
        node = {"reachable_roles": ["user", "admin"], "method": "GET", "path": "/api/tickets/{id}"}
        chosen = _jwt_identity(node, roles)
        self.assertEqual(chosen.role, "user")   # lower trust than admin

    def test_none_when_no_reachable_role_carries_jwt(self):
        roles = [RoleSession("anonymous", {}),
                 RoleSession("user", {"Cookie": "sid=opaque"})]
        node = {"reachable_roles": ["anonymous", "user"], "method": "GET", "path": "/x"}
        self.assertIsNone(_jwt_identity(node, roles))

    def test_falls_back_to_any_jwt_role_when_node_lists_no_reachable(self):
        roles = [RoleSession("admin", {"Authorization": f"Bearer {JWT}"})]
        node = {"reachable_roles": [], "method": "GET", "path": "/x"}
        self.assertEqual(_jwt_identity(node, roles).role, "admin")


class AcceptsXmlTests(unittest.TestCase):
    def test_xml_content_type(self):
        self.assertTrue(_accepts_xml(_ex(headers={"Content-Type": "application/xml"}, body="<a/>")))

    def test_xml_body_shape_without_header(self):
        self.assertTrue(_accepts_xml(_ex(body="<?xml version='1.0'?><root/>")))

    def test_doctype_body(self):
        self.assertTrue(_accepts_xml(_ex(body="<!DOCTYPE foo><foo/>")))

    def test_json_is_not_xml(self):
        self.assertFalse(_accepts_xml(_ex(headers={"Content-Type": "application/json"}, body='{"a":1}')))


class HasUrlParamTests(unittest.TestCase):
    def test_url_in_query(self):
        self.assertTrue(_has_url_param(_ex(url="http://t/fetch?target=http://evil.example")))

    def test_url_in_body(self):
        self.assertTrue(_has_url_param(_ex(method="POST", body='{"callback":"https://evil.example/x"}')))

    def test_encoded_url_in_query(self):
        self.assertTrue(_has_url_param(_ex(url="http://t/fetch?u=%2f%2fevil.example")))

    def test_no_url(self):
        self.assertFalse(_has_url_param(_ex(url="http://t/api/tickets/1")))


class ShapePreconditionLegsTests(unittest.TestCase):
    ROLES = [RoleSession("anonymous", {}),
             RoleSession("user", {"Authorization": f"Bearer {JWT}"})]

    def test_object_scoped_get_routes_cross_identity(self):
        node = {"method": "GET", "path": "/api/tickets/{id}", "object_scoped": True,
                "reachable_roles": ["user"]}
        legs = shape_precondition_legs(node, _ex(), self.ROLES, "http://t")
        classes = [c for c, _ in legs]
        self.assertIn("idor", classes)

    def test_jwt_leg_seeded_from_jwt_identity(self):
        node = {"method": "GET", "path": "/api/tickets/mine", "object_scoped": False,
                "reachable_roles": ["user"]}
        legs = shape_precondition_legs(node, _ex(url="http://t/api/tickets/mine"), self.ROLES, "http://t")
        jwt_legs = [ex for c, ex in legs if c == "jwt"]
        self.assertEqual(len(jwt_legs), 1)
        # the jwt leg's seed must carry the JWT identity's Authorization header
        self.assertIn(JWT, jwt_legs[0].request_headers.get("Authorization", ""))

    def test_non_get_object_scoped_gets_no_idor_leg(self):
        node = {"method": "POST", "path": "/api/tickets/{id}", "object_scoped": True,
                "reachable_roles": ["user"]}
        legs = shape_precondition_legs(node, _ex(method="POST"), self.ROLES, "http://t")
        self.assertNotIn("idor", [c for c, _ in legs])

    def test_xml_body_routes_xxe(self):
        node = {"method": "POST", "path": "/api/import", "reachable_roles": ["user"]}
        ex = _ex(url="http://t/api/import", method="POST",
                 headers={"Content-Type": "application/xml"}, body="<a/>")
        legs = shape_precondition_legs(node, ex, self.ROLES, "http://t")
        self.assertIn("xxe", [c for c, _ in legs])

    def test_url_param_routes_ssrf(self):
        node = {"method": "GET", "path": "/api/fetch", "reachable_roles": ["anonymous"]}
        ex = _ex(url="http://t/api/fetch?target=http://evil.example")
        legs = shape_precondition_legs(node, ex, self.ROLES, "http://t")
        self.assertIn("ssrf", [c for c, _ in legs])

    def test_benign_node_routes_nothing(self):
        node = {"method": "GET", "path": "/api/health", "object_scoped": False,
                "reachable_roles": ["anonymous"]}
        # anonymous carries no JWT, not object-scoped, no xml/url -> no legs
        legs = shape_precondition_legs(node, _ex(url="http://t/api/health"),
                                       [RoleSession("anonymous", {})], "http://t")
        self.assertEqual(legs, [])

    def test_object_scoped_jwt_endpoint_routes_both(self):
        node = {"method": "GET", "path": "/api/tickets/{id}", "object_scoped": True,
                "reachable_roles": ["user"]}
        legs = shape_precondition_legs(node, _ex(), self.ROLES, "http://t")
        classes = [c for c, _ in legs]
        self.assertIn("idor", classes)
        self.assertIn("jwt", classes)

    def test_injectable_param_routes_cmdi_and_ssti(self):
        node = {"method": "GET", "path": "/api/tickets/search", "reachable_roles": ["user"]}
        ex = _ex(url="http://t/api/tickets/search?q=test")
        classes = [c for c, _ in shape_precondition_legs(node, ex, self.ROLES, "http://t")]
        self.assertIn("command_injection", classes)
        self.assertIn("ssti", classes)

    def test_fileish_path_segment_routes_path_traversal(self):
        node = {"method": "GET", "path": "/uploads/{id}", "reachable_roles": ["anonymous"]}
        ex = _ex(url="http://t/uploads/1")
        classes = [c for c, _ in shape_precondition_legs(node, ex, self.ROLES, "http://t")]
        self.assertIn("path_traversal", classes)

    def test_redirect_param_routes_open_redirect(self):
        node = {"method": "GET", "path": "/login", "reachable_roles": ["anonymous"]}
        ex = _ex(url="http://t/login?next=/dashboard")
        classes = [c for c, _ in shape_precondition_legs(node, ex, self.ROLES, "http://t")]
        self.assertIn("open_redirect", classes)

    def test_bare_object_path_does_not_route_injection_legs(self):
        # /api/tickets/1 has no params and is not file-ish -> no cmdi/ssti/path/redir.
        classes = [c for c, _ in shape_precondition_legs(
            {"method": "GET", "path": "/api/tickets/{id}", "reachable_roles": ["user"]},
            _ex(), self.ROLES, "http://t")]
        for c in ("command_injection", "ssti", "path_traversal", "open_redirect"):
            self.assertNotIn(c, classes)


class ShapePredicateTests(unittest.TestCase):
    def test_has_injectable_param(self):
        self.assertTrue(_has_injectable_param(_ex(url="http://t/s?q=1")))
        self.assertTrue(_has_injectable_param(_ex(method="POST", headers={"Content-Type": "application/json"},
                                                  body='{"a":1}')))
        self.assertFalse(_has_injectable_param(_ex(url="http://t/api/tickets/1")))

    def test_has_file_shape(self):
        self.assertTrue(_has_file_shape(_ex(url="http://t/d?file=a.txt")))     # file param
        self.assertTrue(_has_file_shape(_ex(url="http://t/uploads/1")))        # file-ish segment
        self.assertFalse(_has_file_shape(_ex(url="http://t/api/tickets/1")))   # neither

    def test_has_redirect_param(self):
        self.assertTrue(_has_redirect_param(_ex(url="http://t/login?next=/x")))
        self.assertFalse(_has_redirect_param(_ex(url="http://t/s?q=1")))


class ShapePreconditionFindingsTests(unittest.TestCase):
    def test_injectable_param_yields_cmdi_and_ssti_findings(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/s?q=test"))}
        self.assertIn("command_injection", classes)
        self.assertIn("ssti", classes)

    def test_fileish_segment_yields_path_traversal_finding(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/uploads/1"))}
        self.assertIn("path_traversal", classes)

    def test_redirect_param_yields_open_redirect_finding(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/go?next=/x"))}
        self.assertIn("open_redirect", classes)

    def test_benign_object_get_yields_nothing(self):
        self.assertEqual(shape_precondition_findings(_ex(url="http://t/api/tickets/1")), [])


if __name__ == "__main__":
    unittest.main()
