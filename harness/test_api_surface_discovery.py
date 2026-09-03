import asyncio
import unittest

from api_surface_discovery import SurfaceDiscovery, _is_not_found, _paths_from_spec

# Flask/Werkzeug wraps an unknown route as a 500 carrying this marker; the oracle
# must read that as "route does not exist" just like a bare 404.
_NF = ("Traceback (most recent call last):\n"
       "werkzeug.exceptions.NotFound: 404 Not Found: The requested URL was not found on the server.")


class _FakeDiscovery(SurfaceDiscovery):
    """SurfaceDiscovery with the network seam replaced by a canned responder:
    responder(method, path) -> (status, body, allow). Unknown paths fall through
    to the Flask-style NotFound 500 so the oracle is exercised realistically."""
    def __init__(self, responder, **kw):
        super().__init__("http://target.test", **kw)
        self._responder = responder

    async def _probe(self, method, path):
        return self._responder(method, path)


def _run(disc):
    return asyncio.run(disc.discover())


class OracleTests(unittest.TestCase):
    def test_bare_404_is_not_found(self):
        self.assertTrue(_is_not_found(404, "{}"))

    def test_framework_marker_is_not_found(self):
        self.assertTrue(_is_not_found(500, _NF))

    def test_real_responses_are_found(self):
        for status in (200, 201, 400, 401, 403, 405, 302):
            self.assertFalse(_is_not_found(status, "{}"), status)


class DiscoveryTests(unittest.TestCase):
    def _responder(self, known):
        def r(method, path):
            if path in known:
                return known[path]
            return (500, _NF, "")
        return r

    def _disc(self, known):
        return _FakeDiscovery(
            self._responder(known),
            prefixes=["/api/"],
            collections=["admin", "tickets"],
            nouns=["health", "users", "login", "tickets", "articles"],
        )

    def test_finds_nested_route_a_flat_wordlist_misses(self):
        # /api/admin/users lives two segments deep; single-noun probing never
        # reaches it, nested enumeration does.
        known = {"/api/admin/users": (200, "{}", "")}
        res = _run(self._disc(known))
        self.assertIn("/api/admin/users", res.paths())
        self.assertEqual(next(r.source for r in res.routes if r.path == "/api/admin/users"), "nested")

    def test_allow_header_learns_post_only_route(self):
        # A GET on a POST-only route answers 405 + Allow -> learn its real methods.
        known = {"/api/login": (405, "{}", "OPTIONS, POST")}
        res = _run(self._disc(known))
        login = next(r for r in res.routes if r.path == "/api/login")
        self.assertIn("POST", login.methods)
        self.assertNotEqual(login.methods, ("GET",))

    def test_response_driven_id_enumeration(self):
        # A 200 list body reveals sibling object ids to enumerate.
        known = {
            "/api/tickets": (200, '[{"id":1},{"id":2},{"id":7}]', ""),
            "/api/tickets/1": (200, "{}", ""),
            "/api/tickets/2": (200, "{}", ""),
            "/api/tickets/7": (200, "{}", ""),
        }
        res = _run(self._disc(known))
        for p in ("/api/tickets/2", "/api/tickets/7"):
            self.assertIn(p, res.paths())

    def test_not_found_routes_excluded(self):
        known = {"/api/health": (200, "{}", "")}
        res = _run(self._disc(known))
        self.assertIn("/api/health", res.paths())
        self.assertNotIn("/api/users", res.paths())   # 404-wrapped -> excluded

    def test_scope_gate_blocks_out_of_scope_host(self):
        disc = _FakeDiscovery(self._responder({"/api/health": (200, "{}", "")}),
                              allowed_hosts=["other.test"],
                              prefixes=["/api/"], collections=[], nouns=["health"])
        # base_url host is target.test, not in allowed_hosts -> _probe short-circuits.
        # Override _probe path uses the real scope check via super? No: fake bypasses
        # network but we assert the real SurfaceDiscovery._probe gate here instead.
        real = SurfaceDiscovery("http://target.test", allowed_hosts=["other.test"])
        self.assertIsNone(asyncio.run(real._probe("GET", "/api/health")))

    def test_budget_cap_is_respected(self):
        calls = {"n": 0}
        def r(method, path):
            calls["n"] += 1
            return (500, _NF, "")
        disc = _FakeDiscovery(r, prefixes=["/api/"], collections=["a", "b"],
                              nouns=["x", "y", "z"], max_probes=5)
        res = _run(disc)
        self.assertLessEqual(res.probes_sent, 5)  # every phase is budget-guarded


class SpecTests(unittest.TestCase):
    def test_spec_paths_parsed(self):
        body = '{"openapi":"3.0.0","paths":{"/api/a":{},"/api/b/{id}":{},"bad":{}}}'
        self.assertEqual(sorted(_paths_from_spec(body)), ["/api/a", "/api/b/{id}"])

    def test_spec_probe_supplies_surface(self):
        spec = '{"openapi":"3.0.0","paths":{"/api/secret/route":{},"/api/other":{}}}'
        def r(method, path):
            if path == "/openapi.json":
                return (200, spec, "")
            return (500, _NF, "")
        disc = _FakeDiscovery(r, prefixes=["/api/"], collections=[], nouns=["nope"])
        res = _run(disc)
        self.assertEqual(res.spec_found, "/openapi.json")
        self.assertIn("/api/secret/route", res.paths())


if __name__ == "__main__":
    unittest.main()
