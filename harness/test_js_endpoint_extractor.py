"""Tests for JS/HTML endpoint extraction (sitemap population)."""
import unittest
from js_endpoint_extractor import extract_endpoints


class JsEndpointExtractorTests(unittest.TestCase):
    def test_fetch_and_axios_calls_are_captured_and_tagged(self):
        js = '''
          fetch("/api/tickets").then(r=>r.json());
          axios.get(`/rest/user/${userId}`);
          $.ajax({url:"/api/admin/config"});
          xhr.open("POST", "/api/login");
        '''
        r = extract_endpoints(js, "https://app.test/main.js")
        self.assertIn("/api/tickets", r.same_origin_paths)
        self.assertIn("/rest/user/{id}", r.same_origin_paths)   # template literal normalized
        self.assertIn("/api/login", r.same_origin_paths)
        self.assertIn("/api/tickets", r.from_request_calls)
        self.assertIn("/api/login", r.from_request_calls)

    def test_bare_path_literals_captured(self):
        js = 'const routes = ["/api/orders", "/api/orders/42", "/health"];'
        r = extract_endpoints(js, "https://app.test/main.js")
        self.assertIn("/api/orders", r.same_origin_paths)
        self.assertIn("/api/orders/{id}", r.same_origin_paths)  # numeric id normalized
        self.assertIn("/health", r.same_origin_paths)

    def test_assets_and_noise_are_dropped(self):
        js = '"/assets/logo.svg"; "/static/app.css"; "/main.js"; "/node_modules/x"; "//cdn.io/x"; "/"'
        r = extract_endpoints(js, "https://app.test/main.js")
        self.assertEqual(r.same_origin_paths, set())

    def test_absolute_same_origin_vs_external(self):
        js = '"https://app.test/api/internal"; "https://evil.cdn.com/track.js"; "https://api.other.com/v1/data"'
        r = extract_endpoints(js, "https://app.test/main.js")
        self.assertIn("/api/internal", r.same_origin_paths)     # same host -> path
        self.assertIn("https://api.other.com/v1/data", r.external_urls)
        # external asset (.js) is dropped from external too
        self.assertNotIn("https://evil.cdn.com/track.js", r.external_urls)

    def test_no_code_fragments_leak_in(self):
        js = 'if (a</b) {} func(x); const re = /\\/api\\//g;'
        r = extract_endpoints(js, "https://app.test/main.js")
        for p in r.same_origin_paths:
            self.assertNotIn("<", p)
            self.assertNotIn("(", p)

    def test_empty_body(self):
        self.assertEqual(extract_endpoints("", "https://app.test/").same_origin_paths, set())

    def test_param_forms_normalize_together(self):
        js = '"/user/:id"; "/user/${id}"; "/user/7"'
        r = extract_endpoints(js, "https://app.test/x.js")
        self.assertEqual({p for p in r.same_origin_paths if p.startswith("/user")}, {"/user/{id}"})


if __name__ == "__main__":
    unittest.main()
