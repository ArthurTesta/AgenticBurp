"""
Tests for the fast-path agent selection module.

These tests verify:
1. Fast-path selection works for various patterns
2. Selection is always a subset of available agents
3. Early termination logic works correctly
4. Pattern matching is accurate
5. Stats tracking works
"""
import unittest
from models import HttpExchange, AgentReport, Finding
from fast_path import (
    select_agents_by_url,
    select_agents_by_query_params,
    select_agents_by_request_headers,
    select_agents_by_method,
    select_agents_by_status,
    select_agents_by_response_body,
    select_agents_by_response_headers,
    select_fast_path_agents,
    should_terminate_early,
    EarlyTerminationConfig,
    FastPathSelector,
    _URL_PATTERNS,
    _QUERY_PARAM_PATTERNS,
)


class TestUrlPatterns(unittest.TestCase):
    """Test URL pattern matching."""
    
    def test_graphql_endpoint(self):
        """GraphQL endpoints should select sqli, idor, business_logic."""
        agents = select_agents_by_url("/api/graphql")
        self.assertIn("sqli", agents)
        self.assertIn("idor", agents)
        self.assertIn("business_logic", agents)
    
    def test_admin_endpoint(self):
        """Admin endpoints should select auth, idor, misconfig."""
        agents = select_agents_by_url("/admin/users")
        self.assertIn("auth", agents)
        self.assertIn("idor", agents)
        self.assertIn("misconfig", agents)
    
    def test_login_endpoint(self):
        """Login endpoints should select auth, business_logic."""
        agents = select_agents_by_url("/login")
        self.assertIn("auth", agents)
        self.assertIn("business_logic", agents)
    
    def test_api_endpoint(self):
        """API endpoints should select multiple agents."""
        agents = select_agents_by_url("/api/v1/users")
        self.assertGreaterEqual(len(agents), 3)
    
    def test_upload_endpoint(self):
        """Upload endpoints should select xss, misconfig, supply_chain."""
        agents = select_agents_by_url("/upload")
        self.assertIn("xss", agents)
        self.assertIn("misconfig", agents)
        self.assertIn("supply_chain", agents)
    
    def test_user_endpoint(self):
        """User endpoints should select idor, auth, misconfig."""
        agents = select_agents_by_url("/users/123")
        self.assertIn("idor", agents)
        self.assertIn("auth", agents)
        self.assertIn("misconfig", agents)
    
    def test_unknown_endpoint(self):
        """Unknown endpoints should return empty set."""
        agents = select_agents_by_url("/completely/unknown/path")
        self.assertEqual(len(agents), 0)
    
    def test_case_insensitive_matching(self):
        """Pattern matching should be case-insensitive."""
        agents_lower = select_agents_by_url("/api/graphql")
        agents_upper = select_agents_by_url("/API/GRAPHQL")
        self.assertEqual(agents_lower, agents_upper)


class TestQueryParamPatterns(unittest.TestCase):
    """Test query parameter pattern matching."""
    
    def test_id_parameter(self):
        """ID parameters should select idor, sqli."""
        agents = select_agents_by_query_params("id=123&name=test")
        self.assertIn("idor", agents)
        self.assertIn("sqli", agents)
    
    def test_search_parameter(self):
        """Search parameters should select sqli, xss."""
        agents = select_agents_by_query_params("q=test&page=1")
        self.assertIn("sqli", agents)
        self.assertIn("xss", agents)
    
    def test_file_parameter(self):
        """File parameters should select ssrf, misconfig."""
        agents = select_agents_by_query_params("file=/etc/passwd")
        self.assertIn("ssrf", agents)
        self.assertIn("misconfig", agents)
    
    def test_token_parameter(self):
        """Token parameters should select auth, misconfig."""
        agents = select_agents_by_query_params("token=abc123")
        self.assertIn("auth", agents)
        self.assertIn("misconfig", agents)
    
    def test_empty_query_string(self):
        """Empty query string should return empty set."""
        agents = select_agents_by_query_params("")
        self.assertEqual(len(agents), 0)


class TestMethodPatterns(unittest.TestCase):
    """Test HTTP method pattern matching."""
    
    def test_get_method(self):
        """GET should select multiple agents."""
        agents = select_agents_by_method("GET")
        self.assertGreaterEqual(len(agents), 3)
        self.assertIn("sqli", agents)
        self.assertIn("xss", agents)
    
    def test_post_method(self):
        """POST should select multiple agents including auth."""
        agents = select_agents_by_method("POST")
        self.assertIn("auth", agents)
        self.assertIn("business_logic", agents)
    
    def test_delete_method(self):
        """DELETE should select idor, auth, business_logic."""
        agents = select_agents_by_method("DELETE")
        self.assertIn("idor", agents)
        self.assertIn("auth", agents)
        self.assertIn("business_logic", agents)
    
    def test_head_method(self):
        """HEAD should select misconfig."""
        agents = select_agents_by_method("HEAD")
        self.assertIn("misconfig", agents)
    
    def test_unknown_method(self):
        """Unknown methods should return empty set."""
        agents = select_agents_by_method("UNKNOWN")
        self.assertEqual(len(agents), 0)


class TestStatusPatterns(unittest.TestCase):
    """Test response status code pattern matching."""
    
    def test_200_status(self):
        """200 should select multiple agents."""
        agents = select_agents_by_status(200)
        self.assertGreaterEqual(len(agents), 5)
    
    def test_401_status(self):
        """401 should select auth, misconfig."""
        agents = select_agents_by_status(401)
        self.assertIn("auth", agents)
        self.assertIn("misconfig", agents)
    
    def test_403_status(self):
        """403 should select auth, idor, misconfig."""
        agents = select_agents_by_status(403)
        self.assertIn("auth", agents)
        self.assertIn("idor", agents)
        self.assertIn("misconfig", agents)
    
    def test_500_status(self):
        """500 should select misconfig, supply_chain."""
        agents = select_agents_by_status(500)
        self.assertIn("misconfig", agents)
        self.assertIn("supply_chain", agents)
    
    def test_none_status(self):
        """None status should return empty set."""
        agents = select_agents_by_status(None)
        self.assertEqual(len(agents), 0)


class TestResponseBodyPatterns(unittest.TestCase):
    """Test response body pattern matching."""
    
    def test_sql_error(self):
        """SQL errors should select sqli."""
        agents = select_agents_by_response_body("SQL syntax error near 'OR'")
        self.assertIn("sqli", agents)
    
    def test_stack_trace(self):
        """Stack traces should select misconfig, supply_chain."""
        agents = select_agents_by_response_body("at com.example.Service.method(Service.java:42)")
        self.assertIn("misconfig", agents)
        self.assertIn("supply_chain", agents)
    
    def test_version_banner(self):
        """Version banners should select misconfig, supply_chain."""
        agents = select_agents_by_response_body("Apache/2.4.41")
        self.assertIn("misconfig", agents)
        self.assertIn("supply_chain", agents)
    
    def test_html_response(self):
        """HTML responses should select xss, misconfig."""
        agents = select_agents_by_response_body("<html><body>Test</body></html>")
        self.assertIn("xss", agents)
        self.assertIn("misconfig", agents)
    
    def test_empty_body(self):
        """Empty body should return empty set."""
        agents = select_agents_by_response_body("")
        self.assertEqual(len(agents), 0)


class TestRequestHeaderPatterns(unittest.TestCase):
    """Test request header pattern matching."""
    
    def test_json_content_type(self):
        """JSON content type should select multiple agents."""
        headers = {"Content-Type": "application/json"}
        agents = select_agents_by_request_headers(headers)
        self.assertIn("sqli", agents)
        self.assertIn("xss", agents)
    
    def test_form_content_type(self):
        """Form content type should select sqli, xss, idor."""
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        agents = select_agents_by_request_headers(headers)
        self.assertIn("sqli", agents)
        self.assertIn("xss", agents)
        self.assertIn("idor", agents)
    
    def test_authorization_header(self):
        """Authorization header should select auth."""
        headers = {"Authorization": "Bearer token123"}
        agents = select_agents_by_request_headers(headers)
        self.assertIn("auth", agents)
    
    def test_basic_auth_header(self):
        """Basic auth header should select auth."""
        headers = {"Authorization": "Basic dXNlcjpwYXNz"}
        agents = select_agents_by_request_headers(headers)
        self.assertIn("auth", agents)


class TestFastPathSelection(unittest.TestCase):
    """Test complete fast-path agent selection."""
    
    def test_graphql_endpoint_selection(self):
        """GraphQL endpoint should select agents without coordinator."""
        exchange = HttpExchange(
            url="https://example.com/graphql",
            method="POST",
            request_headers={"Content-Type": "application/json"},
            request_body='{"query": "{ users { id } }"}',
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"data": {"users": []}}',
        )
        
        available = {"sqli", "xss", "idor", "ssrf", "auth", "business_logic", "misconfig"}
        result = select_fast_path_agents(exchange, available)
        
        self.assertIsNotNone(result[0])
        self.assertIn("sqli", result[0])
        self.assertIn("idor", result[0])
        self.assertIn("URL pattern", result[1])
    
    def test_login_endpoint_selection(self):
        """Login endpoint should select auth, business_logic."""
        exchange = HttpExchange(
            url="https://example.com/login",
            method="POST",
            request_headers={"Content-Type": "application/x-www-form-urlencoded"},
            request_body="username=test&password=test",
            response_status=200,
            response_headers={},
            response_body="",
        )
        
        available = {"sqli", "xss", "idor", "ssrf", "auth", "business_logic", "misconfig"}
        result = select_fast_path_agents(exchange, available)
        
        self.assertIsNotNone(result[0])
        self.assertIn("auth", result[0])
        self.assertIn("business_logic", result[0])
    
    def test_sql_error_response_selection(self):
        """SQL error in response should select sqli."""
        exchange = HttpExchange(
            url="https://example.com/api/users",
            method="GET",
            request_headers={},
            request_body="",
            response_status=500,
            response_headers={"Content-Type": "text/html"},
            response_body="SQL syntax error near 'OR'",
        )
        
        available = {"sqli", "xss", "idor"}
        result = select_fast_path_agents(exchange, available)
        
        self.assertIsNotNone(result[0])
        self.assertIn("sqli", result[0])
    
    def test_no_match_falls_back_to_coordinator(self):
        """Unknown patterns should fall back to coordinator."""
        exchange = HttpExchange(
            url="https://example.com/completely/unknown",
            method="GET",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="Unknown content",
        )
        
        available = {"sqli", "xss"}
        result = select_fast_path_agents(exchange, available)
        
        self.assertIsNone(result[0])
        self.assertEqual(result[1], "")
    
    def test_available_agents_filtering(self):
        """Selected agents should be filtered by available agents."""
        exchange = HttpExchange(
            url="https://example.com/graphql",
            method="POST",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="",
        )
        
        # Only sqli is available
        available = {"sqli"}
        result = select_fast_path_agents(exchange, available)
        
        self.assertIsNotNone(result[0])
        self.assertEqual(result[0], ["sqli"])


class TestEarlyTermination(unittest.TestCase):
    """Test early termination logic."""
    
    def create_report(self, vulnerability_class: str, confidence: float, severity: str) -> AgentReport:
        """Helper to create test reports."""
        return AgentReport(
            agent="test_agent",
            model="test_model",
            findings=[
                Finding(
                    vulnerability_class=vulnerability_class,
                    confidence=confidence,
                    severity=severity,
                    summary="Test finding",
                    evidence="test",
                    suggested_test="test",
                    basis="derived",
                )
            ],
        )
    
    def test_early_termination_on_critical_finding(self):
        """Should terminate early on high-confidence critical finding."""
        config = EarlyTerminationConfig(
            enabled=True,
            min_confidence=0.9,
            min_severity={"critical", "high"},
            max_agents_before_check=2,
        )
        
        reports = [
            self.create_report("sqli", 0.95, "critical"),
            self.create_report("xss", 0.8, "medium"),
        ]
        
        result = should_terminate_early(reports, ["idor", "ssrf"], config)
        
        self.assertTrue(result[0])
        self.assertIn("critical", result[1])
    
    def test_no_early_termination_on_low_confidence(self):
        """Should not terminate early on low-confidence findings."""
        config = EarlyTerminationConfig(
            enabled=True,
            min_confidence=0.9,
            min_severity={"critical", "high"},
            max_agents_before_check=2,
        )
        
        reports = [
            self.create_report("sqli", 0.7, "high"),
            self.create_report("xss", 0.8, "medium"),
        ]
        
        result = should_terminate_early(reports, ["idor", "ssrf"], config)
        
        self.assertFalse(result[0])
    
    def test_no_early_termination_on_low_severity(self):
        """Should not terminate early on low-severity findings."""
        config = EarlyTerminationConfig(
            enabled=True,
            min_confidence=0.9,
            min_severity={"critical", "high"},
            max_agents_before_check=2,
        )
        
        reports = [
            self.create_report("sqli", 0.95, "medium"),
            self.create_report("xss", 0.9, "low"),
        ]
        
        result = should_terminate_early(reports, ["idor", "ssrf"], config)
        
        self.assertFalse(result[0])
    
    def test_early_termination_disabled(self):
        """Should not terminate early when disabled."""
        config = EarlyTerminationConfig(enabled=False)
        
        reports = [self.create_report("sqli", 0.95, "critical")]
        
        result = should_terminate_early(reports, ["idor"], config)
        
        self.assertFalse(result[0])
    
    def test_early_termination_min_agents(self):
        """Should not terminate before min agents have run."""
        config = EarlyTerminationConfig(
            enabled=True,
            min_confidence=0.9,
            min_severity={"critical", "high"},
            max_agents_before_check=5,
        )
        
        reports = [self.create_report("sqli", 0.95, "critical")]
        
        result = should_terminate_early(reports, ["idor", "xss", "ssrf", "auth"], config)
        
        self.assertFalse(result[0])


class TestFastPathSelector(unittest.TestCase):
    """Test the FastPathSelector class."""
    
    def setUp(self):
        """Set up test selector."""
        self.available = {"sqli", "xss", "idor", "ssrf", "auth", "business_logic", "misconfig"}
        self.selector = FastPathSelector(self.available)
    
    def test_fast_path_hit_tracking(self):
        """Fast-path hits should be tracked."""
        exchange = HttpExchange(
            url="https://example.com/graphql",
            method="POST",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="",
        )
        
        self.selector.select_agents(exchange)
        
        stats = self.selector.get_stats()
        self.assertEqual(stats['fast_path_hits'], 1)
    
    def test_fast_path_miss_tracking(self):
        """Fast-path misses should be tracked."""
        exchange = HttpExchange(
            url="https://example.com/unknown",
            method="GET",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="",
        )
        
        self.selector.select_agents(exchange)
        
        stats = self.selector.get_stats()
        self.assertEqual(stats['fast_path_misses'], 1)
    
    def test_early_termination_tracking(self):
        """Early terminations should be tracked."""
        from models import AgentReport, Finding
        
        # Update config to allow early termination with 1 report
        self.selector.early_term_config = EarlyTerminationConfig(
            enabled=True,
            min_confidence=0.9,
            min_severity={"critical", "high"},
            max_agents_before_check=1,
        )
        
        report = AgentReport(
            agent="sqli",
            model="test",
            findings=[
                Finding(
                    vulnerability_class="sqli",
                    confidence=0.95,
                    severity="critical",
                    summary="Test",
                    evidence="test",
                    suggested_test="test",
                    basis="derived",
                )
            ],
        )
        self.selector.check_early_termination([report], ["xss", "idor"])
        stats = self.selector.get_stats()
        self.assertEqual(stats['early_terminations'], 1)
    def test_reset_stats(self):
        """Stats should be resettable."""
        exchange = HttpExchange(
            url="https://example.com/graphql",
            method="POST",
            request_headers={},
            request_body="",
            response_status=200,
            response_headers={},
            response_body="",
        )
        
        self.selector.select_agents(exchange)
        self.selector.reset_stats()
        
        stats = self.selector.get_stats()
        self.assertEqual(stats['fast_path_hits'], 0)


if __name__ == "__main__":
    unittest.main()
