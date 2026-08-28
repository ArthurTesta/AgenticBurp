import unittest
from models import HttpExchange
from agents.base_agent import _redact_headers, BaseAgent


class RedactHeadersTests(unittest.TestCase):
    def test_authorization_and_cookie_values_redacted(self):
        headers = {"Authorization": "Bearer secret-token-abc", "Cookie": "session=deadbeef", "Content-Type": "application/json"}
        out = _redact_headers(headers)
        self.assertNotIn("secret-token-abc", out["Authorization"])
        self.assertNotIn("deadbeef", out["Cookie"])
        self.assertEqual(out["Content-Type"], "application/json")

    def test_header_names_preserved_even_when_redacted(self):
        out = _redact_headers({"Authorization": "Bearer x"})
        self.assertIn("Authorization", out)  # name stays -- agent still knows a session exists

    def test_case_insensitive_matching(self):
        out = _redact_headers({"AUTHORIZATION": "Bearer x", "cookie": "y"})
        self.assertNotIn("Bearer x", out["AUTHORIZATION"])
        self.assertNotIn("y", out["cookie"])

    def test_x_api_key_and_proxy_auth_also_redacted(self):
        out = _redact_headers({"X-API-Key": "k1", "Proxy-Authorization": "Basic abc"})
        self.assertNotIn("k1", out["X-API-Key"])
        self.assertNotIn("abc", out["Proxy-Authorization"])

    def test_non_secret_headers_untouched(self):
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}
        self.assertEqual(_redact_headers(headers), headers)


class DummyAgent(BaseAgent):
    name = "dummy"
    @property
    def specialty_prompt(self):
        return "dummy specialty"


class UserPromptRedactionTests(unittest.TestCase):
    def test_user_prompt_never_contains_raw_secret_values(self):
        agent = DummyAgent(ollama=None, model="m")
        exchange = HttpExchange(
            url="https://a.test/x", method="GET",
            request_headers={"Authorization": "Bearer super-secret-token-123", "Cookie": "session=abc123xyz"},
            response_headers={"Set-Cookie": "session=abc123xyz; HttpOnly"},
        )
        prompt = agent._user_prompt(exchange, max_body_chars=1000)
        self.assertNotIn("super-secret-token-123", prompt)
        self.assertNotIn("abc123xyz", prompt)
        self.assertIn("Authorization", prompt)  # the fact of the header is still visible


class PromptVersionTests(unittest.TestCase):
    def test_prompt_version_is_stable_hash_of_system_prompt(self):
        agent = DummyAgent(ollama=None, model="m")
        v1 = agent._prompt_version()
        v2 = agent._prompt_version()
        self.assertEqual(v1, v2)
        self.assertEqual(len(v1), 12)

    def test_different_specialty_prompts_produce_different_versions(self):
        class OtherAgent(BaseAgent):
            name = "other"
            @property
            def specialty_prompt(self):
                return "a different specialty"
        a = DummyAgent(ollama=None, model="m")
        b = OtherAgent(ollama=None, model="m")
        self.assertNotEqual(a._prompt_version(), b._prompt_version())


if __name__ == "__main__":
    unittest.main()
