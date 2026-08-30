"""
Tests for coordinator.py -- no test file existed for this module before
this one. HANDOVER.md flagged its fail-open behavior (falling back to
ALL available agents when the routing LLM errors or returns nothing
usable) as "never verified under live traffic" -- fast_path.py now
handles the overwhelming majority of real exchanges, so the coordinator
essentially never fires in practice, which also means these code paths
had never run against anything, mocked or real, before this file existed.
"""
import unittest
from unittest.mock import AsyncMock

from coordinator import Coordinator
from models import HttpExchange
from ollama_client import OllamaError, OllamaResult


def _exchange(url="https://example.test/about", method="GET"):
    return HttpExchange(
        url=url, method=method, request_headers={}, request_body="",
        response_status=200, response_headers={}, response_body="<html>ok</html>",
    )


class CoordinatorDispatchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.ollama = AsyncMock()
        self.coordinator = Coordinator(self.ollama, {"model": "llama3.1:8b"})
        self.available = ["sqli", "xss", "idor", "auth", "misconfig"]

    async def test_valid_dispatch_is_returned_as_is(self):
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": ["idor", "auth"], "reason": "numeric id + no auth header"},
            prompt_tokens=10, completion_tokens=5,
        )
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, ["idor", "auth"])
        self.assertEqual(reason, "numeric id + no auth header")

    async def test_dispatch_is_filtered_to_available_agents_only(self):
        """The routing model can only see the names it was given, but
        nothing stops it hallucinating one anyway -- silently trusting an
        unavailable agent name would crash downstream dispatch."""
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": ["idor", "graphql", "ssti"], "reason": "r"},
            prompt_tokens=10, completion_tokens=5,
        )
        dispatch, _ = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, ["idor"])

    async def test_empty_dispatch_falls_back_to_all_available_agents(self):
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": [], "reason": "nothing plausible"},
            prompt_tokens=10, completion_tokens=5,
        )
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, self.available)
        self.assertIn("fallback", reason)

    async def test_dispatch_of_only_unavailable_agents_falls_back(self):
        """Filtering can reduce a non-empty model response to an empty
        one -- that must hit the same fallback as an originally-empty
        dispatch, not silently return an empty list."""
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"dispatch": ["graphql", "ssti"], "reason": "r"},
            prompt_tokens=10, completion_tokens=5,
        )
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, self.available)
        self.assertIn("fallback", reason)

    async def test_malformed_json_response_falls_back(self):
        """chat_json_metered raises OllamaError when the model doesn't
        return valid/parseable JSON -- the coordinator must not propagate
        that as an unhandled exception up through analyze()."""
        self.ollama.chat_json_metered.side_effect = OllamaError("not valid JSON")
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, self.available)
        self.assertIn("fallback", reason)
        self.assertIn("coordinator error", reason)

    async def test_missing_dispatch_key_falls_back(self):
        """A well-formed JSON object that simply doesn't use the
        requested shape (e.g. the model answers conversationally inside
        valid JSON) must be treated the same as an empty dispatch, not
        raise a KeyError."""
        self.ollama.chat_json_metered.return_value = OllamaResult(
            data={"answer": "no vulnerabilities here"}, prompt_tokens=10, completion_tokens=5,
        )
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, self.available)
        self.assertIn("fallback", reason)

    async def test_generic_exception_from_ollama_falls_back(self):
        """Any unexpected exception (network error, timeout, circuit
        breaker open) must degrade to fail-open, never propagate."""
        self.ollama.chat_json_metered.side_effect = RuntimeError("connection reset")
        dispatch, reason = await self.coordinator.choose_agents(_exchange(), self.available)
        self.assertEqual(dispatch, self.available)
        self.assertIn("fallback", reason)


if __name__ == "__main__":
    unittest.main()
