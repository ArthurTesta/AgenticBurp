"""
Tests for AnalysisPipeline, focused on the injected-ollama_client fix.

Before this fix, AnalysisPipeline._critique() constructed a brand-new
OllamaClient() inline on every call -- meaning its circuit breaker was
always freshly-CLOSED and could never accumulate failures the way the
main dispatch path's long-lived client's breaker does. This file exists
so that regression is caught by the test suite, not rediscovered by a
future audit.
"""
import unittest
from unittest.mock import AsyncMock, MagicMock

from analysis_pipeline import AnalysisPipeline
from models import Finding, HttpExchange


def _make_pipeline(ollama_client=None) -> AnalysisPipeline:
    agent_manager = MagicMock()
    effort_budget = MagicMock()
    store = MagicMock()
    # Every _init_clients lookup other than the ollama fallback uses
    # .get() with a default; "ollama" is only required when no client is
    # injected (the fallback-construction path), so it's harmless to
    # always include it here.
    config: dict = {"ollama": {"base_url": "http://example.invalid"}}
    return AnalysisPipeline(agent_manager, effort_budget, store, config, ollama_client=ollama_client)


def _make_report(finding: Finding):
    from models import AgentReport
    return AgentReport(agent="test_agent", model="m", findings=[finding])


def _make_finding(confidence: float = 0.9) -> Finding:
    return Finding(
        vulnerability_class="sqli",
        confidence=confidence,
        summary="s",
        evidence="e",
        suggested_test="t",
        basis="derived",
    )


class InjectedOllamaClientTests(unittest.TestCase):
    def test_pipeline_stores_the_injected_client_instead_of_building_one(self):
        fake_client = MagicMock()
        pipeline = _make_pipeline(ollama_client=fake_client)
        self.assertIs(pipeline.ollama_client, fake_client)

    def test_pipeline_without_an_injected_client_builds_a_standalone_one(self):
        # Documents the fallback path explicitly: still works, but the
        # docstring/log message says its breaker is not shared with
        # anything, which callers need to know if they rely on it.
        pipeline = _make_pipeline(ollama_client=None)
        self.assertIsNotNone(pipeline.ollama_client)


class CritiqueUsesInjectedClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_critique_calls_chat_json_metered_on_the_injected_client(self):
        """
        The actual regression test: _critique() must call
        chat_json_metered on the client that was injected at
        construction time, not build a new OllamaClient inline.
        """
        fake_client = MagicMock()
        fake_result = MagicMock()
        fake_result.data = {"reviews": []}
        fake_client.chat_json_metered = AsyncMock(return_value=fake_result)

        pipeline = _make_pipeline(ollama_client=fake_client)
        pipeline.config = {
            "critique": {"enabled": True, "confidence_threshold": 0.5, "max_findings": 12},
            "coordinator": {"model": "test-model"},
        }

        exchange = HttpExchange(url="https://example.com/x", method="GET")
        finding = _make_finding(confidence=0.9)
        reports = [_make_report(finding)]

        await pipeline._critique(exchange, reports)

        fake_client.chat_json_metered.assert_awaited_once()

    async def test_critique_does_not_construct_a_second_ollama_client(self):
        """
        Guards against a regression that keeps the injected client around
        but still builds a second, throwaway one somewhere in _critique
        (which would silently reintroduce the unshared-breaker bug even
        though the constructor-level fix looks complete).
        """
        import analysis_pipeline as ap_module

        fake_client = MagicMock()
        fake_result = MagicMock()
        fake_result.data = {"reviews": []}
        fake_client.chat_json_metered = AsyncMock(return_value=fake_result)

        pipeline = _make_pipeline(ollama_client=fake_client)
        pipeline.config = {
            "critique": {"enabled": True, "confidence_threshold": 0.5, "max_findings": 12},
            "coordinator": {"model": "test-model"},
        }

        exchange = HttpExchange(url="https://example.com/x", method="GET")
        reports = [_make_report(_make_finding(confidence=0.9))]

        with unittest.mock.patch("ollama_client.OllamaClient") as mock_cls:
            await pipeline._critique(exchange, reports)
            mock_cls.assert_not_called()


if __name__ == "__main__":
    unittest.main()
