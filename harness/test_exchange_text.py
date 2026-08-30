"""
Tests for exchange_text.py -- the shared helper extracted to fix a real,
silently-diverged duplicate found during audit: orchestrator.py's
_exchange_text() included exchange.analyst_note; analysis_pipeline.py's
copy of the same logic did not. Both now delegate to this one function.
"""
import unittest

from exchange_text import exchange_text
from models import HttpExchange


def _exchange_with_note(note: str) -> HttpExchange:
    return HttpExchange(
        url="https://example.com/x",
        method="GET",
        request_headers={"X-Req": "reqval"},
        response_headers={"X-Resp": "respval"},
        request_body="reqbody",
        response_body="respbody",
        analyst_note=note,
    )


class ExchangeTextIncludesEverythingTests(unittest.TestCase):
    def test_analyst_note_is_included(self):
        """
        The specific regression: analysis_pipeline.py's old duplicate
        omitted analyst_note entirely, meaning a note like "this looks
        like log4j 2.14" could count as component-observation evidence
        via orchestrator.py's path but not analysis_pipeline.py's.
        """
        ex = _exchange_with_note("looks like log4j 2.14 based on the stack trace")
        text = exchange_text(ex)
        self.assertIn("log4j 2.14", text)

    def test_headers_bodies_and_url_are_all_included(self):
        ex = _exchange_with_note("")
        text = exchange_text(ex)
        for expected in ("example.com/x", "reqbody", "respbody", "X-Req", "reqval", "X-Resp", "respval"):
            self.assertIn(expected, text)


class BothCallersProduceIdenticalTextTests(unittest.TestCase):
    """
    Confirms orchestrator.py and analysis_pipeline.py now genuinely agree,
    not just that each individually calls the shared function -- a
    regression here would mean one of them started passing extra/fewer
    fields, silently reintroducing exactly the divergence this file
    exists to prevent.
    """

    def test_orchestrator_and_analysis_pipeline_agree(self):
        import orchestrator
        from analysis_pipeline import AnalysisPipeline

        ex = _exchange_with_note("some analyst note with a version string 4.17.21")

        orchestrator_text = orchestrator._exchange_text(ex)

        # AnalysisPipeline._exchange_text is an instance method but does
        # not touch `self` beyond delegating -- call it unbound-style on
        # a bare object to avoid constructing the full pipeline (which
        # needs a config dict and several sub-clients) just for this.
        pipeline_text = AnalysisPipeline._exchange_text(object(), ex)

        self.assertEqual(orchestrator_text, pipeline_text)


if __name__ == "__main__":
    unittest.main()
