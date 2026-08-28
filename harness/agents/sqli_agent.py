from .base_agent import BaseAgent


class SqliAgent(BaseAgent):
    name = "sqli"

    @property
    def specialty_prompt(self) -> str:
        return """
SQL injection. Look at parameters (query string, form body, JSON fields,
cookies, headers) that appear to flow into a database query: IDs, sort/order
fields, filter fields, search boxes, "type" or "category" style selectors.

Signals worth flagging (each on its own, moderate confidence at most without
more evidence):
- Numeric- or string-looking identifiers used directly in the URL/body.
- Error responses (5xx, stack traces, DB engine names/messages, ODBC/JDBC
  strings, "syntax error", "unclosed quotation mark") in the response body.
- Behavioral differences implied by the response that suggest the input
  reaches a query unsanitized (this exchange alone usually can't prove
  that -- say so and propose the boundary test that would).
- ORDER BY / sort parameters, which are commonly injectable and commonly
  missed by naive filters.

For suggested_test, name the specific parameter and a standard boundary
probe (e.g. append a single quote, or a numeric offset like id-0, or a
sleep-based timing probe) and what response difference would confirm it --
do not invent novel bypass techniques, just the standard diagnostic step.
"""
