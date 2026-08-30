"""
Answers template. Copy this file, fill in ANSWERS based on the REAL
prompts you read in your transcript.json from `harness_driver.py record`,
then pass your copy to `harness_driver.py run --answers your_file.py`.

RULES FOR ANSWERING GENUINELY (this is the entire point of the exercise):
- Read ONLY what's in that entry's user_prompt. Don't use outside
  knowledge about the target -- if you've explored it yourself via curl/
  Burp, that's fine and expected (that's how you built your exchange
  list), but when deciding what a given agent call would output, act as
  if you only know what's in front of you in that specific prompt.
- If a header is shown as "[REDACTED -- ...]", the agent genuinely can't
  see that value. Don't reason as if you know what's behind the
  redaction.
- Confidence should reflect what the evidence in THIS ONE exchange
  actually supports -- a plausible-looking numeric ID with no baseline
  comparison is a candidate, not a confirmed finding. See the
  "MOMENTARY NOTES" / "METHODOLOGY NOTES" block in each prompt for
  guidance on what would actually confirm a finding in that category.
- If nothing in the evidence supports a finding for that agent's
  specialty, return an empty findings list. Don't manufacture a finding
  to seem thorough -- an empty, honest answer is a valid and often
  correct response.
- basis must be one of: "derived" (reasoned from this exchange's actual
  content), "recalled" (general knowledge of the vulnerability class,
  not specific to this exchange), "assumed" (guessing about something
  the exchange doesn't show).

FINDING SCHEMA (must match harness/models.py's Finding class):
{
    "vulnerability_class": str,
    "confidence": float,        # 0.0-1.0
    "severity": str,            # "info"|"low"|"medium"|"high"|"critical"
    "owasp_category": str | None,
    "summary": str,
    "evidence": str,
    "suggested_test": str,
    "basis": str,               # "derived"|"recalled"|"assumed"
    "validation_hints": list[str],  # usually [] -- only real validator
                                     # capability names, e.g. "sqlmap"
}

COMPONENT SCHEMA (must match ComponentCandidate in harness/models.py):
{
    "ecosystem": str,   # "npm"|"PyPI"|"Maven"|"RubyGems"|"Go"|"generic"
    "name": str,
    "version": str | None,
    "source": str,      # where you saw this, e.g. "Server response header"
}
"""

EMPTY = {"findings": [], "components": []}

# Keyed by (exchange_index, agent_name) -> response dict. Fill this in
# based on your own transcript.json.
ANSWERS = {
    # Example:
    # (0, "sqli"): {
    #     "findings": [{
    #         "vulnerability_class": "sqli",
    #         "confidence": 0.9,
    #         "severity": "critical",
    #         "owasp_category": "A03:2021-Injection",
    #         "summary": "...",
    #         "evidence": "...",
    #         "suggested_test": "...",
    #         "basis": "derived",
    #         "validation_hints": [],
    #     }],
    #     "components": [],
    # },
}

# Agents like misconfig/supply_chain/api_security tend to fire on nearly
# every exchange for reasons unrelated to the vulnerability under test
# (a version banner header, an /api/ URL prefix). If your target repeats
# the same low-value signal on every request, consider reporting it once
# and returning EMPTY afterward, the way a disciplined agent shown
# "already flagged on this host" prior-findings context would. This is
# optional -- simplest is to just judge each one honestly from what's
# shown.


def get_answer(exchange_index: int, agent_name: str) -> dict:
    return ANSWERS.get((exchange_index, agent_name), EMPTY)
