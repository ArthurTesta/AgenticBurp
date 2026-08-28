from __future__ import annotations

"""
Canonical vulnerability categories, and normalization from the free-text
`vulnerability_class` string an LLM specialist writes into one of them.

Why this exists
----------------
`Finding.vulnerability_class` is genuinely free text (see base_agent.py's
prompt -- there is no enum constraint on what the model writes). Before
this module existed, planner.py matched that free text against
capability keys with an EXACT lowercase string comparison. If the idor
agent wrote "Insecure Direct Object Reference" or "IDOR" instead of the
literal string "idor", the lookup silently failed: no TestPlan was ever
created, no error was raised, and nothing downstream (including an
analyst reading the response) had any indication that a plan should
have existed and didn't. This is exactly the kind of silent gap the
project's own "known vs rediscover" and confirmation-honesty principles
exist to prevent -- it just happened to live in the plumbing rather
than in a finding's confidence number.

CANONICAL_CATEGORIES intentionally matches the specialist agent names in
orchestrator.py's _AGENT_CLASSES, since that mapping (AgentReport.agent)
IS reliable -- it's set programmatically by each agent class, never by
model output. Category-derived logic (the coverage ledger, capability
planning) should key off this canonical set, not off raw
vulnerability_class strings.
"""

CANONICAL_CATEGORIES: tuple[str, ...] = (
    "sqli", "xss", "idor", "ssrf", "auth", "business_logic",
    "business_logic_enhanced", "misconfig", "ai_llm", "supply_chain", "rate_limit",
    "jwt", "xxe", "csrf", "file_upload", "nosql",
    "command_injection", "ssti", "open_redirect", "info_disclosure",
    "anomaly",
)

# Deliberately generous but not promiscuous: each entry is a phrase an
# LLM plausibly writes for that category, lowercased. Keep this list
# reviewable -- a synonym that's too broad (e.g. mapping bare "access"
# to idor) would misclassify unrelated findings, which is worse than
# leaving them unmapped and visibly NOT_TESTED.
_SYNONYMS: dict[str, str] = {
    "sqli": "sqli", "sql injection": "sqli", "sql-injection": "sqli", "sqlinjection": "sqli",
    "xss": "xss", "cross-site scripting": "xss", "cross site scripting": "xss",
    "reflected xss": "xss", "stored xss": "xss", "dom xss": "xss", "dom-based xss": "xss",
    "idor": "idor", "insecure direct object reference": "idor",
    "insecure direct object references": "idor", "broken object level authorization": "idor",
    "bola": "idor", "object level authorization": "idor",
    "ssrf": "ssrf", "server-side request forgery": "ssrf", "server side request forgery": "ssrf",
    "auth": "auth", "authentication": "auth", "broken authentication": "auth",
    "session management": "auth", "broken session management": "auth",
    "business_logic": "business_logic", "business logic": "business_logic",
    "business logic flaw": "business_logic", "workflow abuse": "business_logic",
    "race condition": "business_logic",
    "misconfig": "misconfig", "misconfiguration": "misconfig",
    "security misconfiguration": "misconfig",
    "ai_llm": "ai_llm", "prompt injection": "ai_llm", "llm": "ai_llm",
    "insecure output handling": "ai_llm",
    "supply_chain": "supply_chain", "supply chain": "supply_chain",
    "vulnerable and outdated components": "supply_chain",
    "outdated dependency": "supply_chain", "known vulnerable component": "supply_chain",
    "rate_limit": "rate_limit", "rate limiting": "rate_limit",
    "missing rate limiting": "rate_limit", "brute force": "rate_limit",
    "jwt": "jwt", "json web token": "jwt", "json-web-token": "jwt",
    "jws": "jwt", "jwe": "jwt", "jwt token": "jwt",
    "xxe": "xxe", "xml external entity": "xxe", "xml-external-entity": "xxe",
    "xee": "xxe", "xml injection": "xxe",
    "csrf": "csrf", "cross-site request forgery": "csrf",
    "cross site request forgery": "csrf", "xsrf": "csrf",
    "file_upload": "file_upload", "file upload": "file_upload",
    "arbitrary file upload": "file_upload", "file upload vulnerability": "file_upload",
    "nosql": "nosql", "nosql injection": "nosql", "no-sql": "nosql",
    "no sql": "nosql", "mongodb injection": "nosql", "mongo injection": "nosql",
    "command_injection": "command_injection", "command injection": "command_injection",
    "rce": "command_injection", "remote code execution": "command_injection",
    "code injection": "command_injection", "shell injection": "command_injection",
    "ssti": "ssti", "template injection": "ssti", "server-side template injection": "ssti",
    "server side template injection": "ssti",
    "open_redirect": "open_redirect", "open redirect": "open_redirect",
    "redirect": "open_redirect", "url redirect": "open_redirect",
    "info_disclosure": "info_disclosure", "information disclosure": "info_disclosure",
    "info disclosure": "info_disclosure", "information leak": "info_disclosure",
    "data leak": "info_disclosure", "sensitive data exposure": "info_disclosure",
    "business_logic_enhanced": "business_logic_enhanced", "business logic enhanced": "business_logic_enhanced",
    "workflow abuse": "business_logic_enhanced", "state manipulation": "business_logic_enhanced",
    "anomaly": "anomaly", "anomaly detection": "anomaly", "unknown vulnerability": "anomaly",
    "behavioral anomaly": "anomaly", "suspicious behavior": "anomaly",
}


def canonicalize(raw: str | None) -> str | None:
    """
    Map a free-text vulnerability_class to one of CANONICAL_CATEGORIES,
    or None if it doesn't recognizably match any of them. Returning None
    (rather than guessing) is deliberate: an unmapped category should
    surface as visibly uncategorized, not get silently absorbed into the
    nearest-sounding bucket.
    """
    if not raw:
        return None
    key = raw.strip().lower()
    if key in CANONICAL_CATEGORIES:
        return key
    return _SYNONYMS.get(key)
