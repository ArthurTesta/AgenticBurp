"""
Shared security helpers for the harness.

This module centralizes security-sensitive policies (e.g., which headers
contain secrets that must never reach LLM prompts) so they can be
consistently applied across all prompt-construction code paths.
"""
from __future__ import annotations


# Header names whose VALUES are session-identifying secrets (bearer
# tokens, session cookies, API keys) and must never reach the model --
# only the fact that such a header is present matters for an agent's
# reasoning (e.g. "this request is authenticated"), never the value
# itself. Names only, matched case-insensitively; kept as a module-level
# constant so it's one reviewable list, not scattered inline logic.
SECRET_HEADER_NAMES: set[str] = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

# The redaction placeholder text. Kept as a constant so it's the same
# string everywhere, making it easier to search for in logs or model
# context dumps if needed.
REDACTED_PLACEHOLDER = "[REDACTED -- header present, value withheld from model]"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact the values of any headers whose names match SECRET_HEADER_NAMES.
    
    Returns a new dict with the same keys. Values for secret-bearing
    header names are replaced with REDACTED_PLACEHOLDER; all other
    headers are copied unchanged.
    
    Matching is case-insensitive on the header name.
    """
    return {
        k: (REDACTED_PLACEHOLDER if k.lower() in SECRET_HEADER_NAMES else v)
        for k, v in headers.items()
    }
