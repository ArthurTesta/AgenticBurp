"""
Shared security helpers for the harness.

This module centralizes security-sensitive policies (e.g., which headers
contain secrets that must never reach LLM prompts) so they can be
consistently applied across all prompt-construction code paths.
"""
from __future__ import annotations
import base64
import json


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


def _decode_jwt_header_only(token: str) -> dict | None:
    """Best-effort decode of ONLY a JWT's first segment (the algorithm/
    type header) -- never touches the second segment (claims/payload,
    which can carry user-identifying data) or the third (signature).

    Returns the decoded header dict if `token` is JWT-shaped (three
    dot-separated base64url segments) and the first segment decodes to
    JSON containing an "alg" key. Returns None for anything else --
    opaque API keys, non-JWT bearer tokens, or malformed input -- so
    callers fall back to full redaction by default, never partial
    disclosure on a guess.

    Why this exists: full redaction of Authorization made an entire
    vulnerability class (alg=none / algorithm-confusion JWT forgery)
    structurally invisible to every agent, since the evidence needed to
    catch it is the token's own header field -- see
    DISCOVERY_RUN_RESULTS.md, architecture finding #4. The algorithm
    name is metadata about how the token is supposed to be verified, not
    a credential; the payload (who the token is for) and signature (the
    actual secret-derived material) are the parts that must stay hidden,
    and this function never looks at either.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[0] + "=" * (-len(parts[0]) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        header = json.loads(decoded)
    except Exception:
        return None
    if isinstance(header, dict) and "alg" in header:
        return header
    return None


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact the values of any headers whose names match SECRET_HEADER_NAMES.
    
    Returns a new dict with the same keys. Values for secret-bearing
    header names are replaced with REDACTED_PLACEHOLDER; all other
    headers are copied unchanged.

    One narrow exception: an `Authorization: Bearer <jwt>` value whose
    token is JWT-shaped gets its header segment (only) disclosed
    alongside the redaction notice -- e.g. `{"alg": "none"}` or
    `{"alg": "HS256", "typ": "JWT"}`. This never exposes the payload
    (claims) or signature. Anything that isn't JWT-shaped -- opaque API
    keys, Basic/Digest auth, malformed tokens -- gets the original full
    redaction with no exception.
    
    Matching is case-insensitive on the header name.
    """
    result = {}
    for k, v in headers.items():
        if k.lower() == "authorization" and v.lower().startswith("bearer "):
            jwt_header = _decode_jwt_header_only(v[len("Bearer "):].strip())
            if jwt_header is not None:
                result[k] = (
                    f"Bearer [REDACTED -- payload and signature withheld from model; "
                    f"JWT header only: {json.dumps(jwt_header, sort_keys=True)}]"
                )
                continue
        result[k] = REDACTED_PLACEHOLDER if k.lower() in SECRET_HEADER_NAMES else v
    return result
