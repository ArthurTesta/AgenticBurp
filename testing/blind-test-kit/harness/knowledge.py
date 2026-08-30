from __future__ import annotations
import re

from models import HttpExchange

# A deliberately small, hand-written methodology corpus -- not a copy of
# any external text (OWASP Testing Guide, PortSwigger docs, etc; those
# are copyrighted and paraphrasing them closely enough to be useful would
# still risk reproducing their structure). This is the "Memory Retriever"
# module VulnBot's five-module architecture names explicitly: a
# retrieval step separate from planning/generation, so agents ground
# their reasoning in something written down instead of only what's in
# the model's weights. Keeping this file-based and keyword-scored (no
# embeddings, no vector DB) is a deliberate choice: it's inspectable,
# has zero extra runtime dependencies, and its failure mode when it
# misses is "no context added" rather than "silently wrong context from
# a bad embedding match."
#
# Extend this corpus freely -- each entry needs "tags" (matched against
# agent name + a few keywords pulled from the exchange) and "note" (the
# actual grounding text, kept short and operational).
_CORPUS: list[dict] = [
    {
        "tags": ["sqli", "sql", "injection", "database"],
        "note": "Differential testing beats single-request pattern matching for SQLi: "
                "compare a baseline request against one with a single quote appended, "
                "then against one with the quote escaped/doubled -- a genuine injection "
                "point usually shows a response difference on the first and not the "
                "second. Time-based confirmation (a sleep expression vs a no-op of "
                "matching syntax) is the fallback when the response body gives no signal.",
    },
    {
        "tags": ["xss", "cross-site", "script"],
        "note": "Where a reflection lands changes what breaks out of it: inside an HTML "
                "attribute you need to close the attribute and possibly the tag; inside a "
                "<script> block you don't need HTML-breaking characters at all, just "
                "JS-breaking ones; inside a JSON response that's later parsed by JS, the "
                "risk is downstream (does something eval or innerHTML it), not the "
                "response itself.",
    },
    {
        "tags": ["idor", "access_control", "business_logic"],
        "note": "IDOR is only proven by a differential test across two identities: same "
                "object ID, two different session tokens, compare responses -- or same "
                "token, two different IDs. A single request showing a plausible-looking "
                "numeric ID is a candidate, not a finding, until that second request "
                "exists.",
    },
    {
        "tags": ["ssrf"],
        "note": "Blind SSRF (no reflected response, no visible fetch) is usually "
                "confirmed out-of-band: point the candidate parameter at an "
                "analyst-controlled listener and check for an inbound connection, "
                "since the application's own response may never show anything. "
                "Cloud metadata endpoints (link-local addresses reachable from inside "
                "the app's network) are a common high-value target once SSRF is "
                "confirmed at all.",
    },
    {
        "tags": ["business_logic", "race", "workflow"],
        "note": "Race-condition-shaped findings (redemption, balance transfer, "
                "limited-quantity purchase) need concurrent requests, not sequential "
                "ones -- firing the same request twice one after another rarely "
                "reproduces a TOCTOU window; it needs to be genuinely simultaneous.",
    },
    {
        "tags": ["misconfig", "headers", "cors"],
        "note": "The dangerous CORS misconfiguration is the *pairing* of "
                "Access-Control-Allow-Origin reflecting an arbitrary origin together "
                "with Access-Control-Allow-Credentials: true -- either alone is much "
                "lower risk than the combination, which lets a malicious origin read "
                "authenticated responses.",
    },
    {
        "tags": ["auth", "jwt", "session"],
        "note": "For JWT-bearing apps, check the algorithm field before anything else: "
                "an app that accepts 'none' as an algorithm, or that can be tricked into "
                "verifying an RS256 token with the public key as an HMAC secret, breaks "
                "signature verification entirely regardless of how strong the actual "
                "signing key is.",
    },
    {
        "tags": ["ai_llm", "prompt", "injection"],
        "note": "Prompt injection testing separates two different risks that get "
                "conflated: direct injection (the user's own message tries to override "
                "instructions) and indirect injection (untrusted third-party content -- "
                "a fetched URL, an uploaded document -- contains instructions the model "
                "follows as if they were trusted). Indirect injection is generally the "
                "higher-severity, easier-to-miss case, since the attacker never talks to "
                "the app directly.",
    },
    {
        "tags": ["supply_chain", "dependency", "lockfile", "ci", "github", "actions"],
        "note": "An exposed lockfile is a reconnaissance gift, not a vulnerability by "
                "itself -- the actual risk is whichever named version turns out to have "
                "a disclosed advisory, which is exactly what the deterministic "
                "known-vulnerability lookup step (not agent reasoning) is for. "
                "Separately: a GitHub Actions workflow using pull_request_target while "
                "checking out and running code from the PR head is a well-documented "
                "'pwn request' pattern -- untrusted fork code runs with the base repo's "
                "token and secrets.",
    },
    {
        "tags": ["known", "advisory", "cve", "rediscover"],
        "note": "When a component's exact version and a matching disclosed advisory "
                "both exist, the useful next step is confirming the deployed version "
                "falls in the affected range and checking remediation status -- not "
                "spending further effort trying to independently redemonstrate that the "
                "underlying bug exists. Effort is better spent on components where no "
                "advisory was found, since that's the only case where independent "
                "analysis is actually adding information.",
    },
]


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z][a-z0-9_-]{2,}", text.lower()))


def retrieve(agent_name: str, exchange: HttpExchange, top_k: int = 2) -> str:
    """
    Keyword-overlap retrieval (no embeddings): score each corpus entry by
    how many of its tags/words appear in the agent's own name plus a
    slice of the exchange (URL + first part of the body), return the
    top_k entries' notes as a single prompt-ready block. Deterministic
    and cheap enough to run on every call.
    """
    query_tokens = _tokenize(agent_name) | _tokenize(exchange.url) | _tokenize(exchange.request_body[:500])

    scored = []
    for entry in _CORPUS:
        tag_tokens = set(entry["tags"])
        overlap = len(query_tokens & tag_tokens)
        if overlap > 0:
            scored.append((overlap, entry))

    if not scored:
        return ""

    scored.sort(key=lambda pair: pair[0], reverse=True)
    top = [entry["note"] for _, entry in scored[:top_k]]
    return "\n".join(f"- {note}" for note in top)
