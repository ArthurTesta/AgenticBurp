from __future__ import annotations
from dataclasses import dataclass

from models import Finding

# Rule-based, not LLM-based, deliberately: the ARTEMIS benchmark (Dec
# 2025, 8,000-host live network) found autonomous agents specifically
# lose ground to top human testers on "creative chaining and business
# logic" -- the risk with an LLM narrating a chain from a list of
# findings is that it's exactly the kind of fluent-sounding, hard-to-
# verify claim this whole harness exists to avoid. A rule match over
# labeled finding categories is auditable -- a reader can see exactly
# which two findings triggered which rule -- where an LLM's "these might
# chain into X" is not.
#
# The escalation pattern in CHAIN rule "open_redirect+ssrf" is not
# invented for this tool -- it mirrors Intigriti's own published triage
# guidance, which gives exactly this example: an open redirect report
# followed by a separate SSRF report that escalates through it to RCE.


@dataclass(frozen=True)
class ChainRule:
    signature: str
    tag_a: str
    tag_b: str
    severity: str
    narrative_template: str  # {a_url} {b_url} get filled in


_RULES: list[ChainRule] = [
    ChainRule(
        signature="open_redirect+ssrf",
        tag_a="open_redirect", tag_b="ssrf",
        severity="critical",
        narrative_template=(
            "An open-redirect-shaped finding at {a_url} and an SSRF-shaped finding at "
            "{b_url} are both present on this host. This is a documented escalation "
            "pattern (open redirect used to bypass an SSRF allowlist that only checks "
            "the initial hostname) that has previously escalated to RCE in triaged bug "
            "bounty reports. Worth testing together even though each was flagged "
            "independently."
        ),
    ),
    ChainRule(
        signature="admin_exposure+access_control",
        tag_a="admin_exposure", tag_b="access_control",
        severity="high",
        narrative_template=(
            "Exposed admin/internal surface at {a_url} plus an access-control gap "
            "(IDOR or missing authorization) at {b_url} on the same host raises the "
            "combined risk above either alone: the access-control gap may be reachable "
            "specifically through the exposed admin surface rather than needing a "
            "separate discovery path."
        ),
    ),
    ChainRule(
        signature="dependency_exposure+known_vuln",
        tag_a="dependency_exposure", tag_b="known_vuln",
        severity="high",
        narrative_template=(
            "A dependency manifest/lockfile exposure at {a_url} is what made precise "
            "version fingerprinting possible, and a disclosed advisory was then "
            "confirmed at {b_url} via the deterministic GitHub Advisory lookup. "
            "Treat the exposure itself as worth fixing independently of whether this "
            "specific advisory turns out to be exploitable here -- it will keep "
            "enabling this kind of match against future advisories too."
        ),
    ),
    ChainRule(
        signature="weak_auth+business_logic",
        tag_a="weak_auth", tag_b="business_logic",
        severity="high",
        narrative_template=(
            "A weak authentication/session primitive at {a_url} combined with a "
            "sensitive state-changing action at {b_url} means the auth weakness's "
            "real-world impact is higher than its isolated severity suggests -- it's "
            "not just \"a weak token\", it's \"a weak token that gates {b_url}\"."
        ),
    ),
    ChainRule(
        signature="idor+rate_limit",
        tag_a="access_control", tag_b="rate_limit",
        severity="high",
        narrative_template=(
            "An object-level access-control weakness at {a_url} combined with a "
            "rate-limit gap at {b_url} may permit automated enumeration at scale. "
            "Treat this as a chain hypothesis requiring a controlled bulk test."
        ),
    ),
    ChainRule(
        signature="xss+weak_auth",
        tag_a="xss", tag_b="weak_auth",
        severity="high",
        narrative_template=(
            "An XSS-shaped finding at {a_url} combined with a weak authentication "
            "or session primitive at {b_url} may increase the impact of script execution."
        ),
    ),
    ChainRule(
        signature="open_redirect+oauth_redirect",
        tag_a="open_redirect", tag_b="oauth_redirect",
        severity="high",
        narrative_template=(
            "An open redirect at {a_url} plus OAuth redirect handling at {b_url} "
            "may create a token/code redirection path. Verify exact redirect_uri "
            "validation before treating this as an account-takeover chain."
        ),
    ),
    ChainRule(
        signature="graphql_introspection+access_control",
        tag_a="graphql_introspection", tag_b="access_control",
        severity="high",
        narrative_template=(
            "GraphQL introspection exposure at {a_url} plus an access-control gap "
            "at {b_url} may make sensitive fields or operations easier to enumerate. "
            "Verify field-level authorization explicitly."
        ),
    ),
]

# Keyword -> tag mapping. A finding gets a tag if any of its keywords
# appear in its vulnerability_class or summary (lowercased). A finding
# can carry multiple tags.
_CLASS_TAGS: dict[str, set[str]] = {
    "open_redirect": {"open_redirect", "open-redirect", "open redirect"},
    "ssrf": {"ssrf", "server-side request forgery"},
    "admin_exposure": {"admin_exposure", "admin-exposure"},
    "access_control": {"idor", "access_control", "access-control", "broken-access-control", "missing-authorization"},
    "dependency_exposure": {"dependency_exposure", "dependency-exposure", "manifest-exposure"},
    "known_vuln": {"known-vulnerable-dependency"},
    "weak_auth": {"weak_auth", "weak-auth", "authentication-bypass", "session"},
    "business_logic": {"business_logic", "business-logic", "workflow", "race-condition"},
    "rate_limit": {"rate_limit", "rate-limit", "rate limiting", "throttling"},
    "xss": {"xss", "cross-site-scripting", "cross-site scripting"},
    "oauth_redirect": {"oauth_redirect", "oauth-redirect", "oauth redirect"},
    "graphql_introspection": {"graphql_introspection", "graphql-introspection", "graphql introspection"},
}


def _tags_for(vulnerability_class: str, summary: str) -> set[str]:
    """Tag only from the structured vulnerability class, never free text.

    Summaries/evidence are model-controlled and may contain arbitrary words;
    using them as a taxonomy oracle can manufacture chains.
    """
    normalized = vulnerability_class.lower().strip()
    return {tag for tag, aliases in _CLASS_TAGS.items() if normalized in aliases}
def detect(host_findings: list[dict]) -> list[Finding]:
    """
    host_findings: dicts as returned by store.all_host_findings() --
    {url, vulnerability_class, severity, confidence, summary}.
    Returns Finding objects for chains found. Caller is responsible for
    checking store.is_chain_already_detected()/mark_chain_detected() so
    the same chain isn't re-reported on every subsequent exchange.
    """
    tagged = [(f, _tags_for(f["vulnerability_class"], f["summary"])) for f in host_findings]

    results: list[Finding] = []
    for rule in _RULES:
        a_matches = [f for f, tags in tagged if rule.tag_a in tags]
        b_matches = [f for f, tags in tagged if rule.tag_b in tags]
        if not a_matches or not b_matches:
            continue
        a, b = a_matches[0], b_matches[0]
        if a["url"] == b["url"] and rule.tag_a == rule.tag_b:
            continue
        results.append(Finding(
            vulnerability_class=f"potential-attack-chain:{rule.signature}",
            confidence=0.5,  # rule match on category labels, not a confirmed chain -- always needs a human look
            severity=rule.severity,
            owasp_category=None,
            summary=f"Potential attack chain: {rule.signature.replace('+', ' -> ')}",
            evidence=rule.narrative_template.format(a_url=a["url"], b_url=b["url"]),
            suggested_test="Test these together explicitly, in the order implied by the chain -- "
                            "individually-valid findings don't automatically compose, this is a "
                            "hypothesis to verify, not a confirmed exploit path.",
            basis="derived",
        ))
    return results
