"""
Host-level dependency finding policy -- Phase 1.2.

The passive-banner classification and severity cap used to live inline inside
orchestrator._resolve_known_vulnerabilities, where nothing could exercise it
without driving the whole GitHub-advisory lookup. This extracts that policy into
two pure functions the orchestrator and the tests both call directly.

Why cap passive banners: a component seen ONLY in a passive response banner
(Server, X-Powered-By, Via) is unverified surface -- the banner can be stale,
wrong, or spoofed, and reachability of the vulnerable code path is unproven. An
advisory match on such a component is worth noting but must NOT ship at
actionable severity (medium/high); it is capped to low. Active/manifest-sourced
components (a served package.json, an exposed lockfile) are not passive and keep
their advisory severity.

KEV escalation is intentionally applied by the caller AFTER this cap: CISA
confirming active in-the-wild exploitation overrides the "unverified banner"
discount and re-escalates to critical.
"""
from __future__ import annotations

# Substrings in a ComponentCandidate.source that mark it as observed only from a
# passive response banner rather than an active fetch / served manifest.
_PASSIVE_SOURCE_MARKERS = ("server", "x-powered-by", "header", "via", "response headers")

# Actionable severities capped for a passive banner. A GHSA-"critical" advisory
# is deliberately NOT capped here (a disclosed critical on a named component still
# warrants attention), matching the pre-extraction behavior; KEV escalation is a
# separate, caller-applied path.
_ACTIONABLE = ("medium", "high")

# What a capped passive-banner advisory is demoted to.
_PASSIVE_CAP = "low"


def is_passive_banner(source: str | None) -> bool:
    """True when a component was observed only via a passive response banner
    (Server / X-Powered-By / Via / a header), not an active fetch or a served
    dependency manifest."""
    s = (source or "").lower()
    return any(marker in s for marker in _PASSIVE_SOURCE_MARKERS)


def cap_passive_banner_severity(severity: str, passive: bool) -> str:
    """Cap an advisory severity to low when the component is a passive banner and
    the severity would otherwise be actionable. Non-passive components, and
    already-low/info severities, are returned unchanged. Callers apply KEV
    escalation AFTER this, so a genuinely actively-exploited banner can still be
    raised back to critical."""
    if passive and severity in _ACTIONABLE:
        return _PASSIVE_CAP
    return severity
