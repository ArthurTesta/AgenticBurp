"""
Header/config noise gate -- deterministic precision control (critique rec #4).

A live run's raw data made the problem undeniable: of 73 "confirmed" findings on
Juice Shop, 56 were the CORS validator re-reading a wildcard
Access-Control-Allow-Origin header, and on a blind target every one of 6 secure
control endpoints still drew a medium+ finding. The header/config observer classes
(CORS, CSP, clickjacking, missing security headers, HSTS) will ALWAYS find
something to say about any HTTP response, so as per-exchange medium+ findings they
manufacture false positives by construction on exactly the endpoints that are
actually secure.

These are legitimately DETECTABLE and legitimately LOW-VALUE. So we keep the
observation but cap its severity to at most `low` -- below the sev>=medium
operating point the scorer and report key on -- turning a pile of per-exchange
"medium CORS" findings into one honest informational note per host (the report
layer already de-dupes per (endpoint-family, class)). This is the severity knob
score.py itself names as the biggest FP lever; it changes precision, not recall
(no true-positive class is touched), and it never deletes a finding, only demotes
its severity so it stops competing with real, exploitable results.

Deliberately NARROW: only the header/transport observer classes are matched.
`information_disclosure`, `security_misconfiguration`, and crypto findings are NOT
capped here -- they span genuinely high-value cases (leaked source/secrets, a real
broken misconfig) that a blanket demotion would wrongly bury.
"""
from __future__ import annotations

import logging

log = logging.getLogger("harness.header_noise_gate")

# Severity this gate caps a matched finding DOWN to (never up). `low` keeps the
# observation visible while dropping it below the sev>=medium operating point.
_CAP_SEVERITY = "low"
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Substrings (matched against the lowercased vulnerability_class) that identify a
# header/transport observer finding. Kept explicit and narrow; each is a class the
# model or a passive validator emits for a property visible on ANY response.
_HEADER_NOISE_MARKERS = (
    "cors", "cross-origin resource sharing",
    "csp", "content security policy", "content-security-policy",
    "clickjack", "x-frame", "frame options", "frame-options",
    "hsts", "strict-transport", "strict transport",
    "missing security header", "missing header", "security headers",
    "referrer-policy", "referrer policy",
    "permissions-policy", "permissions policy", "feature-policy",
    "x-content-type-options", "content-type-options", "nosniff",
)


def is_header_noise_class(vuln_class: str) -> bool:
    low = (vuln_class or "").lower()
    return any(marker in low for marker in _HEADER_NOISE_MARKERS)


def apply_header_noise_gate(exchange, reports) -> int:
    """Cap every header/config-observer finding to at most `low` severity, in
    place. Returns how many findings were demoted. Recall-safe by construction:
    the matched classes are informational, never a scored true-positive class."""
    cap = _SEV_RANK[_CAP_SEVERITY]
    n = 0
    for report in reports:
        for finding in getattr(report, "findings", []) or []:
            if not is_header_noise_class(getattr(finding, "vulnerability_class", "")):
                continue
            sev = (getattr(finding, "severity", "info") or "info").lower()
            if _SEV_RANK.get(sev, 0) > cap:
                # Record the pre-cap severity for audit, mirroring the
                # access-control gate's original_confidence bookkeeping.
                if finding.original_severity is None:
                    finding.original_severity = sev
                finding.severity = _CAP_SEVERITY
                n += 1
    if n:
        log.debug("Header-noise gate capped %d header/config finding(s) to %s", n, _CAP_SEVERITY)
    return n
