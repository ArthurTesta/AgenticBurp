"""
Confirmation-suppression gate -- leg-aware, 3-state (Phase 1.1).

An unconfirmed hypothesis is not one thing: what its non-confirmation MEANS
depends on whether the harness even had a reliable way to confirm it. So the gate
places every unconfirmed finding into one of three states, keyed off the
verification TIER of the confirmation leg for its class:

  1. CONFIRMED   -- a leg proved it (confirmed=True). Untouched; ships at its true
                    severity/confidence with reproduction evidence.
  2. REFUTED     -- unconfirmed, and the class has a LIVE-VERIFIED leg (one proven
                    to actually confirm real instances on a live target). The
                    leg had its shot and stayed silent, so this is likely a false
                    positive: demote to "low", cap confidence <= 0.35, verdict
                    "unconfirmed_hypothesis", prefix "[Hypothesis]".
  3. UNPROVEN    -- unconfirmed, and the class's leg is only SMOKE/hermetic-verified
                    (not yet proven to bite live). Its silence is weak evidence, so
                    burying a possibly-real finding to "low" would cost recall:
                    instead cap severity at "medium" (never high/critical
                    unconfirmed), cap confidence <= 0.5, verdict
                    "unproven_unverified_leg", prefix "[Unconfirmed]".

Classes with NO confirmation leg are left untouched (the gate is about classes we
could have confirmed). The live-verified set is what Phase 2's leg
live-verification refreshes: as a leg graduates smoke_only -> live_verified, its
class moves from UNPROVEN (medium) to REFUTED (low) suppression. Callers may pass
`live_verified_markers` to override the default seed.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models import AgentReport, Finding, ValidationReport

log = logging.getLogger("harness.confirmation_gate")

# Confidence caps. REFUTED (live-verified leg stayed silent) is capped hard,
# below the standard triage threshold; UNPROVEN (leg not live-verified) is capped
# at the threshold -- visible but not asserted.
_REFUTED_CONFIDENCE_CAP = 0.35
_UNPROVEN_CONFIDENCE_CAP = 0.5
# Back-compat alias (older imports).
_UNCONFIRMED_HYPOTHESIS_CONFIDENCE_CAP = _REFUTED_CONFIDENCE_CAP

# Vulnerability classes that possess a deterministic confirmation leg in this harness.
# Matched case-insensitively as substrings against finding.vulnerability_class.
CONFIRMABLE_CLASS_MARKERS = frozenset({
    # IDOR / Access Control family (cross_identity_validator)
    "idor",
    "insecure_direct_object",
    "insecure direct object",
    "broken_access_control",
    "broken access control",
    "bola",
    "bfla",
    "privilege escalation",
    "privilege_escalation",
    "missing authorization",
    "missing_authorization",

    # SQL Injection family (sqlmap / sqlmap_validator)
    "sql_injection",
    "sql injection",
    "sqli",

    # XSS family (browser_xss_validator)
    "xss",
    "cross_site_scripting",
    "cross-site scripting",
    "cross site scripting",

    # SSRF family (ssrf_validator)
    "ssrf",
    "server_side_request_forgery",
    "server-side request forgery",
    "server side request forgery",

    # XXE family (xxe_validator)
    "xxe",
    "xml_external_entity",
    "xml external entity",

    # JWT family (jwt_forge_validator)
    "jwt",
    "jwt_forge",
    "algorithm confusion",
    "algorithm_confusion",
    "weak_token",

    # Command Injection family (command_injection_validator)
    "command_injection",
    "command injection",
    "rce",
    "remote code execution",
    "remote_code_execution",
    "shell injection",
    "shell_injection",

    # SSTI family (ssti_validator)
    "ssti",
    "template_injection",
    "template injection",

    # Path Traversal family (path_traversal_validator)
    "path_traversal",
    "path traversal",
    "directory traversal",
    "directory_traversal",
    "lfi",
    "local file inclusion",
    "file inclusion",

    # Open Redirect family (open_redirect_validator)
    "open_redirect",
    "open redirect",
    "unvalidated redirect",
    "unvalidated_redirect",

    # Mass-assignment / privilege escalation (sequence_validator, Phase 3)
    "mass_assignment",
    "mass assignment",

    # Insecure deserialization -- active OOB pickle beacon (deserialization_oob)
    "deserialization",
    "insecure deserialization",
    "insecure_deserialization",
    "pickle",
})

# The subset of confirmable classes whose leg is LIVE-VERIFIED -- proven to
# actually confirm real instances against a live target. Sources:
#   - session-11 max-coverage run vs VulnCorp: cross_identity (IDOR/access
#     control), sqlmap (SQLi), jwt_forge (JWT alg:none), xxe, path_traversal.
#   - Phase 2 (this session), test_leg_live_verification against a real local
#     vulnerable fixture: ssti (Jinja render), open_redirect (blind 302), ssrf
#     (real server-side fetch to the collaborator), command_injection (real shell
#     fetch), and the sequence leg (real mass-assignable write -> re-read).
# The only confirmable class still smoke_only-by-default is xss: its browser_xss
# leg needs a real Chromium ON THE HARNESS, so it stays UNPROVEN unless an operator
# with a browser promotes it via the live_verified_markers override. THIS SET is
# what live-verification refreshes. See LEG_VERIFICATION.md for the full split.
LIVE_VERIFIED_MARKERS = frozenset({
    "idor", "insecure_direct_object", "insecure direct object",
    "broken_access_control", "broken access control", "bola", "bfla",
    "missing authorization", "missing_authorization",
    "sql_injection", "sql injection", "sqli",
    "xxe", "xml_external_entity", "xml external entity",
    "path_traversal", "path traversal", "directory traversal", "directory_traversal",
    "lfi", "local file inclusion", "file inclusion",
    "jwt", "jwt_forge", "algorithm confusion", "algorithm_confusion", "weak_token",
    # Phase 2 live-verified (test_leg_live_verification, real local fixture):
    "ssti", "template_injection", "template injection",
    "open_redirect", "open redirect", "unvalidated redirect", "unvalidated_redirect",
    "ssrf", "server_side_request_forgery", "server-side request forgery",
    "server side request forgery",
    "command_injection", "command injection", "rce", "remote code execution",
    "remote_code_execution", "shell injection", "shell_injection",
    "mass_assignment", "mass assignment",
    # Session-13: active deserialization OOB pickle beacon, live-verified against a
    # real pickle.loads sink in test_leg_live_verification.
    "deserialization", "insecure deserialization", "insecure_deserialization", "pickle",
})


def is_confirmable_class(vuln_class: str | None) -> bool:
    """Check if the given vulnerability class has a deterministic confirmation leg."""
    if not vuln_class:
        return False
    lowered = vuln_class.lower()
    return any(marker in lowered for marker in CONFIRMABLE_CLASS_MARKERS)


def leg_tier(vuln_class: str | None, live_verified_markers: frozenset | None = None) -> str:
    """Verification tier of the confirmation leg for a class:
    "live" (a live-verified leg exists), "provisional" (a leg exists but is only
    smoke/hermetic-verified), or "none" (no leg). `live_verified_markers` overrides
    the default LIVE_VERIFIED_MARKERS seed -- this is the seam Phase 2 uses to
    promote a leg once it is live-verified."""
    if not is_confirmable_class(vuln_class):
        return "none"
    live = LIVE_VERIFIED_MARKERS if live_verified_markers is None else live_verified_markers
    lowered = (vuln_class or "").lower()
    return "live" if any(marker in lowered for marker in live) else "provisional"


def apply_confirmation_suppression(
    reports: list[AgentReport],
    validation_reports: list[ValidationReport] | None = None,
    live_verified_markers: frozenset | None = None,
) -> int:
    """
    Place each unconfirmed finding into the leg-aware 3-state model (see module
    docstring). Mutates findings in place; returns the number demoted (REFUTED +
    UNPROVEN). Confirmed findings and no-leg classes are left untouched.

    - REFUTED  (class has a LIVE-verified leg): severity -> "low", confidence
      <= 0.35, verdict "unconfirmed_hypothesis", prefix "[Hypothesis]".
    - UNPROVEN (class has a leg, but only smoke/hermetic-verified): severity
      capped at "medium" (high/critical -> medium), confidence <= 0.5, verdict
      "unproven_unverified_leg", prefix "[Unconfirmed]".

    `live_verified_markers` overrides which classes count as live-verified -- the
    seam Phase 2 uses to promote a leg after live-verifying it.
    """
    demoted = 0

    for report in reports:
        for finding in report.findings:
            if finding.confirmed:
                continue  # a leg proved it -- ships at true severity/confidence
            tier = leg_tier(finding.vulnerability_class, live_verified_markers)
            if tier == "none":
                continue  # no leg could have confirmed it -- not the gate's business

            demoted += 1
            if finding.original_confidence is None:
                finding.original_confidence = finding.confidence

            if tier == "live":
                # REFUTED: a reliable leg stayed silent -> likely a false positive.
                finding.confidence = min(finding.confidence, _REFUTED_CONFIDENCE_CAP)
                if finding.severity in ("critical", "high", "medium"):
                    if finding.original_severity is None:
                        finding.original_severity = finding.severity
                    finding.severity = "low"
                finding.review_verdict = "unconfirmed_hypothesis"
                prefix = "[Hypothesis]"
                note = ("Demoted by confirmation-suppression gate: this class has a LIVE-VERIFIED "
                        "leg that did not confirm the finding on target -- treated as a likely "
                        "false positive.")
            else:  # provisional
                # UNPROVEN: the leg isn't live-verified, so silence is weak
                # evidence -- keep it visible (capped) rather than bury it.
                finding.confidence = min(finding.confidence, _UNPROVEN_CONFIDENCE_CAP)
                if finding.severity in ("critical", "high"):
                    if finding.original_severity is None:
                        finding.original_severity = finding.severity
                    finding.severity = "medium"
                finding.review_verdict = "unproven_unverified_leg"
                prefix = "[Unconfirmed]"
                note = ("Capped by confirmation-suppression gate: this class's confirmation leg is "
                        "not yet live-verified, so the finding is neither confirmed nor reliably "
                        "refutable -- kept at capped severity pending live verification (Phase 2).")

            finding.review_note = (
                (finding.review_note + " " + note) if finding.review_note else note
            )
            if finding.summary and not finding.summary.startswith(prefix):
                finding.summary = f"{prefix} {finding.summary}"

    if demoted > 0:
        log.info("Confirmation-suppression gate processed %d unconfirmed finding(s) "
                 "(REFUTED to low / UNPROVEN capped at medium)", demoted)

    return demoted
