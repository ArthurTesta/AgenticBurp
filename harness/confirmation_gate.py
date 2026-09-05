"""
Confirmation-suppression gate.

Enforces the operating-point discipline: for any vulnerability class that HAS
a deterministic confirmation leg (IDOR, SQLi, XSS, SSRF, XXE, CMDi, SSTI,
path traversal, open redirect, JWT forge), an unconfirmed hypothesis produced by
an LLM must NEVER ship at actionable severity (medium/high/critical).

Instead, unconfirmed hypotheses are:
- Demoted to severity "low" (or "info").
- Capped at confidence <= 0.35 (below default triage gates).
- Annotated as an unconfirmed hypothesis for audit and visibility in Burp.
- Summary-prefixed with "[Hypothesis]" so the tester/triager immediately knows
  this is an unvalidated model suspicion, not a confirmed finding.

A finding that WAS confirmed by its validator (confirmed=True) is untouched and
ships at its true severity and confidence with full reproduction evidence.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models import AgentReport, Finding, ValidationReport

log = logging.getLogger("harness.confirmation_gate")

# Confidence cap applied to unconfirmed hypotheses in confirmable classes.
# Capped below the standard reporting and scoring threshold (0.50).
_UNCONFIRMED_HYPOTHESIS_CONFIDENCE_CAP = 0.35

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
})


def is_confirmable_class(vuln_class: str | None) -> bool:
    """Check if the given vulnerability class has a deterministic confirmation leg."""
    if not vuln_class:
        return False
    lowered = vuln_class.lower()
    return any(marker in lowered for marker in CONFIRMABLE_CLASS_MARKERS)


def apply_confirmation_suppression(
    reports: list[AgentReport],
    validation_reports: list[ValidationReport] | None = None,
) -> int:
    """
    Demote unconfirmed hypotheses in confirmable classes to low severity.

    Any finding in a confirmable class that has NOT been validated (confirmed == False)
    is capped to confidence <= 0.35, severity demoted to 'low', review_verdict set to
    'unconfirmed_hypothesis', and summary tagged with '[Hypothesis]'.

    Findings that are confirmed (confirmed == True) or findings in classes without
    a confirmation leg (e.g. general info disclosure, business logic) are not touched.

    Returns the number of findings demoted. Mutates findings in place.
    """
    demoted = 0

    for report in reports:
        for finding in report.findings:
            if not is_confirmable_class(finding.vulnerability_class):
                continue

            # If it's already confirmed by a validator, it keeps its full severity & confidence
            if finding.confirmed:
                continue

            # Unconfirmed hypothesis in a confirmable class -> demote
            demoted += 1

            if finding.original_confidence is None:
                finding.original_confidence = finding.confidence
            finding.confidence = min(finding.confidence, _UNCONFIRMED_HYPOTHESIS_CONFIDENCE_CAP)

            if finding.severity in ("critical", "high", "medium"):
                if finding.original_severity is None:
                    finding.original_severity = finding.severity
                finding.severity = "low"

            finding.review_verdict = "unconfirmed_hypothesis"
            note = (
                "Demoted by confirmation-suppression gate: this vulnerability class has a "
                "deterministic verification leg, but the finding was not confirmed on target."
            )
            finding.review_note = (
                (finding.review_note + " " + note) if finding.review_note else note
            )

            if finding.summary and not finding.summary.startswith("[Hypothesis]"):
                finding.summary = f"[Hypothesis] {finding.summary}"

    if demoted > 0:
        log.info(
            "Confirmation-suppression gate demoted %d unconfirmed finding(s) to low severity",
            demoted,
        )

    return demoted
