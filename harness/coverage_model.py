"""
Deterministic WSTG/PortSwigger-Academy-driven coverage model.

The spine of the coverage engine (I1–I5 from the operator's expanded goal):

- **Check catalog**: a fixed, code-defined list of security checks, each tagged
  with a WSTG/Academy id, a phase (domain|endpoint|parameter — I4), a mapped
  vulnerability class, and a deterministic applicability predicate (I1/I5).
- **CoverageMatrix**: identity × endpoint × check, each cell recording an
  auditable status (I2/I5). Naturally memoises (item #4) and is the report
  substrate. Integrates with the existing EngagementState/validators rather
  than replacing them.
- **Check.confirmation**: how a check is confirmed — a deterministic leg/tool
  name where one exists (I3), else "agent" or "manual".

Every check declares WHY it applies or doesn't (the predicate's `reason`), so
"what was NOT tested and why" (I2/I5) is always answerable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from categories import canonicalize


# ---------------------------------------------------------------------------
# Phase (I4): every check belongs to exactly one phase
# ---------------------------------------------------------------------------

class Phase(str, Enum):
    DOMAIN = "domain"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"


# ---------------------------------------------------------------------------
# Cell status (I2/I5): the auditable lifecycle of each matrix cell
# ---------------------------------------------------------------------------

class CellStatus(str, Enum):
    NOT_APPLICABLE = "not_applicable"
    PENDING = "pending"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class CellResult:
    """One cell in the coverage matrix: (identity, endpoint, check)."""
    status: CellStatus = CellStatus.PENDING
    reason: str = ""
    severity: str | None = None
    confidence: float | None = None
    validator: str | None = None
    evidence: str | None = None

    def to_dict(self) -> dict:
        d: dict = {"status": self.status.value, "reason": self.reason}
        if self.severity:
            d["severity"] = self.severity
        if self.confidence is not None:
            d["confidence"] = self.confidence
        if self.validator:
            d["validator"] = self.validator
        if self.evidence:
            d["evidence"] = self.evidence
        return d

    @classmethod
    def not_applicable(cls, reason: str) -> "CellResult":
        return cls(status=CellStatus.NOT_APPLICABLE, reason=reason)

    @classmethod
    def from_dict(cls, d: dict) -> "CellResult":
        return cls(
            status=CellStatus(d.get("status", "pending")),
            reason=d.get("reason", ""),
            severity=d.get("severity"),
            confidence=d.get("confidence"),
            validator=d.get("validator"),
            evidence=d.get("evidence"),
        )


# ---------------------------------------------------------------------------
# Applicability predicates — shape-based, deterministic (I1/I5)
# ---------------------------------------------------------------------------

def _has_params(endpoint: dict) -> tuple[bool, str]:
    path = endpoint.get("path", "")
    if "?" in path or "{" in path or re.search(r"/\d+(?:/|$)", path):
        return True, "endpoint has parameters or path variables"
    methods = endpoint.get("methods", ())
    if any(m in ("POST", "PUT", "PATCH") for m in methods):
        return True, "endpoint accepts body-bearing methods"
    return False, "no parameters or body-bearing methods detected"

def _accepts_input(endpoint: dict) -> tuple[bool, str]:
    has, reason = _has_params(endpoint)
    if has:
        return True, reason
    return False, "endpoint does not accept user-controllable input"

def _is_authed(endpoint: dict) -> tuple[bool, str]:
    access = endpoint.get("access", {})
    reachable = endpoint.get("reachable_roles", [])
    if access or reachable:
        return True, "endpoint has role/access data"
    return False, "no role/access information available"

def _is_object_scoped(endpoint: dict) -> tuple[bool, str]:
    if endpoint.get("object_scoped"):
        return True, "endpoint is object-scoped (e.g. /resource/{id})"
    path = endpoint.get("path", "")
    if re.search(r"/\{?id\}?|/\d+(?:/|$)", path):
        return True, "path contains an object identifier"
    return False, "not object-scoped"

def _accepts_xml(endpoint: dict) -> tuple[bool, str]:
    methods = endpoint.get("methods", ())
    if any(m in ("POST", "PUT", "PATCH") for m in methods):
        path = (endpoint.get("path", "") or "").lower()
        if any(k in path for k in ("import", "xml", "upload", "feed", "rss", "soap")):
            return True, "body-bearing method on an XML-associated path"
    return False, "no XML-accepting indicators"

def _has_url_param(endpoint: dict) -> tuple[bool, str]:
    path = endpoint.get("path", "")
    if "?" in path:
        return True, "endpoint has query parameters"
    lower = (path or "").lower()
    if any(k in lower for k in ("redirect", "url", "next", "return", "goto", "link",
                                 "forward", "continue", "callback", "proxy", "fetch")):
        return True, "path suggests URL/redirect parameter"
    return False, "no URL parameter indicators"

def _has_auth_endpoint(endpoint: dict) -> tuple[bool, str]:
    path = (endpoint.get("path", "") or "").lower()
    if any(k in path for k in ("login", "auth", "signin", "sign-in", "session",
                                "token", "oauth", "register", "signup", "sign-up",
                                "password", "reset", "mfa", "2fa", "verify")):
        return True, "authentication-related endpoint"
    return False, "not an authentication endpoint"

def _has_file_path_segment(endpoint: dict) -> tuple[bool, str]:
    path = endpoint.get("path", "")
    if re.search(r"/(upload|file|download|media|attachment|avatar|image|doc|asset)s?(/|$)", path, re.I):
        return True, "path suggests file handling"
    if re.search(r"/\d+(?:/|$)", path) and any(
            k in (path or "").lower() for k in ("upload", "file", "attachment", "media")):
        return True, "object-scoped file endpoint"
    return False, "no file-handling indicators"

def _always_applicable(_endpoint: dict) -> tuple[bool, str]:
    return True, "domain-level check (applies to all endpoints)"

def _has_cookie_or_session(endpoint: dict) -> tuple[bool, str]:
    if _has_auth_endpoint(endpoint)[0]:
        return True, "authentication endpoint likely involves sessions"
    access = endpoint.get("access", {})
    if access:
        return True, "endpoint has access-control data suggesting session use"
    return False, "no session/cookie indicators"

def _accepts_body(endpoint: dict) -> tuple[bool, str]:
    methods = endpoint.get("methods", ())
    if any(m in ("POST", "PUT", "PATCH") for m in methods):
        return True, "endpoint accepts body-bearing methods"
    return False, "endpoint does not accept request bodies"


# Predicate type: endpoint dict → (applicable: bool, reason: str)
ApplicabilityPredicate = Callable[[dict], tuple[bool, str]]


# ---------------------------------------------------------------------------
# Check — one entry in the catalog
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Check:
    """A single security check in the catalog."""
    id: str                              # e.g. "WSTG-INPV-05"
    name: str                            # human-readable
    phase: Phase
    vulnerability_class: str             # maps to categories.canonicalize
    applicability: ApplicabilityPredicate
    confirmation: str                    # "sqlmap" | "cross_identity" | "agent" | "manual" | ...
    description: str = ""
    academy_ref: str = ""                # PortSwigger Academy topic if applicable

    def applies(self, endpoint: dict) -> tuple[bool, str]:
        return self.applicability(endpoint)

    def canonical_class(self) -> str | None:
        return canonicalize(self.vulnerability_class)


# ---------------------------------------------------------------------------
# The catalog — the fixed check list (I1)
# ---------------------------------------------------------------------------

CHECK_CATALOG: tuple[Check, ...] = (
    # === DOMAIN phase ===
    Check("WSTG-CRYP-01", "TLS/SSL configuration", Phase.DOMAIN,
          "crypto", _always_applicable, "crypto",
          "Verify TLS versions, cipher suites, certificate validity",
          "Server-side TLS"),
    Check("WSTG-CONF-07", "HTTP Strict Transport Security", Phase.DOMAIN,
          "misconfig", _always_applicable, "crypto",
          "Check HSTS header presence and configuration"),
    Check("WSTG-CONF-05", "Content Security Policy", Phase.DOMAIN,
          "csp", _always_applicable, "csp",
          "Evaluate CSP header directives",
          "Content security policy"),
    Check("WSTG-CONF-08", "CORS policy", Phase.DOMAIN,
          "cors", _always_applicable, "cors",
          "Test Cross-Origin Resource Sharing configuration",
          "CORS"),
    Check("WSTG-INFO-02", "Server fingerprinting", Phase.DOMAIN,
          "recon", _always_applicable, "recon",
          "Identify web server software and version"),
    Check("WSTG-INFO-05", "Information in comments/metadata", Phase.DOMAIN,
          "info_disclosure", _always_applicable, "recon",
          "Check for sensitive data in HTML comments, headers, metadata"),
    Check("WSTG-CONF-06", "HTTP methods", Phase.DOMAIN,
          "misconfig", _always_applicable, "recon",
          "Test which HTTP methods are enabled"),
    Check("WSTG-CONF-02", "Security headers", Phase.DOMAIN,
          "misconfig", _always_applicable, "recon",
          "Check X-Frame-Options, X-Content-Type-Options, etc."),

    # === ENDPOINT phase ===
    Check("WSTG-ATHZ-04", "IDOR / Broken Object-Level Authorization", Phase.ENDPOINT,
          "idor", _is_object_scoped, "cross_identity",
          "Test access to other users' objects by varying identifiers",
          "Insecure direct object references (IDOR)"),
    Check("WSTG-ATHZ-02", "Broken Function-Level Authorization", Phase.ENDPOINT,
          "idor", _is_authed, "cross_identity",
          "Access admin/privileged functions as a lower-privilege user",
          "Access control vulnerabilities"),
    Check("WSTG-ATHN-01", "Authentication bypass", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "auth_sequence",
          "Test for authentication bypass techniques",
          "Authentication vulnerabilities"),
    Check("WSTG-ATHN-07", "Weak password policy", Phase.ENDPOINT,
          "auth", _has_auth_endpoint, "auth_sequence",
          "Test password complexity requirements",
          "Authentication vulnerabilities"),
    Check("WSTG-ATHN-03", "Weak lockout mechanism", Phase.ENDPOINT,
          "rate_limit", _has_auth_endpoint, "rate_limit",
          "Test account lockout / rate limiting after repeated attempts",
          "Authentication vulnerabilities"),
    Check("WSTG-ATHN-09", "Weak password-reset token", Phase.ENDPOINT,
          "reset_token", _has_auth_endpoint, "reset_token",
          "Test password-reset tokens for predictability (sequential, timestamp, "
          "below-entropy-floor, or derived from a known value)",
          "Authentication vulnerabilities"),
    Check("WSTG-SESS-01", "Session management", Phase.ENDPOINT,
          "auth", _has_cookie_or_session, "auth_sequence",
          "Test session token generation, fixation, timeout",
          "Authentication vulnerabilities"),
    Check("WSTG-SESS-03", "Session fixation", Phase.ENDPOINT,
          "session_fixation", _has_auth_endpoint, "auth_sequence",
          "Test if session tokens are regenerated after login"),
    Check("WSTG-BUSL-09", "File upload", Phase.ENDPOINT,
          "file_upload", _has_file_path_segment, "manual",
          "Test file type/size/content validation on upload endpoints",
          "File upload vulnerabilities"),
    Check("WSTG-ATHZ-01", "Path traversal", Phase.ENDPOINT,
          "path_traversal", _has_file_path_segment, "path_traversal",
          "Test for directory traversal in file-serving endpoints",
          "Path traversal"),
    Check("WSTG-ERRH-01", "Error handling / stack traces", Phase.ENDPOINT,
          "info_disclosure", _always_applicable, "recon",
          "Trigger errors and check for verbose stack traces / debug info"),
    Check("WSTG-CONF-09", "Mass assignment", Phase.ENDPOINT,
          "api_security", _accepts_body, "sequence",
          "Send extra fields in requests and check if they persist",
          "Mass assignment"),
    Check("WSTG-BUSV-04", "HTTP request smuggling", Phase.ENDPOINT,
          "http_request_smuggling", _accepts_body, "http_request_smuggling",
          "Test CL/TE and TE/CL desync",
          "HTTP request smuggling"),
    Check("WSTG-INPV-14", "HTTP header injection / CRLF", Phase.ENDPOINT,
          "header_injection", _accepts_input, "header_injection",
          "Inject CRLF sequences in header-reflected parameters"),
    Check("WSTG-SESS-09", "CSRF", Phase.ENDPOINT,
          "csrf", _accepts_body, "manual",
          "Test state-changing requests for anti-CSRF protections",
          "Cross-site request forgery (CSRF)"),

    # === PARAMETER phase ===
    Check("WSTG-INPV-05", "SQL injection", Phase.PARAMETER,
          "sqli", _accepts_input, "sqlmap",
          "Test all input parameters for SQL injection",
          "SQL injection"),
    Check("WSTG-INPV-01", "Reflected XSS", Phase.PARAMETER,
          "xss", _accepts_input, "browser_xss",
          "Test input reflection in HTML responses for script injection",
          "Cross-site scripting (XSS)"),
    Check("WSTG-INPV-02", "Stored XSS", Phase.PARAMETER,
          "xss", _accepts_body, "stored_xss",
          "Test stored input rendered in HTML context",
          "Stored cross-site scripting"),
    Check("WSTG-INPV-12", "Command injection", Phase.PARAMETER,
          "command_injection", _accepts_input, "command_injection",
          "Test for OS command injection in parameters",
          "OS command injection"),
    Check("WSTG-INPV-18", "Server-side template injection", Phase.PARAMETER,
          "ssti", _accepts_input, "ssti",
          "Test for template expression evaluation",
          "Server-side template injection (SSTI)"),
    Check("WSTG-INPV-07", "XXE", Phase.PARAMETER,
          "xxe", _accepts_xml, "xxe",
          "Test XML-accepting endpoints for external entity processing",
          "XML external entity (XXE) injection"),
    Check("WSTG-INPV-19", "SSRF", Phase.PARAMETER,
          "ssrf", _has_url_param, "ssrf",
          "Test URL parameters for server-side request forgery",
          "Server-side request forgery (SSRF)"),
    Check("WSTG-INPV-17", "Open redirect", Phase.PARAMETER,
          "open_redirect", _has_url_param, "open_redirect",
          "Test redirect parameters for off-site redirection",
          "Open redirection"),
    Check("WSTG-INPV-06", "NoSQL injection", Phase.PARAMETER,
          "nosql", _accepts_input, "agent",
          "Test for NoSQL query manipulation",
          "NoSQL injection"),
    Check("WSTG-CRYP-04", "JWT weaknesses", Phase.PARAMETER,
          "jwt", _is_authed, "jwt_forge",
          "Test JWT algorithm confusion, key disclosure, claim tampering",
          "JWT attacks"),
    Check("WSTG-INPV-11", "Insecure deserialization", Phase.PARAMETER,
          "deserialization", _accepts_body, "deserialization_oob",
          "Test for unsafe deserialization of user-supplied data",
          "Insecure deserialization"),
    Check("WSTG-BUSL-07", "Race conditions", Phase.PARAMETER,
          "race_condition", _accepts_body, "race_condition",
          "Test for TOCTOU and concurrent-request bugs",
          "Race conditions"),
)

CHECKS_BY_ID: dict[str, Check] = {c.id: c for c in CHECK_CATALOG}
CHECKS_BY_PHASE: dict[Phase, list[Check]] = {}
for _c in CHECK_CATALOG:
    CHECKS_BY_PHASE.setdefault(_c.phase, []).append(_c)


# ---------------------------------------------------------------------------
# Coverage matrix — identity × endpoint × check (I2)
# ---------------------------------------------------------------------------

class CoverageMatrix:
    """The auditable coverage matrix.

    Keys: (identity, endpoint_key, check_id) → CellResult.
    endpoint_key is "METHOD path" matching EngagementState.endpoints keys.
    """

    def __init__(self) -> None:
        self._cells: dict[tuple[str, str, str], CellResult] = {}

    def get(self, identity: str, endpoint_key: str, check_id: str) -> CellResult | None:
        return self._cells.get((identity, endpoint_key, check_id))

    def set(self, identity: str, endpoint_key: str, check_id: str, result: CellResult) -> None:
        self._cells[(identity, endpoint_key, check_id)] = result

    def fill_applicability(self, identities: list[str], endpoints: dict[str, dict],
                           checks: tuple[Check, ...] | None = None) -> int:
        """Pre-fill cells based on each check's applicability predicate.

        Returns the number of cells set to not_applicable. Cells already
        populated (e.g. from a prior run) are not overwritten.
        """
        checks = checks or CHECK_CATALOG
        na_count = 0
        for identity in identities:
            for ep_key, ep_data in endpoints.items():
                for check in checks:
                    key = (identity, ep_key, check.id)
                    if key in self._cells:
                        continue
                    applicable, reason = check.applies(ep_data)
                    if not applicable:
                        self._cells[key] = CellResult.not_applicable(reason)
                        na_count += 1
                    else:
                        self._cells[key] = CellResult(
                            status=CellStatus.PENDING,
                            reason=reason)
        return na_count

    def record(self, identity: str, endpoint_key: str, check_id: str, *,
               status: CellStatus, reason: str = "", severity: str | None = None,
               confidence: float | None = None, validator: str | None = None,
               evidence: str | None = None) -> CellResult:
        """Record a check result. Does NOT overwrite a CONFIRMED cell."""
        key = (identity, endpoint_key, check_id)
        existing = self._cells.get(key)
        if existing and existing.status == CellStatus.CONFIRMED:
            return existing
        result = CellResult(status=status, reason=reason, severity=severity,
                            confidence=confidence, validator=validator, evidence=evidence)
        self._cells[key] = result
        return result

    # --- queries ---

    def cells(self) -> dict[tuple[str, str, str], CellResult]:
        return dict(self._cells)

    def for_endpoint(self, endpoint_key: str) -> dict[tuple[str, str], CellResult]:
        """All (identity, check_id) → result for one endpoint."""
        return {(i, c): r for (i, e, c), r in self._cells.items() if e == endpoint_key}

    def for_identity(self, identity: str) -> dict[tuple[str, str], CellResult]:
        """All (endpoint_key, check_id) → result for one identity."""
        return {(e, c): r for (i, e, c), r in self._cells.items() if i == identity}

    def for_check(self, check_id: str) -> dict[tuple[str, str], CellResult]:
        """All (identity, endpoint_key) → result for one check."""
        return {(i, e): r for (i, e, c), r in self._cells.items() if c == check_id}

    def summary(self) -> dict:
        """Aggregate counts by status, phase, and check."""
        by_status: dict[str, int] = {}
        by_phase: dict[str, dict[str, int]] = {}
        by_check: dict[str, dict[str, int]] = {}
        for (_, _, check_id), result in self._cells.items():
            s = result.status.value
            by_status[s] = by_status.get(s, 0) + 1
            check = CHECKS_BY_ID.get(check_id)
            if check:
                phase = check.phase.value
                by_phase.setdefault(phase, {})
                by_phase[phase][s] = by_phase[phase].get(s, 0) + 1
                by_check.setdefault(check_id, {})
                by_check[check_id][s] = by_check[check_id].get(s, 0) + 1
        total = len(self._cells)
        tested = sum(1 for r in self._cells.values()
                     if r.status not in (CellStatus.PENDING, CellStatus.NOT_APPLICABLE))
        return {
            "total_cells": total,
            "tested": tested,
            "not_applicable": by_status.get("not_applicable", 0),
            "pending": by_status.get("pending", 0),
            "confirmed": by_status.get("confirmed", 0),
            "detected": by_status.get("detected", 0),
            "not_detected": by_status.get("not_detected", 0),
            "by_status": by_status,
            "by_phase": by_phase,
            "by_check": by_check,
        }

    def not_tested(self) -> list[dict]:
        """Cells that were NOT tested, with the reason (I2/I5)."""
        result = []
        for (identity, ep_key, check_id), cell in self._cells.items():
            if cell.status in (CellStatus.NOT_APPLICABLE, CellStatus.SKIPPED):
                result.append({
                    "identity": identity,
                    "endpoint": ep_key,
                    "check": check_id,
                    "status": cell.status.value,
                    "reason": cell.reason,
                })
        return result

    def to_dict(self) -> dict:
        return {
            "cells": {
                f"{i}|{e}|{c}": r.to_dict()
                for (i, e, c), r in self._cells.items()
            }
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CoverageMatrix":
        m = cls()
        for key_str, cell_dict in (d.get("cells", {}) or {}).items():
            parts = key_str.split("|", 2)
            if len(parts) == 3:
                m._cells[(parts[0], parts[1], parts[2])] = CellResult.from_dict(cell_dict)
        return m
