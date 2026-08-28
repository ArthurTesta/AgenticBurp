from __future__ import annotations
from models import Finding, HttpExchange, TestPlan
from categories import canonicalize
import hashlib

# Declarative capabilities that the Burp execution plane can implement without
# granting an LLM arbitrary HTTP or shell access.
_CAPABILITIES = {
    "idor": ("cross_identity_compare", True),
    "business_logic": ("workflow_replay_compare", True),
    "business_logic_enhanced": ("workflow_replay_compare", True),
    "rate_limit": ("bounded_rate_limit_probe", True),
    "ssrf": ("controlled_callback_probe", True),
    "auth": ("authorization_boundary_compare", True),
    "xss": ("reflection_context_validation", True),
    "jwt": ("jwt_validation", True),
    "xxe": ("xxe_validation", True),
    "csrf": ("csrf_validation", True),
    "file_upload": ("file_upload_validation", True),
    "nosql": ("nosql_validation", True),
    "command_injection": ("command_injection_validation", True),
    "ssti": ("ssti_validation", True),
    "open_redirect": ("open_redirect_validation", True),
    "info_disclosure": ("info_disclosure_scan", False),  # Passive, no active validation
    "cors": ("cors_misconfiguration_detection", True),
    "recon": ("attack_surface_mapping", True),
    "http_request_smuggling": ("http_request_smuggling_detection", True),
}

def exchange_fingerprint(exchange: HttpExchange) -> str:
    material = "\x1f".join([
        exchange.method.upper(), exchange.url,
        *[f"{k.lower()}:{v}" for k, v in sorted(exchange.request_headers.items())],
        exchange.request_body,
    ]).encode()
    return hashlib.sha256(material).hexdigest()

def _plan_id(capability: str, finding: Finding, exchange: HttpExchange) -> str:
    material = f"{capability}|{finding.vulnerability_class}|{exchange_fingerprint(exchange)}".encode()
    return f"{capability}:{hashlib.sha256(material).hexdigest()[:20]}"


def plans_for_findings(exchange: HttpExchange, findings: list[Finding]) -> list[TestPlan]:
    """Translate hypotheses into safe capabilities without asking each agent
    to know implementation details. Explicit hints remain supported for
    tool-specific capabilities such as sqlmap.

    Category matching goes through categories.canonicalize() rather than a
    bare lowercase string comparison against finding.vulnerability_class.
    That field is genuinely free text an LLM writes (see base_agent.py's
    prompt -- there is no enum constraint on it); an exact-match lookup
    meant an agent writing "Insecure Direct Object Reference" instead of
    the literal string "idor" would silently produce zero test plans,
    with no error and no visible sign that a plan should have existed.
    """
    plans: list[TestPlan] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        candidates = list(finding.validation_hints or [])
        category = canonicalize(finding.vulnerability_class)
        if category and category in _CAPABILITIES:
            candidates.append(category)
        if category == "sqli" or "sqlmap" in candidates:
            candidates.append("sql_injection_validation")
        if category == "jwt":
            candidates.append("jwt_validation")
        if category == "xxe":
            candidates.append("xxe_validation")
        if category == "csrf":
            candidates.append("csrf_validation")
        if category == "file_upload":
            candidates.append("file_upload_validation")
        if category == "nosql":
            candidates.append("nosql_validation")
        if category == "command_injection":
            candidates.append("command_injection_validation")
        if category == "ssti":
            candidates.append("ssti_validation")
        if category == "open_redirect":
            candidates.append("open_redirect_validation")
        if category == "business_logic_enhanced":
            candidates.append("workflow_replay_compare")
        for hint in candidates:
            if hint == "sqlmap":
                cap, requires, plane = "sql_injection_validation", True, "local_tool"
            elif hint in _CAPABILITIES:
                cap, requires = _CAPABILITIES[hint]
                plane = "burp"
            elif hint in ("sql_injection_validation", "jwt_validation", "xxe_validation", "csrf_validation", "file_upload_validation", "nosql_validation", "command_injection_validation", "ssti_validation", "open_redirect_validation"):
                cap, requires, plane = hint, True, "local_tool"
            else:
                continue
            key = (finding.vulnerability_class, cap)
            if key in seen:
                continue
            seen.add(key)
            plans.append(TestPlan(
                id=_plan_id(cap, finding, exchange),
                capability=cap,
                finding_class=finding.vulnerability_class,
                category=category,
                source_exchange_url=exchange.url,
                mutation={"strategy": "validator-defined", "source": "captured-exchange"},
                success_signals=["independent evidence supports the hypothesis"],
                requires_approval=requires,
                execution_plane=plane,
                rationale=finding.suggested_test,
                source_exchange_hash=exchange_fingerprint(exchange),
            ))
    return plans
