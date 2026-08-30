"""
Phase 2: canned answers, written by genuinely reading each real constructed
prompt (see /tmp/all_prompts.json) and reasoning only from the evidence
shown to that specific agent -- not from out-of-band knowledge of how
PixelMart was built. Where the evidence is genuinely ambiguous or
redacted, the answer reflects that honestly (moderate confidence,
"candidate" framing, or an empty findings list) rather than being
inflated to match the answer key.
"""

# misconfig / supply_chain: PixelMart sends the same Werkzeug/Flask
# version banner on every single response. A disciplined agent shown
# prior-findings context saying "already flagged on this host" should
# not re-report it. We simulate that: report once (first occurrence per
# host), empty afterward. api_security: nothing API-shape-specific ever
# stands out in this app, so it's empty throughout.
GENERIC_REPORTED = {"misconfig": False, "supply_chain": False}

MISCONFIG_FINDING = {
    "findings": [{
        "vulnerability_class": "misconfig",
        "confidence": 0.75,
        "severity": "low",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "summary": "Verbose Server/X-Powered-By banners disclose exact framework and language versions on every response.",
        "evidence": "Server: Werkzeug/3.1.7 Python/3.12.3; X-Powered-By: PixelMart/2.3.1 (Flask)",
        "suggested_test": "No active test needed -- passively note the banner and check it against known CVEs for the disclosed versions.",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}
SUPPLY_CHAIN_FINDING = {
    "findings": [],
    "components": [
        {"ecosystem": "PyPI", "name": "Werkzeug", "version": "3.1.7", "source": "Server response header"},
    ],
}
EMPTY = {"findings": [], "components": []}

# Keyed by (exchange_index, agent_name) -> response dict.
ANSWERS = {}

# ---- TP1: SQLi auth bypass on /api/login ----
ANSWERS[(4, "auth")] = {
    "findings": [{
        "vulnerability_class": "auth",
        "confidence": 0.85,
        "severity": "critical",
        "owasp_category": "A03:2021-Injection",
        "summary": "Login accepted a username field containing SQL comment syntax with an arbitrary password and returned a valid admin-role token.",
        "evidence": "Request username \"admin' -- \" with password \"anything\" returned {\"role\":\"admin\",\"token\":\"...\"} with HTTP 200.",
        "suggested_test": "In Repeater, replay with username set to a normal non-existent username and confirm login fails, isolating whether the ' -- syntax is what causes the bypass.",
        "basis": "derived",
        "validation_hints": ["sqlmap"],
    }],
    "components": [],
}
ANSWERS[(4, "business_logic")] = EMPTY

# ---- TP2: SQLi UNION exfil ----
ANSWERS[(5, "sqli")] = {
    "findings": [{
        "vulnerability_class": "sqli",
        "confidence": 0.97,
        "severity": "critical",
        "owasp_category": "A03:2021-Injection",
        "summary": "UNION-based SQL injection in the product search endpoint returns full user credential data in place of product fields.",
        "evidence": "q=zzz' UNION SELECT id,username,password,role FROM users -- returned [{\"name\":\"alice\",\"price\":\"alicepw123\",...}] -- username/password/role values appearing in product name/price/description fields.",
        "suggested_test": "Confirm column count and data types were guessed correctly by varying the UNION SELECT column list; extract remaining tables via further UNION queries.",
        "basis": "derived",
        "validation_hints": ["sqlmap"],
    }],
    "components": [],
}
ANSWERS[(5, "xss")] = EMPTY

# ---- TP3: IDOR profile ----
ANSWERS[(6, "auth")] = EMPTY
ANSWERS[(6, "idor")] = {
    "findings": [{
        "vulnerability_class": "idor",
        "confidence": 0.55,
        "severity": "high",
        "owasp_category": "A01:2021-Broken Access Control",
        "summary": "Profile endpoint returns full PII (email, address, balance) scoped only by a numeric URL id, with an auth token present but its ownership unverifiable from this exchange alone.",
        "evidence": "GET /api/users/2/profile with an Authorization header returned {\"email\":\"bob@example.com\",\"address\":...,\"balance\":31.0} for id=2.",
        "suggested_test": "Replay this exact request with a token belonging to a different user, or the same token against a different numeric id, and compare -- this single exchange can't confirm whether the token's owner was checked against the id.",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}

# ---- TP4: IDOR order (idor now dispatches thanks to the /order URL-pattern fix) ----
ANSWERS[(7, "auth")] = EMPTY
ANSWERS[(7, "idor")] = {
    "findings": [{
        "vulnerability_class": "idor",
        "confidence": 0.55,
        "severity": "high",
        "owasp_category": "A01:2021-Broken Access Control",
        "summary": "Order endpoint returns full order details (product, quantity, total, owning user_id) scoped only by a numeric URL id, with an auth token present but its ownership unverifiable from this exchange alone.",
        "evidence": "GET /api/orders/1 with an Authorization header returned {\"user_id\":2,\"total_price\":69.0,...} for order id=1.",
        "suggested_test": "Replay with a token belonging to a different user against the same order id, or the same token against a different sequential order id, and compare -- this single exchange can't confirm whether the token's owner was checked against the order's user_id.",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}

# ---- TP5: reflected XSS ----
ANSWERS[(8, "sqli")] = EMPTY
ANSWERS[(8, "xss")] = {
    "findings": [{
        "vulnerability_class": "xss",
        "confidence": 0.95,
        "severity": "medium",
        "owasp_category": "A03:2021-Injection",
        "summary": "The 'q' query parameter is reflected into the HTML response with no encoding.",
        "evidence": "q=<script>alert(1)</script> appears verbatim, unescaped, inside <p>Results for: ...</p> in a text/html response.",
        "suggested_test": "Replay with a payload that exfiltrates document.cookie to an analyst-controlled listener to confirm real-world impact beyond alert().",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}

# ---- TP6: stored XSS ----
ANSWERS[(9, "xss")] = {
    "findings": [{
        "vulnerability_class": "xss",
        "confidence": 0.95,
        "severity": "high",
        "owasp_category": "A03:2021-Injection",
        "summary": "A previously-submitted comment body is rendered into HTML with no encoding -- stored XSS, affects every visitor to this page, not just the submitter.",
        "evidence": "Response body contains a live <script>document.location=... +document.cookie</script> tag sourced from stored comment data, served as text/html.",
        "suggested_test": "Confirm persistence by fetching this same view endpoint from a separate session/browser and observing the script still renders.",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}

# ---- TP7: business logic (business_logic and idor now both dispatch,
# thanks to the /order URL pattern also covering the collection endpoint) ----
ANSWERS[(10, "auth")] = EMPTY
ANSWERS[(10, "business_logic")] = {
    "findings": [{
        "vulnerability_class": "business_logic",
        "confidence": 0.9,
        "severity": "critical",
        "owasp_category": "A04:2021-Insecure Design",
        "summary": "Placing an order with a negative quantity produced a negative total_price, and the response's new_balance reflects the user being credited rather than charged -- the workflow does not validate that quantity (or the resulting total) is non-negative.",
        "evidence": "Request {\"product_id\": 2, \"quantity\": -5} returned {\"new_balance\":499.95,\"status\":\"ordered\",\"total_price\":-399.95} -- a negative charge on a purchase is not a valid business state regardless of what the starting balance was.",
        "suggested_test": "Repeat with other negative quantities and confirm the balance increases proportionally; check whether any server-side minimum-quantity validation exists at all.",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}
ANSWERS[(10, "idor")] = EMPTY  # a creation endpoint with no target object id; not idor's specialty

# ---- TP8: first (successful) coupon redemption -- no vuln-specific agents dispatched ----

# ---- TP9: SSRF ----
ANSWERS[(12, "ssrf")] = {
    "findings": [{
        "vulnerability_class": "ssrf",
        "confidence": 0.9,
        "severity": "critical",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
        "summary": "The avatar endpoint fetches an attacker-supplied URL server-side with no scheme or host restriction, including local files via file://.",
        "evidence": "{\"url\":\"file:///tmp/internal_secret.txt\"} returned {\"content_preview\":\"top secret internal data\",\"status\":\"fetched\"} -- the server read and returned an arbitrary local file.",
        "suggested_test": "Try http://169.254.169.254/ or an internal-only hostname/port to check for cloud-metadata or internal-service exposure beyond local file read.",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}
ANSWERS[(12, "xss")] = EMPTY

# ---- TP10: path traversal ----
ANSWERS[(13, "sqli")] = EMPTY
ANSWERS[(13, "ssrf")] = {
    "findings": [{
        "vulnerability_class": "ssrf",
        "confidence": 0.9,
        "severity": "high",
        "owasp_category": "A01:2021-Broken Access Control",
        "summary": "The 'file' parameter accepts a relative path and returns arbitrary files outside the intended invoices directory -- path traversal / arbitrary file read.",
        "evidence": "file=../app.py returned the application's own Python source code as plain text.",
        "suggested_test": "Try deeper traversal (../../../../etc/passwd) to establish how far outside the intended directory the read extends.",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}
ANSWERS[(13, "xss")] = EMPTY

# ---- TP11: alg=none forged token (now visible after the security.py fix --
# the request header exposes only the JWT's algorithm field, never the
# payload or signature, but that's exactly the evidence needed here) ----
ANSWERS[(14, "auth")] = {
    "findings": [{
        "vulnerability_class": "auth",
        "confidence": 0.9,
        "severity": "critical",
        "owasp_category": "A02:2021-Cryptographic Failures",
        "summary": "The request's JWT header declares alg:none, and the server returned a full authenticated response -- if the server accepts unsigned tokens, any client can forge a token for any user or role with no secret required.",
        "evidence": "Authorization header's JWT header segment is {\"alg\": \"none\", \"typ\": \"JWT\"}; the request nonetheless succeeded and returned the target user's full profile.",
        "suggested_test": "Construct a token with header {\"alg\":\"none\"}, an empty signature segment, and a payload claiming a different user id or an admin role; replay against any authenticated endpoint to confirm the server accepts it.",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}
ANSWERS[(14, "idor")] = {
    "findings": [{
        "vulnerability_class": "idor",
        "confidence": 0.4,
        "severity": "medium",
        "owasp_category": "A01:2021-Broken Access Control",
        "summary": "Profile endpoint returns full PII scoped only by URL id; token ownership can't be verified from this single redacted exchange.",
        "evidence": "GET /api/users/3/profile with an Authorization header present returned the admin user's full profile.",
        "suggested_test": "Compare this response against the same request made with a different, known-valid user token to check whether the id is actually cross-checked against the caller's identity.",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}

# ---- TP12: unauthenticated admin config ----
ANSWERS[(15, "auth")] = {
    "findings": [{
        "vulnerability_class": "auth",
        "confidence": 0.97,
        "severity": "critical",
        "owasp_category": "A01:2021-Broken Access Control",
        "summary": "Admin configuration endpoint requires no authentication at all and returns the JWT signing secret and internal database path.",
        "evidence": "GET /api/admin/config with no Authorization header present (request-headers block is empty) returned 200 with jwt_secret, db_path, and debug:true in the body.",
        "suggested_test": "Confirm the secret is live by using it to forge a signed (not just alg=none) token for an arbitrary user and replaying it against an authenticated endpoint.",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}
ANSWERS[(15, "idor")] = EMPTY  # no object id in this URL; not idor's specialty

# ---- TN1 / TN2: no vuln-specific agents dispatched (correctly) ----

# ---- TN3: safe self-profile ----
ANSWERS[(18, "auth")] = EMPTY
ANSWERS[(18, "idor")] = EMPTY  # identity comes from the token itself, no id parameter to manipulate

# ---- TN4: sort param allowlisted (red herring) ----
ANSWERS[(19, "business_logic")] = EMPTY
ANSWERS[(19, "sqli")] = EMPTY
ANSWERS[(19, "xss")] = {
    "findings": [{
        "vulnerability_class": "xss",
        "confidence": 0.3,
        "severity": "low",
        "owasp_category": "A03:2021-Injection",
        "summary": "Response body (application/json) contains an unescaped <script> tag in stored comment data, but this endpoint serves it as JSON, not rendered HTML -- risk is downstream only.",
        "evidence": "\"body\":\"<script>document.location=...</script>\" returned with Content-Type: application/json.",
        "suggested_test": "Check whether any client code parses this field and inserts it into the DOM (innerHTML or equivalent) rather than treating it as inert text -- this response by itself does not execute in a standards-compliant browser.",
        "basis": "assumed",
        "validation_hints": [],
    }],
    "components": [],
}

# ---- TN5: CSRF correctly enforced ----
ANSWERS[(20, "auth")] = EMPTY  # 403 rejection is the CORRECT behavior, not a finding
ANSWERS[(20, "business_logic")] = EMPTY
ANSWERS[(20, "idor")] = EMPTY

# ---- TP8b: coupon already-used rejection ----
ANSWERS[(22, "business_logic")] = EMPTY
ANSWERS[(22, "race_condition")] = {
    "findings": [{
        "vulnerability_class": "race_condition",
        "confidence": 0.6,
        "severity": "medium",
        "owasp_category": "A04:2021-Insecure Design",
        "summary": "Coupon redemption is a check-then-act, single-use resource (error message confirms a use-count limit is enforced) -- a plausible TOCTOU candidate for concurrent testing.",
        "evidence": "{\"error\":\"coupon already used\"} confirms a max-use check exists; a single sequential request pattern can't confirm whether that check is atomic.",
        "suggested_test": "Fire 10-20 concurrent redemption requests for the same coupon code and check whether more than the intended number succeed.",
        "basis": "derived",
        "validation_hints": [],
    }],
    "components": [],
}


def get_answer(exchange_index: int, agent_name: str) -> dict:
    if agent_name == "misconfig":
        if not GENERIC_REPORTED["misconfig"]:
            GENERIC_REPORTED["misconfig"] = True
            return MISCONFIG_FINDING
        return EMPTY
    if agent_name == "supply_chain":
        if not GENERIC_REPORTED["supply_chain"]:
            GENERIC_REPORTED["supply_chain"] = True
            return SUPPLY_CHAIN_FINDING
        return EMPTY
    if agent_name == "api_security":
        return EMPTY
    return ANSWERS.get((exchange_index, agent_name), EMPTY)
