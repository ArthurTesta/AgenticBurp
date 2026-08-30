# Security Findings Report -- localhost:3000

Generated: 2026-08-29 05:02 UTC

**9 confirmed finding(s)**, **2 unconfirmed finding(s)**, **0 potential attack chain(s)**.

*1 previously-suppressed finding(s) from earlier scans are not shown below.* Suppression means an analyst already reviewed and dismissed these (typically as false positives) -- not that they were re-checked and cleared this run. Declared here so the count is never silently missing from the total.

> Unconfirmed findings are hypotheses from an LLM agent's analysis of captured traffic, not verified vulnerabilities. Each is labeled with its `basis` -- treat `assumed` and `recalled` findings with extra scrutiny before acting on them. Confirmed findings were independently checked by a validator (an active probe, a byte-level format check, or equivalent) and carry stronger evidence.

## Confirmed Findings

### sqli -- http://localhost:3000/rest/products/search?q=apple%27%20UNION%20SELECT%201--

**Status:** ✅ CONFIRMED &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Confidence:** 0.98 (very likely) &nbsp;|&nbsp; **Basis:** derived
**OWASP category:** A03:2021-Injection

**Description:** The 'q' parameter on /rest/products/search is directly concatenated into a raw SQL query, confirmed exploitable to bypass a data-visibility filter.

**Evidence:**
```
GET /rest/products/search?q=apple' UNION SELECT 1-- returned HTTP 500 with the literal database error "SQLITE_ERROR: near \"UNION\": syntax error" -- proving the parameter reaches raw SQL unescaped. Follow-up confirmed real impact: q=')--" returned 56 products vs 46 for a normal empty-query baseline, meaning the injected query-closing payload bypassed a WHERE clause condition (almost certainly a deletedAt/visibility filter), exposing 10 additional hidden or soft-deleted products that a legitimate search would never surface.
```

**Steps to reproduce:** Already confirmed end-to-end via the two requests above; a full sqlmap run would further characterize the injection point.

**Suggested remediation:** Use parameterized queries / prepared statements everywhere user input reaches SQL; never build queries via string concatenation. _(generic starting point -- verify against this target's actual implementation)_

_Reported by: `stand_in_agents`_
_Fingerprint: `3fa0edd554c5c60d` -- use this to suppress if this is a false positive, so it doesn't resurface on a future scan of this host._

---

### business_logic -- http://localhost:3000/api/Users

**Status:** ✅ CONFIRMED &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Confidence:** 0.98 (very likely) &nbsp;|&nbsp; **Basis:** derived
**OWASP category:** A01:2021-Broken Access Control

**Description:** Unauthenticated self-registration accepts a client-supplied "role" field, allowing anyone to create an admin account with no privilege check.

**Evidence:**
```
POST /api/Users with "role":"admin" in the body (alongside the normal registration fields) returned success with role echoed back as "admin" and profileImage set to the admin default avatar. Fully confirmed end-to-end: logging in with the new account and decoding the returned JWT shows "role":"admin" in the token payload -- a genuine, unauthenticated privilege escalation to admin via mass assignment on the public registration endpoint, not just an echoed field.
```

**Steps to reproduce:** Already confirmed end-to-end via registration + login + JWT decode above.

**Suggested remediation:** Add server-side validation of business rules (limits, sequencing, ownership) that doesn't rely on client-side enforcement or UI flow alone. _(generic starting point -- verify against this target's actual implementation)_

_Reported by: `stand_in_agents`_
_Fingerprint: `d89610cf4a1bc1cb` -- use this to suppress if this is a false positive, so it doesn't resurface on a future scan of this host._

---

### info_disclosure -- http://localhost:3000/ftp

**Status:** ✅ CONFIRMED &nbsp;|&nbsp; **Severity:** 🔴 CRITICAL &nbsp;|&nbsp; **Confidence:** 0.97 (very likely) &nbsp;|&nbsp; **Basis:** derived
**OWASP category:** A01:2021-Broken Access Control

**Description:** The unauthenticated /ftp listing exposes a downloadable KeePass password database (incident-support.kdbx) and multiple backup files.

**Evidence:**
```
Directory listing at /ftp lists incident-support.kdbx, package.json.bak, package-lock.json.bak, coupons_2013.md.bak, and others, all reachable with no authentication. Follow-up confirmed: GET /ftp/incident-support.kdbx returned HTTP 200, downloading 3246 bytes -- matching the size shown in the listing exactly. This is a fully confirmed, unauthenticated password-database exposure, not just a listed filename.
```

**Steps to reproduce:** Already confirmed: GET /ftp/incident-support.kdbx returns the real KeePass file with no authentication.

**Suggested remediation:** Remove verbose error messages, stack traces, and internal identifiers from responses served to end users. _(generic starting point -- verify against this target's actual implementation)_

_Reported by: `stand_in_agents`_
_Fingerprint: `7f7ac4ddfe6f3ceb` -- use this to suppress if this is a false positive, so it doesn't resurface on a future scan of this host._

---

### supply_chain -- http://localhost:3000/ftp/package.json.bak%2500.md

**Status:** ✅ CONFIRMED &nbsp;|&nbsp; **Severity:** 🟠 HIGH &nbsp;|&nbsp; **Confidence:** 0.97 (very likely) &nbsp;|&nbsp; **Basis:** derived
**OWASP category:** A05:2021-Security Misconfiguration

**Description:** A server-side extension allowlist meant to restrict /ftp downloads to .md/.pdf files is bypassed via a double-URL-encoded null byte, fully exposing the real package.json.bak dependency manifest.

**Evidence:**
```
GET /ftp/package.json.bak directly returns 403 ("Only .md and .pdf files are allowed!"). GET /ftp/package.json.bak%2500.md (a double-encoded null byte followed by an allowed extension) returns 200 with the real manifest content: juice-shop@6.2.0-SNAPSHOT and 39 listed dependencies (body-parser~1.18, colors~1.1, config~1.28, cookie-parser~1.4, cors~2.8, and 34 more), fully confirming both the filter bypass and the dependency-version disclosure.
```

**Steps to reproduce:** Already confirmed end-to-end via the exact request above.

**Suggested remediation:** Pin dependency versions, monitor for disclosed advisories against them, and remove exposed manifests/lockfiles from public access. _(generic starting point -- verify against this target's actual implementation)_

_Reported by: `stand_in_agents`_
_Fingerprint: `df0e7df01fb3a189` -- use this to suppress if this is a false positive, so it doesn't resurface on a future scan of this host._

---

### misconfig -- http://localhost:3000/ftp/coupons_2013.md.bak%2500.md

**Status:** ✅ CONFIRMED &nbsp;|&nbsp; **Severity:** 🟠 HIGH &nbsp;|&nbsp; **Confidence:** 0.97 (very likely) &nbsp;|&nbsp; **Basis:** derived
**OWASP category:** A05:2021-Security Misconfiguration

**Description:** The /ftp extension-filter bypass (double-encoded null byte) is not specific to one file -- it retrieves any file in the listing regardless of blocked extension.

**Evidence:**
```
The same %2500.md bypass previously confirmed against package.json.bak was reapplied to coupons_2013.md.bak (also listed but not directly downloadable due to the .md/.pdf-only filter). GET /ftp/coupons_2013.md.bak%2500.md returned 200 with real file content (an obfuscated/enciphered block of text, consistent with the listing's separate announcement_encrypted.md also being an intentionally-obscured file) -- confirming the bypass is a general filter defeat applicable to every blocked file in the directory, not a one-off against a single filename.
```

**Steps to reproduce:** The bypass generalizes: any filename in the /ftp listing can be retrieved by appending %2500 followed by an allowed extension (.md or .pdf), regardless of its real extension.

**Suggested remediation:** Review server/framework configuration against current vendor hardening guidance; remove default credentials, debug endpoints, and verbose error output in production. _(generic starting point -- verify against this target's actual implementation)_

_Reported by: `stand_in_agents`_
_Fingerprint: `b434d92812a33025` -- use this to suppress if this is a false positive, so it doesn't resurface on a future scan of this host._

---

### misconfig -- http://localhost:3000/ftp

**Status:** ✅ CONFIRMED &nbsp;|&nbsp; **Severity:** 🟠 HIGH &nbsp;|&nbsp; **Confidence:** 0.90 (very likely) &nbsp;|&nbsp; **Basis:** derived
**OWASP category:** A05:2021-Security Misconfiguration

**Description:** GET /ftp serves an unauthenticated, fully browsable directory listing with no access control.

**Evidence:**
```
Response is a standard directory-index HTML page for /ftp, returned with no auth sent and no redirect/401/403.
```

**Steps to reproduce:** Request /ftp with no session and confirm the listing returns; check sibling paths for the same behavior.

**Suggested remediation:** Review server/framework configuration against current vendor hardening guidance; remove default credentials, debug endpoints, and verbose error output in production. _(generic starting point -- verify against this target's actual implementation)_

_Reported by: `stand_in_agents`_
_Fingerprint: `cd9201059b02d196` -- use this to suppress if this is a false positive, so it doesn't resurface on a future scan of this host._

---

### misconfig -- http://localhost:3000/rest/admin/application-configuration

**Status:** ✅ CONFIRMED &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Confidence:** 0.90 (very likely) &nbsp;|&nbsp; **Basis:** derived
**OWASP category:** A05:2021-Security Misconfiguration

**Description:** GET /rest/admin/application-configuration exposes internal application configuration with no authentication required.

**Evidence:**
```
Response includes internal-only configuration: the LLM model backing the chatbot feature (gemma4:e4b), a Google OAuth client ID and its full list of authorized redirect URIs (including internal/staging hostnames), CTF challenge trap URLs and an embedded XSS bonus payload string, a CSAF hash value, and metrics-collection internals -- none of which should be readable by an unauthenticated visitor in a production deployment.
```

**Steps to reproduce:** Confirm the same 200/full-body response is returned with no Authorization header or session cookie at all (already the case in the captured request).

**Suggested remediation:** Review server/framework configuration against current vendor hardening guidance; remove default credentials, debug endpoints, and verbose error output in production. _(generic starting point -- verify against this target's actual implementation)_

_Reported by: `stand_in_agents`_
_Fingerprint: `6af3486927704aec` -- use this to suppress if this is a false positive, so it doesn't resurface on a future scan of this host._

---

### auth -- http://localhost:3000/rest/user/security-question?email=admin@juice-sh.op

**Status:** ✅ CONFIRMED &nbsp;|&nbsp; **Severity:** 🟡 MEDIUM &nbsp;|&nbsp; **Confidence:** 0.85 (very likely) &nbsp;|&nbsp; **Basis:** derived
**OWASP category:** A07:2021-Identification and Authentication Failures

**Description:** GET /rest/user/security-question discloses a target account's password-recovery security question with no authentication and no observed rate limiting.

**Evidence:**
```
GET /rest/user/security-question?email=admin@juice-sh.op returned the real question ("Mother's maiden name?") with no authentication required. 5 rapid consecutive requests all returned 200 with no throttling, 429, or Retry-After observed, meaning an attacker can query security questions for arbitrarily many targeted email addresses without being slowed down. A commonly-guessable question like this materially lowers the bar for the password-reset flow downstream. Note: a genuine user-enumeration claim (does {} vs a real question reliably indicate account non-existence vs existence) could NOT be confirmed from this test -- my own test accounts (registered via raw API calls rather than the normal signup flow) returned {} for reasons that may be an artifact of how their security question was linked, not necessarily representative of how a normally-registered account would behave. That specific angle is flagged as unconfirmed, not claimed.
```

**Steps to reproduce:** Register a fresh account via the normal signup flow (not a raw API call) with a real security question, then compare its security-question response against a genuinely non-existent email to establish whether this endpoint reliably enables account enumeration.

**Suggested remediation:** Review session token generation (entropy, rotation on login), cookie attributes (Secure/HttpOnly/SameSite), and CSRF protection on state-changing endpoints. _(generic starting point -- verify against this target's actual implementation)_

_Reported by: `stand_in_agents`_
_Fingerprint: `52a6044ff1e2e694` -- use this to suppress if this is a false positive, so it doesn't resurface on a future scan of this host._

---

### misconfig -- http://localhost:3000/api/Feedbacks/

**Status:** ✅ CONFIRMED &nbsp;|&nbsp; **Severity:** 🔵 LOW &nbsp;|&nbsp; **Confidence:** 0.85 (very likely) &nbsp;|&nbsp; **Basis:** derived
**OWASP category:** A05:2021-Security Misconfiguration

**Description:** POST /api/Feedbacks/ returns a verbose 500 error revealing internal ORM/query parameter names instead of a clean validation error.

**Evidence:**
```
A syntactically valid JSON body missing an undocumented required field (captchaId) produced HTTP 500 with the literal text: Error: WHERE parameter "captchaId" has invalid "undefined" value -- exposing the backend ORM's internal parameter-binding behavior rather than a generic 400 Bad Request.
```

**Steps to reproduce:** Resend the same request and observe the full stack trace in the response body for additional internal file paths or framework version detail beyond what is captured here.

**Suggested remediation:** Review server/framework configuration against current vendor hardening guidance; remove default credentials, debug endpoints, and verbose error output in production. _(generic starting point -- verify against this target's actual implementation)_

_Reported by: `stand_in_agents`_
_Fingerprint: `50a76395f93d3153` -- use this to suppress if this is a false positive, so it doesn't resurface on a future scan of this host._

---

## Unconfirmed Findings

_These have not been independently validated. Verify manually before including them in a submission._

### xss -- http://localhost:3000/rest/products/1/reviews

**Status:** ❓ UNCONFIRMED &nbsp;|&nbsp; **Severity:** 🟠 HIGH &nbsp;|&nbsp; **Confidence:** 0.55 (possible) &nbsp;|&nbsp; **Basis:** derived
**OWASP category:** A03:2021-Injection

**Description:** A raw, unescaped <script> tag submitted via the review API is stored and returned verbatim by GET /rest/products/{id}/reviews with no server-side encoding.

**Evidence:**
```
Submitted PUT /rest/products/1/reviews with message="<script>alert(document.cookie)</script>" (no encoding applied on submission). GET /rest/products/1/reviews subsequently returned the exact same string, completely unescaped, inside the JSON message field. This confirms the REST API itself performs no server-side HTML sanitization/encoding on review content -- but this exchange alone cannot establish whether the actual rendered product page executes it: this sandbox only has a placeholder (non-Angular) frontend, so the real rendering behavior (Angular's default template auto-escaping vs. an unsafe [innerHTML] binding) could not be observed. If the frontend uses safe interpolation, the API-level lack of encoding would not translate into exploitable XSS; if it uses unsafe HTML binding for review text, this is a directly exploitable stored XSS reachable by any visitor viewing this product's reviews.
```

**Steps to reproduce:** Load the actual product page in a real browser (with the real Angular frontend built, not this sandbox's placeholder) and check whether the injected <script> executes -- or inspect the frontend's review-rendering component source for [innerHTML]/bypassSecurityTrustHtml usage.

**Suggested remediation:** Apply context-aware output encoding at the point of rendering, and adopt a restrictive Content-Security-Policy without 'unsafe-inline'/'unsafe-eval' as defense in depth. _(generic starting point -- verify against this target's actual implementation)_

_Reported by: `stand_in_agents`_
_Fingerprint: `e82b6a3c401afb5c` -- use this to suppress if this is a false positive, so it doesn't resurface on a future scan of this host._

---

### sqli -- http://localhost:3000/api/Feedbacks/

**Status:** ❓ UNCONFIRMED &nbsp;|&nbsp; **Severity:** 🔵 LOW &nbsp;|&nbsp; **Confidence:** 0.25 (speculative) &nbsp;|&nbsp; **Basis:** assumed
> ⚠️ Rests on an assumption the model made, not something directly observed -- confirm the assumption holds before relying on this.

**Description:** The captchaId validation error suggests a SQL-backed (WHERE-clause) query construction, worth checking for injection once the required field is understood -- not demonstrated here.

**Evidence:**
```
Error text references a WHERE clause parameter, consistent with a SQL/ORM-backed lookup, but no injection was attempted or shown in this exchange -- this is a plausibility note about the backend, not a finding of injectability.
```

**Steps to reproduce:** Once captchaId's expected format is known (likely from a prior /rest/captcha response), resubmit with a single-quote or boolean-based probe in the comment/captchaId fields and compare responses.

**Suggested remediation:** Use parameterized queries / prepared statements everywhere user input reaches SQL; never build queries via string concatenation. _(generic starting point -- verify against this target's actual implementation)_

_Reported by: `stand_in_agents`_
_Fingerprint: `f28073f92cf513c0` -- use this to suppress if this is a false positive, so it doesn't resurface on a future scan of this host._

---

