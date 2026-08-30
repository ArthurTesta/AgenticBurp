"""
PixelMart -- a small, deliberately-vulnerable e-commerce API.

Built specifically to test the Burp LLM Harness against a target that has
NEVER been publicly documented, walked through, or blogged about --
unlike OWASP Juice Shop, whose vulnerabilities and exact exploit steps
are extensively described in training data for any LLM. A "confirmed"
finding against Juice Shop can't distinguish genuine reasoning from
recall of a write-up. This app exists to force the former.

Single file, one dependency (Flask), SQLite for real data (real SQL
injection, not simulated), a hand-rolled JWT implementation (real
alg=none and weak-secret bugs, not simulated), and a real outbound HTTP
fetch for the avatar feature (real SSRF, not simulated).

See ANSWER_KEY.md in this directory for the ground-truth list of what's
planted where -- don't read it before running the harness against this
app, or you'll bias your own review of its findings.

Run: python app.py  (defaults to http://127.0.0.1:5001)
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
import urllib.request
from pathlib import Path

from flask import Flask, request, jsonify, g

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "pixelmart.db"
INVOICE_DIR = APP_DIR / "invoices"
JWT_SECRET = "supersecretkey123"  # intentionally weak -- see ANSWER_KEY.md

app = Flask(__name__)
app.config["FRAMEWORK_BANNER"] = "PixelMart/2.3.1 (Flask)"


# ---------------------------------------------------------------------------
# Data layer
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            address TEXT,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 100.0
        );
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        );
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            total_price REAL,
            status TEXT DEFAULT 'placed'
        );
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            product_id INTEGER,
            author TEXT,
            body TEXT
        );
        CREATE TABLE coupons (
            code TEXT PRIMARY KEY,
            discount_percent INTEGER,
            max_uses INTEGER,
            used_count INTEGER DEFAULT 0
        );
    """)
    conn.executemany(
        "INSERT INTO users (username, password, email, address, role) VALUES (?, ?, ?, ?, ?)",
        [
            ("alice", "alicepw123", "alice@example.com", "12 Rowan St, Springfield", "user"),
            ("bob", "bobpw456", "bob@example.com", "88 Larch Ave, Shelbyville", "user"),
            ("admin", "correct-horse-battery", "admin@pixelmart.test", "HQ, Capital City", "admin"),
        ],
    )
    conn.executemany(
        "INSERT INTO products (name, price, description) VALUES (?, ?, ?)",
        [
            ("Wireless Mouse", 24.99, "2.4GHz wireless mouse, 1600 DPI"),
            ("Mechanical Keyboard", 79.99, "Hot-swappable, brown switches"),
            ("USB-C Hub", 34.50, "7-in-1 hub with HDMI and SD card reader"),
            ("Webcam 1080p", 45.00, "Autofocus, built-in mic"),
        ],
    )
    conn.execute(
        "INSERT INTO coupons (code, discount_percent, max_uses, used_count) VALUES (?, ?, ?, ?)",
        ("WELCOME10", 10, 1, 0),
    )
    conn.commit()
    conn.close()
    INVOICE_DIR.mkdir(exist_ok=True)
    (INVOICE_DIR / "invoice-1001.txt").write_text(
        "Invoice #1001\nWireless Mouse x1 - $24.99\n"
    )


# ---------------------------------------------------------------------------
# Hand-rolled JWT -- intentionally accepts alg=none (see ANSWER_KEY.md)
# ---------------------------------------------------------------------------

def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def issue_token(user_id: int, role: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user_id": user_id, "role": role, "iat": int(time.time())}
    header_b64 = _b64url_encode(json.dumps(header).encode())
    payload_b64 = _b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def decode_token(token: str) -> dict | None:
    """Intentionally vulnerable: accepts alg=none with no signature check.
    See ANSWER_KEY.md."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        return None

    alg = header.get("alg", "")
    if alg.lower() == "none":
        # BUG: no signature verification at all for alg=none.
        return payload

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    try:
        actual_sig = _b64url_decode(sig_b64)
    except Exception:
        return None
    if not hmac.compare_digest(expected_sig, actual_sig):
        return None
    return payload


def get_auth_payload():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return decode_token(auth[len("Bearer "):])


# ---------------------------------------------------------------------------
# CORS -- intentionally permissive (see ANSWER_KEY.md)
# ---------------------------------------------------------------------------

@app.after_request
def add_cors_and_banner(resp):
    origin = request.headers.get("Origin")
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["X-Powered-By"] = app.config["FRAMEWORK_BANNER"]
    return resp


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    email = data.get("email", "")
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password, email, address, role) VALUES (?, ?, ?, ?, 'user')",
            (username, password, email, ""),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username taken"}), 409
    row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    token = issue_token(row["id"], "user")
    return jsonify({"token": token})


@app.route("/api/login", methods=["POST"])
def login():
    """BUG: raw string-built SQL query -- real SQL injection, and no
    rate limiting / lockout at all. See ANSWER_KEY.md."""
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    db = get_db()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        row = db.execute(query).fetchone()
    except sqlite3.Error as e:
        # BUG (secondary): raw DB error text returned to the client.
        return jsonify({"error": "database error", "detail": str(e)}), 500
    if row is None:
        return jsonify({"error": "invalid credentials"}), 401
    token = issue_token(row["id"], row["role"])
    return jsonify({"token": token, "role": row["role"]})


@app.route("/api/users/me", methods=["GET"])
def users_me():
    """Correctly implemented for contrast: identity comes from the
    verified token, never from a client-supplied id."""
    payload = get_auth_payload()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    row = db.execute("SELECT id, username, email, role FROM users WHERE id = ?", (payload["user_id"],)).fetchone()
    if not row:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(dict(row))


@app.route("/api/users/<int:user_id>/profile", methods=["GET"])
def user_profile(user_id):
    """BUG: authenticates the request but never checks that the
    authenticated user matches the requested :user_id -- IDOR."""
    payload = get_auth_payload()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    row = db.execute(
        "SELECT id, username, email, address, balance FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------

@app.route("/api/products", methods=["GET"])
def list_products():
    """True negative: no user input, nothing to inject."""
    db = get_db()
    rows = db.execute("SELECT id, name, price, description FROM products").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/products/<int:product_id>", methods=["GET"])
def get_product(product_id):
    """True negative: parameterized query."""
    db = get_db()
    row = db.execute("SELECT id, name, price, description FROM products WHERE id = ?", (product_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/products/search", methods=["GET"])
def search_products():
    """BUG: raw string-built SQL LIKE query -- real SQL injection."""
    q = request.args.get("q", "")
    db = get_db()
    query = f"SELECT id, name, price, description FROM products WHERE name LIKE '%{q}%'"
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.Error as e:
        return jsonify({"error": "database error", "detail": str(e)}), 500
    return jsonify([dict(r) for r in rows])


@app.route("/api/products/<int:product_id>/comments", methods=["GET", "POST"])
def comments(product_id):
    db = get_db()
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        db.execute(
            "INSERT INTO comments (product_id, author, body) VALUES (?, ?, ?)",
            (product_id, data.get("author", "anonymous"), data.get("body", "")),
        )
        db.commit()
        return jsonify({"status": "posted"}), 201
    rows = db.execute("SELECT author, body FROM comments WHERE product_id = ?", (product_id,)).fetchall()
    sort = request.args.get("sort", "id")
    # A "sort" param that pattern-matches common fast-path trigger words
    # but is safely allowlisted server-side -- true negative, not a bug.
    if sort not in ("id", "author"):
        sort = "id"
    return jsonify([dict(r) for r in rows])


@app.route("/api/products/<int:product_id>/comments/view", methods=["GET"])
def comments_view(product_id):
    """BUG: stored XSS -- comment body rendered into HTML unescaped."""
    db = get_db()
    rows = db.execute("SELECT author, body FROM comments WHERE product_id = ?", (product_id,)).fetchall()
    items = "".join(f"<li><b>{r['author']}</b>: {r['body']}</li>" for r in rows)
    return f"<html><body><ul>{items}</ul></body></html>", 200, {"Content-Type": "text/html"}


@app.route("/api/search-page", methods=["GET"])
def search_page():
    """BUG: reflected XSS -- query param echoed into HTML unescaped."""
    q = request.args.get("q", "")
    html = f"<html><body><p>Results for: {q}</p><p>No products found.</p></body></html>"
    return html, 200, {"Content-Type": "text/html"}


# ---------------------------------------------------------------------------
# Orders / checkout
# ---------------------------------------------------------------------------

@app.route("/api/orders", methods=["POST"])
def create_order():
    """BUG: no validation that quantity is positive -- a negative
    quantity produces a negative total, which is then *added* to the
    user's balance (buying costs money; a negative purchase pays you)."""
    payload = get_auth_payload()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    product_id = data.get("product_id")
    quantity = data.get("quantity", 1)
    db = get_db()
    product = db.execute("SELECT price FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        return jsonify({"error": "no such product"}), 404
    total_price = product["price"] * quantity
    db.execute(
        "INSERT INTO orders (user_id, product_id, quantity, total_price) VALUES (?, ?, ?, ?)",
        (payload["user_id"], product_id, quantity, total_price),
    )
    db.execute(
        "UPDATE users SET balance = balance - ? WHERE id = ?",
        (total_price, payload["user_id"]),
    )
    db.commit()
    row = db.execute("SELECT balance FROM users WHERE id = ?", (payload["user_id"],)).fetchone()
    return jsonify({"status": "ordered", "total_price": total_price, "new_balance": row["balance"]})


@app.route("/api/orders/<int:order_id>", methods=["GET"])
def get_order(order_id):
    """BUG: authenticates but never checks the order belongs to the
    caller -- IDOR, sequential integer ids make this trivially
    enumerable."""
    payload = get_auth_payload()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    row = db.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


# ---------------------------------------------------------------------------
# Coupons -- race condition
# ---------------------------------------------------------------------------

@app.route("/api/coupons/redeem", methods=["POST"])
def redeem_coupon():
    """BUG: non-atomic check-then-write (TOCTOU). Concurrent requests
    for the same coupon can both pass the used_count < max_uses check
    before either write lands, letting a single-use coupon be redeemed
    more than once. Requires the dev server to run with threaded=True
    (it does, see bottom of file) to actually race."""
    data = request.get_json(force=True, silent=True) or {}
    code = data.get("code", "")
    db = get_db()
    row = db.execute("SELECT * FROM coupons WHERE code = ?", (code,)).fetchone()
    if not row:
        return jsonify({"error": "invalid coupon"}), 404
    if row["used_count"] >= row["max_uses"]:
        return jsonify({"error": "coupon already used"}), 409
    time.sleep(0.05)  # simulates real processing latency, widens the race window
    db.execute("UPDATE coupons SET used_count = used_count + 1 WHERE code = ?", (code,))
    db.commit()
    return jsonify({"status": "redeemed", "discount_percent": row["discount_percent"]})


# ---------------------------------------------------------------------------
# Avatar -- SSRF
# ---------------------------------------------------------------------------

@app.route("/api/avatar", methods=["POST"])
def fetch_avatar():
    """BUG: fetches any attacker-supplied URL server-side with no
    scheme/host allowlist -- real SSRF. urllib.request supports
    file:// URLs by default, so this also allows local file
    disclosure through the same bug."""
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            content = resp.read(2000)
        return jsonify({
            "status": "fetched",
            "content_preview": content.decode(errors="replace"),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ---------------------------------------------------------------------------
# Invoices -- path traversal
# ---------------------------------------------------------------------------

@app.route("/api/invoices/download", methods=["GET"])
def download_invoice():
    """BUG: naive path join, no traversal sanitization."""
    filename = request.args.get("file", "")
    path = INVOICE_DIR / filename  # BUG: allows ../../ escape
    try:
        content = Path(path).read_text()
    except Exception as e:
        return jsonify({"error": str(e)}), 404
    return content, 200, {"Content-Type": "text/plain"}


# ---------------------------------------------------------------------------
# Admin / misconfig
# ---------------------------------------------------------------------------

@app.route("/api/admin/config", methods=["GET"])
def admin_config():
    """BUG: meant to be admin-only but has no auth check at all --
    exposes the JWT signing secret and internal paths."""
    return jsonify({
        "jwt_secret": JWT_SECRET,
        "db_path": str(DB_PATH),
        "debug": True,
        "framework": app.config["FRAMEWORK_BANNER"],
    })


# ---------------------------------------------------------------------------
# Account -- correctly-implemented CSRF protection, for contrast
# ---------------------------------------------------------------------------

_csrf_tokens: dict[int, str] = {}


@app.route("/api/account/csrf-token", methods=["GET"])
def get_csrf_token():
    payload = get_auth_payload()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401
    token = base64.urlsafe_b64encode(os.urandom(18)).decode()
    _csrf_tokens[payload["user_id"]] = token
    return jsonify({"csrf_token": token})


@app.route("/api/account/change-email", methods=["POST"])
def change_email():
    """True negative: CSRF token correctly required and checked."""
    payload = get_auth_payload()
    if not payload:
        return jsonify({"error": "unauthorized"}), 401
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = _csrf_tokens.get(payload["user_id"])
    if not expected or not hmac.compare_digest(supplied, expected):
        return jsonify({"error": "invalid or missing CSRF token"}), 403
    data = request.get_json(force=True, silent=True) or {}
    db = get_db()
    db.execute("UPDATE users SET email = ? WHERE id = ?", (data.get("email", ""), payload["user_id"]))
    db.commit()
    return jsonify({"status": "updated"})


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    """True negative: nothing sensitive, no user input."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    print(f"PixelMart running at http://127.0.0.1:5001  (db: {DB_PATH})")
    app.run(host="127.0.0.1", port=5001, threaded=True, debug=False)
