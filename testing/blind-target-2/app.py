"""
DeskHive - a small internal IT helpdesk / ticketing API.

Single-file Flask app. Rebuilds its SQLite database from scratch on every
startup (seeded with a couple of demo users and tickets).

Run:
    python app.py

Listens on http://127.0.0.1:5002
"""

import hashlib
import os
import secrets
import sqlite3
import time
import urllib.request
import urllib.error

from flask import Flask, request, jsonify, send_file, g
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "helpdesk.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
EXPORT_DIR = os.path.join(BASE_DIR, "exports")

SECRET_KEY = secrets.token_hex(16)

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def rebuild_database():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    os.makedirs(EXPORT_DIR, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            display_name TEXT,
            role TEXT NOT NULL,
            department TEXT
        );

        CREATE TABLE sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL,
            body TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            priority TEXT NOT NULL DEFAULT 'normal',
            department TEXT,
            created_by INTEGER NOT NULL,
            assigned_to INTEGER,
            internal_notes TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE exports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            ticket_id INTEGER NOT NULL,
            filepath TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            rating INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );
        """
    )

    now = str(int(time.time()))

    def add_user(username, password, email, display_name, role, department):
        conn.execute(
            "INSERT INTO users (username, password_hash, email, display_name, role, department) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, generate_password_hash(password), email, display_name, role, department),
        )

    add_user("admin", "AdminPass1!", "admin@deskhive.local", "Site Admin", "admin", "management")
    add_user("agent_bob", "BobPass1!", "bob@deskhive.local", "Bob Agent", "agent", "support")
    add_user("alice", "AlicePass1!", "alice@example.com", "Alice Customer", "customer", None)
    add_user("dan", "DanPass1!", "dan@example.com", "Dan Customer", "customer", None)
    conn.commit()

    conn.execute(
        "INSERT INTO tickets (subject, body, status, priority, department, created_by, assigned_to, "
        "internal_notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "Cannot log in to the customer portal",
            "I keep getting an error when I try to sign in since yesterday.",
            "open",
            "normal",
            "support",
            3,  # alice
            2,  # agent_bob
            "Customer called twice, sounding irate. Consider escalating if no reply in 24h.",
            now,
        ),
    )
    conn.execute(
        "INSERT INTO tickets (subject, body, status, priority, department, created_by, assigned_to, "
        "internal_notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "Billing discrepancy on invoice #492",
            "The invoice total doesn't match what we agreed on the call.",
            "open",
            "high",
            "support",
            4,  # dan
            None,
            "VIP account, CFO is aware of this ticket. Handle carefully, possible churn risk.",
            now,
        ),
    )
    conn.commit()

    conn.execute(
        "INSERT INTO comments (ticket_id, author_id, body, created_at) VALUES (?, ?, ?, ?)",
        (1, 2, "Thanks for reaching out, looking into this now.", now),
    )
    conn.commit()

    with open(os.path.join(UPLOAD_DIR, "ticket1_notes.txt"), "w") as f:
        f.write("Customer reported the issue again at 2pm, screenshot attached separately.\n")

    conn.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def get_current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):].strip()
    if not token:
        return None
    db = get_db()
    row = db.execute(
        "SELECT users.* FROM sessions JOIN users ON sessions.user_id = users.id "
        "WHERE sessions.token = ?",
        (token,),
    ).fetchone()
    return row


def require_login():
    user = get_current_user()
    if user is None:
        return None, (jsonify(error="authentication required"), 401)
    return user, None


def effective_role(user):
    """Resolve the role to use for an authorization check.

    NOTE: kept the X-Debug-Role override so QA could impersonate roles
    while the mobile client was in development. Should not matter in
    production since nothing sets that header normally.
    """
    override = request.headers.get("X-Debug-Role")
    if override:
        return override
    return user["role"]


def ticket_to_dict(row, include_internal=True):
    d = dict(row)
    if not include_internal:
        d.pop("internal_notes", None)
    return d


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    email = data.get("email")
    if not username or not password:
        return jsonify(error="username and password are required"), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        return jsonify(error="username already taken"), 409

    # role is always forced to 'customer' regardless of what the caller sends
    db.execute(
        "INSERT INTO users (username, password_hash, email, display_name, role, department) "
        "VALUES (?, ?, ?, ?, 'customer', NULL)",
        (username, generate_password_hash(password), email, username),
    )
    db.commit()
    return jsonify(message="account created"), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username") or ""
    password = data.get("password") or ""

    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify(error="invalid credentials"), 401

    token = secrets.token_hex(24)
    db.execute(
        "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
        (token, row["id"], str(int(time.time()))),
    )
    db.commit()
    return jsonify(token=token, user_id=row["id"], role=row["role"])


@app.route("/api/logout", methods=["POST"])
def logout():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[len("Bearer "):].strip()
        db = get_db()
        db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        db.commit()
    return jsonify(message="logged out")


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

def reset_code_for(user_id):
    return hashlib.sha256(f"{user_id}-reset-code".encode()).hexdigest()[:6]


@app.route("/api/password-reset/request", methods=["POST"])
def password_reset_request():
    data = request.get_json(silent=True) or {}
    username = data.get("username") or ""
    db = get_db()
    row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if row is not None:
        code = reset_code_for(row["id"])
        db.execute(
            "INSERT INTO password_resets (user_id, code, used) VALUES (?, ?, 0)",
            (row["id"], code),
        )
        db.commit()
    # Always the same response, whether or not the account exists.
    return jsonify(message="If that account exists, a reset code has been sent.")


@app.route("/api/password-reset/confirm", methods=["POST"])
def password_reset_confirm():
    data = request.get_json(silent=True) or {}
    username = data.get("username") or ""
    code = data.get("code") or ""
    new_password = data.get("new_password") or ""

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        return jsonify(error="invalid request"), 400

    pending = db.execute(
        "SELECT * FROM password_resets WHERE user_id = ? AND code = ? AND used = 0",
        (user["id"], code),
    ).fetchone()
    if pending is None:
        return jsonify(error="invalid or expired code"), 400

    if not new_password:
        return jsonify(error="new_password is required"), 400

    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), user["id"]))
    db.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (pending["id"],))
    db.commit()
    return jsonify(message="password updated")


# ---------------------------------------------------------------------------
# Tickets
# ---------------------------------------------------------------------------

SORTABLE_COLUMNS = {
    "created_at": "created_at",
    "priority": "priority",
    "status": "status",
    "subject": "subject",
}


@app.route("/api/tickets", methods=["GET"])
def list_tickets():
    user, err = require_login()
    if err:
        return err

    db = get_db()
    sort_param = request.args.get("sort", "created_at")
    order_param = request.args.get("order", "desc")
    title_contains = request.args.get("title_contains")

    sort_col = SORTABLE_COLUMNS.get(sort_param, "created_at")
    order = "ASC" if order_param.lower() == "asc" else "DESC"

    if user["role"] == "admin":
        base_sql = "SELECT * FROM tickets"
        params = []
        where = []
    elif user["role"] == "agent":
        base_sql = "SELECT * FROM tickets"
        where = ["department = ?"]
        params = [user["department"]]
    else:
        base_sql = "SELECT * FROM tickets"
        where = ["created_by = ?"]
        params = [user["id"]]

    if title_contains:
        where.append("subject LIKE ?")
        params.append(f"%{title_contains}%")

    sql = base_sql
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {sort_col} {order}"

    rows = db.execute(sql, params).fetchall()
    include_internal = user["role"] in ("admin", "agent")
    return jsonify([ticket_to_dict(r, include_internal) for r in rows])


@app.route("/api/tickets", methods=["POST"])
def create_ticket():
    user, err = require_login()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    subject = (data.get("subject") or "").strip()
    body = data.get("body") or ""
    department = data.get("department") or "support"
    if not subject:
        return jsonify(error="subject is required"), 400

    db = get_db()
    db.execute(
        "INSERT INTO tickets (subject, body, status, priority, department, created_by, assigned_to, "
        "internal_notes, created_at) VALUES (?, ?, 'open', 'normal', ?, ?, NULL, '', ?)",
        (subject, body, department, user["id"], str(int(time.time()))),
    )
    db.commit()
    return jsonify(message="ticket created"), 201


@app.route("/api/tickets/search", methods=["GET"])
def search_tickets():
    user, err = require_login()
    if err:
        return err

    q = request.args.get("q", "")
    db = get_db()
    # Quick keyword search across ticket subjects.
    query = "SELECT id, subject, status, priority FROM tickets WHERE subject LIKE '%" + q + "%'"
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.Error as exc:
        return jsonify(error=f"search failed: {exc}"), 400
    return jsonify([dict(r) for r in rows])


@app.route("/api/tickets/<int:ticket_id>", methods=["GET"])
def get_ticket(ticket_id):
    user, err = require_login()
    if err:
        return err

    db = get_db()
    row = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if row is None:
        return jsonify(error="ticket not found"), 404

    # any authenticated user can view any ticket's full detail
    return jsonify(ticket_to_dict(row, include_internal=True))


@app.route("/api/tickets/<int:ticket_id>/comments", methods=["GET"])
def get_comments(ticket_id):
    user, err = require_login()
    if err:
        return err

    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        return jsonify(error="ticket not found"), 404

    allowed = (
        user["role"] == "admin"
        or ticket["created_by"] == user["id"]
        or (user["role"] == "agent" and ticket["department"] == user["department"])
    )
    if not allowed:
        return jsonify(error="not authorized to view this ticket's comments"), 403

    rows = db.execute(
        "SELECT * FROM comments WHERE ticket_id = ? ORDER BY created_at ASC", (ticket_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/tickets/<int:ticket_id>/comments", methods=["POST"])
def add_comment(ticket_id):
    user, err = require_login()
    if err:
        return err

    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        return jsonify(error="ticket not found"), 404

    allowed = (
        user["role"] == "admin"
        or ticket["created_by"] == user["id"]
        or (user["role"] == "agent" and ticket["department"] == user["department"])
    )
    if not allowed:
        return jsonify(error="not authorized to comment on this ticket"), 403

    data = request.get_json(silent=True) or {}
    body = (data.get("body") or "").strip()
    if not body:
        return jsonify(error="body is required"), 400

    # author is always the authenticated user, never taken from the request body
    db.execute(
        "INSERT INTO comments (ticket_id, author_id, body, created_at) VALUES (?, ?, ?, ?)",
        (ticket_id, user["id"], body, str(int(time.time()))),
    )
    db.commit()
    return jsonify(message="comment added"), 201


@app.route("/tickets/<int:ticket_id>/view", methods=["GET"])
def view_ticket_html(ticket_id):
    user, err = require_login()
    if err:
        return err
    if user["role"] not in ("admin", "agent"):
        return jsonify(error="staff only"), 403

    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        return jsonify(error="ticket not found"), 404

    comments = db.execute(
        "SELECT * FROM comments WHERE ticket_id = ? ORDER BY created_at ASC", (ticket_id,)
    ).fetchall()

    comment_html = ""
    for c in comments:
        comment_html += f"<div class='comment'><p>{c['body']}</p></div>\n"

    page = f"""
    <html>
    <head><title>Ticket #{ticket['id']} - {ticket['subject']}</title></head>
    <body>
      <h1>{ticket['subject']}</h1>
      <p>{ticket['body']}</p>
      <h2>Comments</h2>
      {comment_html}
    </body>
    </html>
    """
    return page


@app.route("/search-page", methods=["GET"])
def search_page():
    q = request.args.get("q", "")
    db = get_db()
    rows = db.execute(
        "SELECT id, subject FROM tickets WHERE status = 'open' ORDER BY created_at DESC"
    ).fetchall()
    listing = "".join(f"<li>{r['subject']}</li>" for r in rows)
    page = f"""
    <html>
    <head><title>DeskHive Help Search</title></head>
    <body>
      <h1>Help Search</h1>
      <div>You searched for: {q}</div>
      <ul>{listing}</ul>
    </body>
    </html>
    """
    return page


@app.route("/api/tickets/<int:ticket_id>/import-link", methods=["POST"])
def import_link(ticket_id):
    user, err = require_login()
    if err:
        return err

    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        return jsonify(error="ticket not found"), 404
    if ticket["created_by"] != user["id"] and user["role"] != "admin":
        return jsonify(error="not authorized"), 403

    data = request.get_json(silent=True) or {}
    url = data.get("url") or ""
    if not url:
        return jsonify(error="url is required"), 400

    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            content = resp.read(2000)
        preview = content.decode("utf-8", errors="replace")
    except (urllib.error.URLError, ValueError) as exc:
        return jsonify(error=f"could not fetch url: {exc}"), 400

    return jsonify(preview=preview)


@app.route("/api/tickets/<int:ticket_id>/rate", methods=["POST"])
def rate_ticket(ticket_id):
    user, err = require_login()
    if err:
        return err

    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        return jsonify(error="ticket not found"), 404
    if ticket["created_by"] != user["id"]:
        return jsonify(error="only the ticket creator can rate it"), 403

    data = request.get_json(silent=True) or {}
    rating = data.get("rating")
    if rating is None:
        return jsonify(error="rating is required"), 400

    db.execute(
        "INSERT INTO ratings (ticket_id, rating, created_at) VALUES (?, ?, ?)",
        (ticket_id, rating, str(int(time.time()))),
    )
    db.commit()

    all_ratings = [r["rating"] for r in db.execute(
        "SELECT rating FROM ratings WHERE ticket_id = ?", (ticket_id,)
    ).fetchall()]
    avg = sum(all_ratings) / len(all_ratings)
    return jsonify(message="thanks for your feedback", average_rating=avg, count=len(all_ratings))


# ---------------------------------------------------------------------------
# Attachments / exports
# ---------------------------------------------------------------------------

@app.route("/api/attachments/download", methods=["GET"])
def download_attachment():
    user, err = require_login()
    if err:
        return err

    filename = request.args.get("file", "")
    if not filename:
        return jsonify(error="file is required"), 400

    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.isfile(path):
        return jsonify(error="not found"), 404
    return send_file(os.path.abspath(path))


@app.route("/api/tickets/<int:ticket_id>/export", methods=["POST"])
def export_ticket(ticket_id):
    user, err = require_login()
    if err:
        return err

    db = get_db()
    ticket = db.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        return jsonify(error="ticket not found"), 404
    if ticket["created_by"] != user["id"] and user["role"] != "admin":
        return jsonify(error="not authorized"), 403

    token = secrets.token_hex(16)
    export_filename = f"{token}.csv"
    export_path = os.path.join(EXPORT_DIR, export_filename)
    with open(export_path, "w") as f:
        f.write("id,subject,status,priority\n")
        f.write(f"{ticket['id']},{ticket['subject']},{ticket['status']},{ticket['priority']}\n")

    db.execute(
        "INSERT INTO exports (token, ticket_id, filepath, created_at) VALUES (?, ?, ?, ?)",
        (token, ticket_id, export_path, str(int(time.time()))),
    )
    db.commit()
    return jsonify(export_token=token)


@app.route("/api/exports/<token>", methods=["GET"])
def download_export(token):
    user, err = require_login()
    if err:
        return err

    db = get_db()
    row = db.execute("SELECT * FROM exports WHERE token = ?", (token,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    # filepath comes from our own database record, never from user input
    return send_file(os.path.abspath(row["filepath"]))


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@app.route("/api/users/me", methods=["GET"])
def get_me():
    user, err = require_login()
    if err:
        return err
    d = dict(user)
    d.pop("password_hash", None)
    return jsonify(d)


@app.route("/api/users/me", methods=["PATCH"])
def update_me():
    user, err = require_login()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    db = get_db()
    # explicit whitelist: only these two fields can ever be changed here
    display_name = data.get("display_name")
    email = data.get("email")
    if display_name is not None:
        db.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user["id"]))
    if email is not None:
        db.execute("UPDATE users SET email = ? WHERE id = ?", (email, user["id"]))
    db.commit()

    row = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    d = dict(row)
    d.pop("password_hash", None)
    return jsonify(d)


@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    user, err = require_login()
    if err:
        return err
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    d = dict(row)
    d.pop("password_hash", None)
    return jsonify(d)


@app.route("/api/users/<int:user_id>", methods=["PATCH"])
def update_user(user_id):
    user, err = require_login()
    if err:
        return err

    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        return jsonify(error="not found"), 404

    data = request.get_json(silent=True) or {}
    fields = {}
    for key in ("username", "email", "role", "department", "display_name"):
        if key in data:
            fields[key] = data[key]

    if fields:
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [user_id]
        db.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
        db.commit()

    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    d = dict(row)
    d.pop("password_hash", None)
    return jsonify(d)


# ---------------------------------------------------------------------------
# Admin / misc
# ---------------------------------------------------------------------------

@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    user, err = require_login()
    if err:
        return err

    db = get_db()
    total_tickets = db.execute("SELECT COUNT(*) AS c FROM tickets").fetchone()["c"]
    users = db.execute("SELECT id, username, role, department, email FROM users").fetchall()
    return jsonify(
        total_tickets=total_tickets,
        total_users=len(users),
        users=[dict(u) for u in users],
    )


@app.route("/api/admin/tickets/<int:ticket_id>", methods=["DELETE"])
def admin_delete_ticket(ticket_id):
    user, err = require_login()
    if err:
        return err

    role = effective_role(user)
    if role != "admin":
        return jsonify(error="admin only"), 403

    db = get_db()
    db.execute("DELETE FROM comments WHERE ticket_id = ?", (ticket_id,))
    db.execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
    db.commit()
    return jsonify(message="ticket deleted")


@app.route("/api/system/health", methods=["GET"])
def system_health():
    return jsonify(
        status="ok",
        secret_key_prefix=SECRET_KEY[:8],
        db_path=DB_PATH,
        upload_dir=UPLOAD_DIR,
    )


if __name__ == "__main__":
    rebuild_database()
    app.run(host="127.0.0.1", port=5002, debug=False)
