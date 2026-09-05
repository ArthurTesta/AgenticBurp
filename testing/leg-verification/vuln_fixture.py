"""
Disposable leg-verification fixture -- Phase 2.

A deliberately-vulnerable local Flask app used ONLY to LIVE-verify the harness's
confirmation legs against real true-positives (and matched negative controls),
so a leg is proven to actually bite on a real target rather than only pass a
stubbed smoke test. It is never deployed and binds to localhost only.

Each vuln class has a PAIR of endpoints differing in exactly one property:
  - a TRUE-POSITIVE endpoint that has the bug, and
  - a CONTROL endpoint that is structurally similar but safe,
so a leg must confirm the first and stay silent on the second.

Covered: SSTI (Jinja render vs escaped echo), open redirect (blind vs fixed),
path traversal (raw join vs basename), reflected XSS (raw vs escaped -- for the
browser_xss leg the operator runner drives). Build/run via run_leg_verification.py
or the hermetic test_leg_live_verification.
"""
from __future__ import annotations

import html
import os
import subprocess
import urllib.request

from flask import Flask, request, redirect, Response, jsonify
from jinja2 import Template


def make_app(file_base: str | None = None) -> Flask:
    app = Flask(__name__)
    base = file_base or os.path.dirname(os.path.abspath(__file__))

    @app.get("/health")
    def health():
        return {"status": "ok"}

    # --- SSTI: TP renders the param as a template; control escapes it ---------
    @app.get("/ssti/render")
    def ssti_render():
        q = request.args.get("q", "")
        return Response(Template(q).render(), mimetype="text/html")  # VULNERABLE

    @app.get("/ssti/echo")
    def ssti_echo():
        q = request.args.get("q", "")
        return Response(f"you said: {html.escape(q)}", mimetype="text/html")  # safe

    # --- Open redirect: TP redirects to the param; control ignores it ---------
    @app.get("/redirect/open")
    def redirect_open():
        return redirect(request.args.get("url", "/"), code=302)  # VULNERABLE

    @app.get("/redirect/safe")
    def redirect_safe():
        return redirect("/home", code=302)  # ignores the param -- fixed target

    # --- Path traversal: TP joins the raw param; control takes the basename ---
    @app.get("/files/read")
    def files_read():
        name = request.args.get("file", "")
        try:
            with open(os.path.join(base, name), "r", errors="ignore") as f:  # VULNERABLE
                return Response(f.read(), mimetype="text/plain")
        except OSError:
            return Response("not found", status=404, mimetype="text/plain")

    @app.get("/files/safe")
    def files_safe():
        name = os.path.basename(request.args.get("file", ""))  # strips traversal
        try:
            with open(os.path.join(base, name), "r", errors="ignore") as f:
                return Response(f.read(), mimetype="text/plain")
        except OSError:
            return Response("not found", status=404, mimetype="text/plain")

    # --- Reflected XSS: TP reflects raw; control escapes (for browser_xss) ----
    @app.get("/xss/reflect")
    def xss_reflect():
        q = request.args.get("q", "")
        return Response(f"<html><body>hello {q}</body></html>", mimetype="text/html")  # VULNERABLE

    @app.get("/xss/safe")
    def xss_safe():
        q = request.args.get("q", "")
        return Response(f"<html><body>hello {html.escape(q)}</body></html>", mimetype="text/html")

    # --- SSRF: TP fetches the url param server-side; control never fetches -----
    @app.get("/ssrf/fetch")
    def ssrf_fetch():
        url = request.args.get("url", "")
        try:
            with urllib.request.urlopen(url, timeout=2) as r:  # VULNERABLE: fetches attacker URL
                r.read(64)
            return Response("fetched", mimetype="text/plain")
        except Exception:
            return Response("fetch failed", mimetype="text/plain")

    @app.get("/ssrf/safe")
    def ssrf_safe():
        return Response(f"url noted: {html.escape(request.args.get('url', ''))}",  # never fetched
                        mimetype="text/plain")

    # --- Command injection: TP passes the param to a shell; control does not ---
    @app.get("/cmdi/ping")
    def cmdi_ping():
        host = request.args.get("host", "")
        try:
            out = subprocess.run(f"echo {host}", shell=True, capture_output=True,  # VULNERABLE
                                 timeout=5, text=True)
            return Response(out.stdout, mimetype="text/plain")
        except Exception:
            return Response("cmd failed", mimetype="text/plain")

    @app.get("/cmdi/safe")
    def cmdi_safe():
        return Response(f"host noted: {html.escape(request.args.get('host', ''))}",  # no shell
                        mimetype="text/plain")

    # --- Mass assignment (sequence leg): TP binds ALL body fields to the object,
    #     readable back via GET; control binds only an allowlist. state resets. --
    def _fresh():
        return {"id": 1, "name": "alice", "role": "user"}

    # nested-response + non-canonical authority field: the write binds all body
    # fields, but the response NESTS the object under wrapper keys and the
    # escalation field (`is_premium`) is NOT in the canonical priv-field list. The
    # original leg (top-level lookup, fixed field set) misses both; the generalised
    # leg (recursive detection + authority-named schema-derived candidates) catches it.
    def _fresh_tier():
        return {"id": 1, "name": "bob", "is_premium": False, "plan": "free"}
    state = {"profile": _fresh(), "profile_safe": _fresh(),
             "tier": _fresh_tier(), "tier_safe": _fresh_tier()}

    @app.post("/account/reset")
    def account_reset():
        state["profile"], state["profile_safe"] = _fresh(), _fresh()
        state["tier"], state["tier_safe"] = _fresh_tier(), _fresh_tier()
        return jsonify(state["profile"])

    @app.route("/account/tier", methods=["GET", "PATCH", "POST", "PUT"])
    def account_tier():
        if request.method != "GET":
            body = request.get_json(silent=True) or {}
            if isinstance(body, dict):
                state["tier"].update(body)  # VULNERABLE: binds every body field
        return jsonify({"ok": True, "user": {"account": dict(state["tier"])}})  # NESTED

    @app.route("/account/tier-safe", methods=["GET", "PATCH", "POST", "PUT"])
    def account_tier_safe():
        if request.method != "GET":
            body = request.get_json(silent=True) or {}
            if isinstance(body, dict):
                for k in ("name",):  # allowlist -- is_premium/plan ignored
                    if k in body:
                        state["tier_safe"][k] = body[k]
        return jsonify({"ok": True, "user": {"account": dict(state["tier_safe"])}})

    @app.route("/account/profile", methods=["GET", "PATCH", "POST", "PUT"])
    def account_profile():
        if request.method != "GET":
            body = request.get_json(silent=True) or {}
            if isinstance(body, dict):
                state["profile"].update(body)  # VULNERABLE: no settable-field allowlist
        return jsonify(state["profile"])

    @app.route("/account/profile-safe", methods=["GET", "PATCH", "POST", "PUT"])
    def account_profile_safe():
        if request.method != "GET":
            body = request.get_json(silent=True) or {}
            if isinstance(body, dict):
                for k in ("name", "bio"):  # allowlist -- privileged fields ignored
                    if k in body:
                        state["profile_safe"][k] = body[k]
        return jsonify(state["profile_safe"])

    return app


if __name__ == "__main__":
    make_app().run(host="127.0.0.1", port=5099)
