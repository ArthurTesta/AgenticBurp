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

from flask import Flask, request, redirect, Response
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

    return app


if __name__ == "__main__":
    make_app().run(host="127.0.0.1", port=5099)
