# Safety proxy setup: CA trust, per-client configuration, and what's actually verified

This covers getting `harness/safety_proxy_addon.py` running and pointed
at by every client that needs to go through it: Python's httpx clients,
sqlmap's subprocess, and Burp's JVM. Read `safety_proxy_addon.py`'s own
module docstring first if you haven't -- it explains the fail-closed
design decisions this setup guide assumes.

**Honesty label for this whole document, per this project's own
vocabulary:** everything below is either (a) confirmed by reading the
actual source of the library/tool in question in this session -- marked
**source-verified** -- or (b) standard, well-documented behavior for a
piece of software this sandbox cannot run (a real Burp instance, a real
browser) -- marked **documented, not verified here**. Nothing below is
guessed from memory without one of those two labels.

---

## 1. Install and run the proxy

```bash
cd harness
pip install -r requirements-proxy.txt --break-system-packages
mitmdump -s safety_proxy_addon.py --listen-port 8888
```

First run generates a CA certificate at `~/.mitmproxy/mitmproxy-ca-cert.pem`
(and a few sibling files in other formats) if one doesn't already exist.
**Documented, not verified here** -- this is mitmproxy's own standard
first-run behavior; this sandbox has no way to start a long-running proxy
process and connect a real client to it, so the actual file getting
written was not observed in this session.

If `running()` logs `refusing to start` and raises `ProxyConfigurationError`,
mitmproxy has been given `--set ignore_hosts=...`, `allow_hosts=...`,
`tcp_hosts=...`, or `udp_hosts=...` somewhere in its config/CLI flags.
Remove it. The addon treats this as fatal on purpose -- see its docstring.

---

## 2. Trust the CA -- Python (httpx)

**Source-verified this session** (read `httpx/_config.py` directly,
installed version 0.28.1, and confirmed no `httpx.AsyncClient(...)`
construction anywhere in this codebase overrides `verify` or `trust_env`
-- both stay at their defaults everywhere):

```python
# httpx._config.create_ssl_context(), the actual code path:
if verify is True:
    if trust_env and os.environ.get("SSL_CERT_FILE"):
        ctx = ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
    ...
```

This means, concretely, for this codebase specifically (not httpx in
general -- other projects may set `verify=False` somewhere and this
wouldn't apply to those clients):

```bash
export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem
export HTTPS_PROXY=http://127.0.0.1:8888
export HTTP_PROXY=http://127.0.0.1:8888
```

`HTTPS_PROXY`/`HTTP_PROXY` are picked up for the same reason
(`trust_env=True` is httpx's default and is never overridden in this
codebase -- also source-verified this session, in `httpx/_client.py`).
Set both env vars before starting `server.py` (or whatever process runs
`orchestrator.py`) so every httpx client the harness constructs inherits
them -- there is no per-client config needed in this codebase for this
to work, precisely because nothing here already overrides the defaults.

**If you ever add an httpx client anywhere in this codebase that passes
`verify=...` or `trust_env=False` explicitly, this stops applying to
that client specifically** -- grep for `httpx.AsyncClient(` /
`httpx.Client(` before assuming the env vars cover a new call site.

---

## 3. Trust the CA -- sqlmap

**Source-verified this session** (cloned sqlmap's own repository and
read `lib/request/httpshandler.py` and `lib/request/connect.py`
directly, rather than assuming):

- sqlmap's own `HTTPSConnection.connect()` **unconditionally disables
  certificate and hostname validation** for every HTTPS connection it
  makes (`ctx.check_hostname = False`, `ctx.verify_mode = ssl.CERT_NONE`)
  -- this is sqlmap's own default behavior, not something this project
  configures. Concretely: **sqlmap needs no CA trust configuration at
  all** to work through this proxy, because it never validates any
  upstream certificate in the first place, MITM or not.
- `--proxy` is wired through a standard `urllib.request.ProxyHandler`,
  fully compatible with pointing it at a local mitmproxy instance:

```bash
sqlmap -u "https://target.test/vulnerable?id=1" --proxy=http://127.0.0.1:8888
```

`validators/sqlmap.py` builds its own sqlmap command line -- confirm
(or add, if not already present) `--proxy=http://127.0.0.1:8888` in that
command construction if you want sqlmap's traffic specifically routed
through the safety proxy rather than direct. This is a real, disclosed
gap: **as of this session, `validators/sqlmap.py`'s command construction
was not modified to add this flag** -- wiring it in is a small, separate
follow-up, not done as part of this proxy's initial build.

---

## 4. Trust the CA -- Burp's JVM

**Documented, not verified here** -- this sandbox has no real Burp
instance or JVM keystore to test against; the steps below are the
standard, well-known procedure for adding a CA to a JVM truststore, not
something confirmed working against Burp specifically in this session.

1. In Burp: **Settings → Network → Connections → Upstream Proxy Servers**
   → add a rule routing outbound traffic to `127.0.0.1:8888` (the safety
   proxy). Burp supports upstream proxy chaining natively -- no code
   change to `ValidationExecutor.java` is needed for this step itself.
2. The JVM Burp runs in needs to trust the safety proxy's CA for its
   *own* outbound TLS connections to succeed once traffic is chained
   through an intercepting upstream proxy (as opposed to a simple
   tunneling proxy, which wouldn't need this because it never presents
   its own certificate). Import the CA into that JVM's trust store:

```bash
# Convert mitmproxy's PEM CA to a DER cert if needed, then:
keytool -importcert -trustcacerts \
  -alias agenticburp-safety-proxy \
  -file ~/.mitmproxy/mitmproxy-ca-cert.pem \
  -keystore "$JAVA_HOME/lib/security/cacerts" \
  -storepass changeit
```

   Which JVM this needs to target depends on how Burp itself is launched
   (its own bundled JRE vs. a system JVM) -- **this detail specifically
   was not verified in this session** and needs confirming against
   whatever Burp installation this is actually run against.
3. Restart Burp after the keystore change.

**This is the least-verified leg of the whole setup.** If step 2 is
wrong for a given Burp installation (wrong JVM, wrong keystore), Burp's
own outbound requests will fail TLS handshakes against the safety
proxy -- which, per `safety_proxy_addon.py`'s fail-closed design, means
those requests simply don't happen (safe by construction) rather than
silently bypassing the proxy. The failure mode here is "Burp traffic
stops working," loudly, not "Burp traffic quietly skips the gate."

---

## 5. What "done" looks like -- the live-target verification this still needs

Everything above is either source-verified against the real library
code or standard documented procedure -- **none of it has been run
end-to-end against a real target**. Before trusting this in a real
engagement:

1. Start the proxy, point a plain `curl` (with `--cacert
   ~/.mitmproxy/mitmproxy-ca-cert.pem --proxy http://127.0.0.1:8888`) at
   a real HTTPS test target, and confirm the request actually completes
   and the proxy's log shows it being evaluated.
2. Confirm a GET passes through unmodified end to end.
3. Confirm a POST is blocked with `validators.active_enabled=false`
   (the config default) -- check for the 403 response body this addon
   returns.
4. Turn `active_enabled` and `allow_mutating_replay` on in `config.yaml`,
   confirm the same POST now succeeds and reaches the real target.
5. Send more mutating requests than `HARD_MAX_COMBINED_MUTATING_PER_WINDOW`
   to the same host within the window and confirm the proxy starts
   blocking them itself, independent of whether `safety_gate.py`'s
   in-process ceiling would have allowed it.
6. Point Burp at the proxy per §4, and confirm Burp's own traffic
   (not just Python's) is visible in the proxy's log.
7. Point sqlmap at it per §3, and confirm sqlmap's traffic is visible
   too.

Steps 6 and 7 in particular are the ones this sandbox structurally
cannot do (no real Burp, no real sqlmap binary, no real network target)
-- they're the actual remaining verification gap, not a formality.
