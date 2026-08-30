from __future__ import annotations
import asyncio
import os
import tempfile
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from models import Finding, HttpExchange, TestPlan
from planner import exchange_fingerprint
from categories import canonicalize
from .base import Validator, ValidationResult
from safety_gate import get_default_gate


class SqlmapValidator(Validator):
    """Optional active SQLi validator.

    sqlmap is deliberately treated as a validator, not as an autonomous
    scanner. The LLM identifies a hypothesis; this adapter supplies the
    captured request and a tightly bounded, analyst-enabled invocation.
    No model-generated command line or URL is ever executed.
    """
    name = "sqlmap"
    finding_classes = {"sqli", "sql injection"}
    active = True

    def __init__(self, binary: str = "sqlmap", timeout_seconds: int = 90,
                 level: int = 1, risk: int = 1):
        self.binary = binary
        self.timeout_seconds = timeout_seconds
        self.level = max(1, min(level, 2))
        self.risk = max(1, min(risk, 2))

    @staticmethod
    def _raw_request(exchange: HttpExchange) -> str:
        parts = urlsplit(exchange.url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"{exchange.method.upper()} {path} HTTP/1.1"]
        host = parts.netloc
        saw_host = False
        for k, v in exchange.request_headers.items():
            if k.lower() == "host":
                saw_host = True
            lines.append(f"{k}: {v}")
        if not saw_host and host:
            lines.append(f"Host: {host}")
        lines.append("")
        lines.append(exchange.request_body or "")
        return "\r\n".join(lines)

    def plan(self, finding: Finding, exchange: HttpExchange) -> TestPlan | None:
        if not self.applies(finding, exchange):
            return None
        return TestPlan(
            id=f"sqlmap:{finding.vulnerability_class}:{exchange_fingerprint(exchange)[:20]}",
            capability="sql_injection_validation",
            finding_class=finding.vulnerability_class,
            category=canonicalize(finding.vulnerability_class) or "sqli",
            source_exchange_url=exchange.url,
            mutation={"strategy": "validate-captured-request", "target": "captured-request"},
            success_signals=["tool reports an injectable parameter", "tool identifies exploitable SQL injection"],
            requires_approval=True, execution_plane="local_tool",
            rationale="Use the original captured request; never use a model-generated URL or command.",
            source_exchange_hash=exchange_fingerprint(exchange),
        )

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        if not self.applies(finding, exchange):
            return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                    summary="validator does not apply")
        if not exchange.url.startswith(("http://", "https://")):
            return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                    summary="unsupported URL scheme")

        if exchange.method.upper() != "GET":
            # sqlmap fuzzes a parameter by sending many requests with
            # different payloads to the SAME endpoint via the SAME
            # method. If that endpoint is a real mutating action (a
            # checkout, a transfer, a coupon redemption), sqlmap will
            # fire that real action repeatedly while fuzzing -- no
            # destructive SQL payload (DROP TABLE etc.) is required for
            # this to cause real harm, just the sheer repetition against
            # a live mutating endpoint. GET is exempted because it's
            # the one method HTTP semantics itself says shouldn't have
            # side effects; anything else requires the same explicit,
            # separate opt-in the rest of this harness's mutating-replay
            # techniques require.
            gate_decision = get_default_gate().authorize(
                validator_name=self.name, method=exchange.method, url=exchange.url,
                body=exchange.request_body,
            )
            if not gate_decision.allowed:
                return ValidationResult(
                    self.name, "blocked", finding.vulnerability_class,
                    summary=f"Blocked by safety gate: {gate_decision.reason} "
                            f"(sqlmap would fuzz a {exchange.method.upper()} endpoint, sending many "
                            f"requests to what may be a real mutating action)",
                )

        with tempfile.TemporaryDirectory(prefix="harness-sqlmap-") as td:
            # Keep the raw request text around as an audit artifact (it's
            # what the original design intended an analyst to be able to
            # inspect), but invoke sqlmap with explicit -u/-H/--data flags
            # rather than `-r <file>`. Verified directly against a live
            # target (OWASP Juice Shop): `-r <file>` with this exact
            # request content silently matched zero targets and exited
            # instantly with no injection attempts and no error -- with
            # the request's content byte-for-byte identical fed via -u/
            # --data/-H instead, sqlmap correctly parsed it, tested it,
            # and found a real, confirmed injection. The `-r` failure
            # mode is unexplained (isolated it to request-file parsing
            # specifically, not to --ignore-code, --smart, or Content-
            # Length) and is a known-broken path in the sqlmap version
            # available here (1.8.4) rather than something worth working
            # around blindly -- -u/-H/--data is the standard, most-tested
            # sqlmap invocation shape, so prefer it outright.
            request_file = Path(td) / "request.txt"
            request_file.write_text(self._raw_request(exchange), encoding="utf-8")

            cmd = [self.binary, "-u", exchange.url, "--batch",
                   "--level", str(self.level), "--risk", str(self.risk),
                   "--threads", "1", "--timeout", "10", "--retries", "1",
                   "--flush-session", "--disable-coloring"]
            # Deliberately no --smart: verified directly against a live
            # target (OWASP Juice Shop's login endpoint, a genuinely
            # injectable, well-known case) that --smart's cheap "is this
            # parameter dynamic" heuristic incorrectly judges a real JSON
            # boolean-blind injection point as not worth testing, and
            # skips it -- a false negative on exactly the kind of finding
            # this validator exists to confirm. --smart trades completeness
            # for fewer requests; for a single bounded, analyst-approved
            # confirmatory run (not a broad unattended crawl), a missed
            # real vulnerability is a worse failure than a few extra
            # seconds of testing.
            if exchange.request_body:
                cmd += ["--data", exchange.request_body]
            if exchange.method.upper() not in ("GET", "POST"):
                cmd += ["--method", exchange.method.upper()]
            for k, v in exchange.request_headers.items():
                if k.lower() in ("host", "content-length"):
                    continue  # sqlmap derives these itself from -u/--data
                cmd += ["-H", f"{k}: {v}"]
            if exchange.response_status is not None and not (200 <= exchange.response_status < 300):
                # Verified against a live target (OWASP Juice Shop's login
                # endpoint, which returns 401 for invalid credentials --
                # the normal, expected baseline response): without this,
                # sqlmap's default behavior is to treat ANY non-2xx
                # response as "not authorized to test this target" and
                # skip it entirely, producing zero injection attempts and
                # no error -- indistinguishable from "tested, not
                # injectable" unless you read the raw output closely. Any
                # endpoint whose normal/expected response is non-2xx
                # (failed auth attempts, permission-gated endpoints, etc.)
                # would silently never be tested. Ignoring the exchange's
                # OWN baseline status code (rather than hardcoding 401) is
                # the general form of this fix: it tells sqlmap "this is
                # this endpoint's normal response," not "ignore all
                # errors everywhere."
                cmd += ["--ignore-code", str(exchange.response_status)]

            # Defense in depth, independent of the level/risk clamping in
            # __init__: assert none of sqlmap's destructive/exfiltration
            # flags are present in the final command, regardless of how
            # cmd got built. This exists so a future edit to this method
            # that adds a flag without realizing its implications fails
            # loudly here rather than silently shipping a validator that
            # can dump a database or open a shell on the target. See
            # test_safety_gate.py's test_sqlmap_command_never_contains_
            # destructive_flags for the corresponding test.
            _DENIED_SQLMAP_FLAGS = (
                "--dump", "--dump-all", "--os-shell", "--os-pwn", "--os-cmd",
                "--sql-shell", "--file-write", "--file-dest", "--file-read",
                "--reg-read", "--reg-add", "--reg-del", "--privesc",
            )
            for denied in _DENIED_SQLMAP_FLAGS:
                assert denied not in cmd, (
                    f"Refusing to run sqlmap: denied flag {denied!r} present in constructed "
                    f"command. This is a hard-coded safety invariant, not a config option."
                )
            assert self.risk <= 2, f"Refusing to run sqlmap: risk={self.risk} exceeds the hard ceiling of 2."
            assert self.level <= 2, f"Refusing to run sqlmap: level={self.level} exceeds the hard ceiling of 2."

            try:
                proc = await asyncio.to_thread(
                    subprocess.run,
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    env=os.environ.copy(),
                    # sqlmap can block waiting on stdin in some execution
                    # contexts even with --batch (verified by reproducing
                    # it directly: without this, the process hung silently
                    # until the timeout killed it, which then reported
                    # "sqlmap timed out" -- indistinguishable from a slow
                    # scan actually running). --batch suppresses prompts,
                    # not stdin reads; this closes the fd explicitly.
                    stdin=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                return ValidationResult(self.name, "error", finding.vulnerability_class,
                                        summary="sqlmap executable not found; install sqlmap to enable active SQLi validation",
                                        command=cmd)
            except subprocess.TimeoutExpired as exc:
                # Found live, against a real target: subprocess.run's
                # TimeoutExpired can carry .stdout/.stderr as bytes even
                # though the call passed text=True -- confirmed by
                # triggering a genuine sqlmap timeout (a slower, more
                # thorough level=2 scan against a real target legitimately
                # exceeded the configured timeout), which this exception
                # handler had never been exercised against before: every
                # prior real run either completed within the timeout or
                # hit a different exception path. The str+bytes
                # concatenation below crashed outright, turning a normal
                # "sqlmap took too long" outcome into an unhandled
                # TypeError instead of the intended graceful ValidationResult.
                # _decode() below normalizes either type to str so this
                # can't happen regardless of which form subprocess hands
                # back for a given Python/OS combination.
                def _decode(x) -> str:
                    if x is None:
                        return ""
                    if isinstance(x, bytes):
                        return x.decode("utf-8", errors="replace")
                    return x
                partial = (_decode(exc.stdout) + "\n" + _decode(exc.stderr))[-4000:]
                return ValidationResult(self.name, "error", finding.vulnerability_class,
                                        summary=f"sqlmap timed out after {self.timeout_seconds}s",
                                        evidence=partial, raw_output=partial, command=cmd)
            except Exception as exc:
                return ValidationResult(self.name, "error", finding.vulnerability_class,
                                        summary=f"sqlmap execution failed: {exc}", command=cmd)

            output = ((proc.stdout or "") + "\n" + (proc.stderr or ""))[-12000:]
            lower = output.lower()
            confirmed = proc.returncode == 0 and "is vulnerable" in lower
            if confirmed:
                return ValidationResult(
                    self.name, "confirmed", finding.vulnerability_class,
                    confidence=0.98, confirmed=True,
                    summary="sqlmap independently reported the target as injectable",
                    evidence=output, raw_output=output, command=cmd,
                )
            return ValidationResult(
                self.name, "not_confirmed", finding.vulnerability_class,
                confidence=0.2 if proc.returncode == 0 else 0.0,
                confirmed=False,
                summary="sqlmap did not establish SQL injection for the captured request",
                evidence=output, raw_output=output, command=cmd,
            )
