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
                partial = ((exc.stdout or "") + "\n" + (exc.stderr or ""))[-4000:] if (exc.stdout or exc.stderr) else ""
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
