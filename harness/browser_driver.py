"""
Headless-browser execution surface -- the dependency-guarded engine behind the
browser-driven XSS validator (A2).

Reflected-XSS confirmation from HTTP responses alone is a guess: you see your
payload echoed in the body and *infer* it would run. The only way to know it
actually executes is to load the page in a real browser and watch for the
script firing -- an alert dialog, a console message, a thrown error from your
injected handler. That's what Aikido's Selenium step did, and what this provides.

A real browser is a heavy, optional dependency, so this module is written so the
rest of the harness never hard-depends on it:

  - The engine (Playwright) is imported lazily, inside the methods that use it,
    never at module import. Importing this module is always safe.
  - `available()` reports whether an engine is actually usable, so callers
    (the validator) degrade to "skipped: no browser" instead of crashing when
    nothing is installed.
  - Everything is expressed against the small BrowserDriver protocol below, so
    tests inject a fake driver and the validator's whole decision logic is
    exercised with no browser present.

Navigation is GET-only and the caller is responsible for scope-gating the URL;
this module just drives the browser and reports what executed.
"""
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

log = logging.getLogger("harness.browser_driver")


@dataclass
class ExecutionObservation:
    """What a page did when loaded: the signals that prove script execution."""
    url: str
    dialogs: list[str] = field(default_factory=list)     # alert/confirm/prompt messages
    console: list[str] = field(default_factory=list)     # console.log/info/... text
    page_errors: list[str] = field(default_factory=list)  # uncaught JS errors
    load_error: str = ""                                 # navigation itself failed

    def all_text(self) -> str:
        return "\n".join(self.dialogs + self.console + self.page_errors)


@runtime_checkable
class BrowserDriver(Protocol):
    async def visit(self, url: str, *, wait_ms: int = 1500) -> ExecutionObservation:
        ...


def playwright_available() -> bool:
    try:
        import playwright.async_api  # noqa: F401
        return True
    except Exception:
        return False


def available(cdp_endpoint: str | None = None) -> tuple[bool, str]:
    """(usable, reason). Reason names the missing piece so the operator knows
    exactly what to install. With a `cdp_endpoint` set the browser runs in a
    container and only the Playwright *client* library is needed on the host
    (no local browser binary) -- the host-cleanliness win, mirroring
    sqlmap-in-container."""
    if playwright_available():
        return True, ("playwright (over CDP -> containerised browser)"
                      if cdp_endpoint else "playwright")
    hint = ("`pip install playwright` (a browser container serves the engine over CDP)"
            if cdp_endpoint else "`pip install playwright && playwright install chromium`")
    return False, f"no headless browser engine available -- install one, e.g. {hint}"


def default_driver(cdp_endpoint: str | None = None) -> "BrowserDriver | None":
    """The best available real driver, or None when the Playwright client is not
    installed. Pass `cdp_endpoint` (e.g. ws://127.0.0.1:3000 from a browser
    container) to drive a containerised Chromium instead of launching one on the
    host."""
    if playwright_available():
        return PlaywrightDriver(cdp_endpoint=cdp_endpoint)
    return None


class PlaywrightDriver:
    """Playwright-backed driver. Navigates to the URL and records dialogs /
    console messages / page errors -- the observable evidence that injected
    script ran. Auto-dismisses dialogs so a blocking alert() can't hang the run.
    Everything Playwright is imported lazily.

    Two engine modes:
      - **local launch** (default): starts a headless Chromium on the host.
        Needs `playwright install chromium`.
      - **container over CDP** (`cdp_endpoint` set): connects to a Chromium
        already running in a container (e.g. the `browserless/chrome` image
        exposing CDP on ws://host:3000). Nothing but the Playwright client lib
        lands on the host -- the same host-cleanliness rationale as
        sqlmap-in-container. We own only the context/session we open, never the
        shared remote browser, so cleanup closes the context, not the browser."""

    def __init__(self, *, launch_timeout_ms: int = 10000, cdp_endpoint: str | None = None):
        self.launch_timeout_ms = launch_timeout_ms
        self.cdp_endpoint = cdp_endpoint or None

    async def visit(self, url: str, *, wait_ms: int = 1500) -> ExecutionObservation:
        obs = ExecutionObservation(url=url)
        try:
            from playwright.async_api import async_playwright
        except Exception as e:  # pragma: no cover - guarded by available()
            obs.load_error = f"playwright import failed: {e}"
            return obs
        try:
            async with async_playwright() as p:
                # Connect to a containerised browser over CDP, or launch locally.
                # We only ever close what we opened: for a connected (shared)
                # browser that means the context, never the remote process.
                connected = bool(self.cdp_endpoint)
                if connected:
                    browser = await p.chromium.connect_over_cdp(
                        self.cdp_endpoint, timeout=self.launch_timeout_ms)
                else:
                    browser = await p.chromium.launch(headless=True)
                context = None
                try:
                    context = await browser.new_context()
                    page = await context.new_page()

                    async def _on_dialog(dialog):
                        obs.dialogs.append(f"{dialog.type}:{dialog.message}")
                        try:
                            await dialog.dismiss()
                        except Exception:
                            pass

                    page.on("dialog", lambda d: __import__("asyncio").create_task(_on_dialog(d)))
                    page.on("console", lambda msg: obs.console.append(msg.text))
                    page.on("pageerror", lambda err: obs.page_errors.append(str(err)))

                    await page.goto(url, timeout=self.launch_timeout_ms, wait_until="load")
                    await page.wait_for_timeout(wait_ms)
                finally:
                    if context is not None:
                        try:
                            await context.close()
                        except Exception:
                            pass
                    # A locally-launched browser is ours to terminate; a
                    # connected one is only disconnected (never kill a shared
                    # container browser out from under other sessions).
                    try:
                        await browser.close()
                    except Exception:
                        pass
        except Exception as e:
            obs.load_error = f"{e.__class__.__name__}: {e}"
        return obs
