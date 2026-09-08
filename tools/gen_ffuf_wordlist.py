#!/usr/bin/env python3
"""
Generate the ffuf content-discovery wordlist from the harness's OWN vocabulary,
so the container tool fuzzes exactly the deterministic candidate set the code
would (nouns, nested collections, id-scoped, action suffixes, sensitive files),
plus a curated common-web set -- and ffuf blasts it concurrently with soft-404
auto-calibration, far faster than the throttled Python sweep.

The output is a FULL-PATH wordlist (no leading slash): ffuf `-u <base>/FUZZ`
substitutes each line, so a line "api/v1/tickets" probes /api/v1/tickets. Kept in
the repo (tools/ffuf-wordlist.txt) and COPYd into the image, so the wordlist is
versioned and auditable with the image.

  python tools/gen_ffuf_wordlist.py   # rewrites tools/ffuf-wordlist.txt
"""
from __future__ import annotations

import sys
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent / "harness"
sys.path.insert(0, str(HARNESS))

from api_surface_discovery import (  # noqa: E402
    DEFAULT_NOUNS, DEFAULT_COLLECTIONS, DEFAULT_ACTIONS, DEFAULT_SENSITIVE_FILES)

# Prefixes as bare segments (no trailing slash) to prepend to nouns.
_PREFIXES = ("", "api", "api/v1", "api/v2", "admin", "internal", "app", "rest")
# One representative id so an object-scoped route is probed too (ffuf can't
# template two keywords cheaply; 1 is the canonical seed the rest of the harness
# already uses).
_ID = "1"
# Curated common-web / framework artifacts a REST-noun sweep never names.
_COMMON = (
    "robots.txt sitemap.xml swagger swagger.json swagger/index.html swagger-ui.html "
    "openapi.json openapi.yaml api-docs v2/api-docs graphql graphiql playground "
    "actuator actuator/health actuator/env actuator/mappings metrics health status "
    "server-status .well-known/security.txt crossdomain.xml "
    ".git/config .git/HEAD .svn/entries .env .env.local .env.production "
    "config.json config.yaml settings.py appsettings.json web.config phpinfo.php "
    "console debug trace status.php test.php info.php adminer.php "
    "wp-login.php wp-admin xmlrpc.php .DS_Store backup.zip backup.sql dump.sql"
).split()


def generate() -> list[str]:
    seen: dict[str, None] = {}

    def add(p: str):
        p = p.strip("/").strip()
        if p:
            seen.setdefault(p, None)

    nouns = DEFAULT_NOUNS
    # nouns bare + id-scoped, across prefixes
    for pre in _PREFIXES:
        for n in nouns:
            base = f"{pre}/{n}" if pre else n
            add(base)
            add(f"{base}/{_ID}")
    # nested two-segment: api[/v1]/<collection>/<noun>
    for pre in ("api", "api/v1"):
        for coll in DEFAULT_COLLECTIONS:
            for n in nouns:
                add(f"{pre}/{coll}/{n}")
    # object-scoped ACTION suffixes: api/<noun>/1/<action>
    for pre in ("api", ""):
        for n in nouns:
            for a in DEFAULT_ACTIONS:
                add(f"{pre}/{n}/{_ID}/{a}" if pre else f"{n}/{_ID}/{a}")
    # sensitive files (already root-relative)
    for f in DEFAULT_SENSITIVE_FILES:
        add(f)
    for c in _COMMON:
        add(c)
    return sorted(seen)


def main():
    words = generate()
    out = Path(__file__).resolve().parent / "ffuf-wordlist.txt"
    out.write_text("\n".join(words) + "\n", encoding="utf-8")
    print(f"wrote {len(words)} paths -> {out}")


if __name__ == "__main__":
    main()
