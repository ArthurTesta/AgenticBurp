"""
Real, non-substituted run of the harness's orchestrator against a live
OWASP Juice Shop instance's captured exchanges (see
capture_juiceshop_exchanges.py), with active validators turned ON for
this run specifically -- an in-memory config override, NOT a change to
the real config.yaml -- so that whichever of the 13 active validators
(sqlmap, cors, header_injection, race_condition, api_security, etc.)
actually apply to a finding get a real chance to confirm it, not just
produce an LLM hypothesis. Juice Shop is a deliberately vulnerable
practice target built for exactly this kind of active testing.
"""
import asyncio
import json
import sys
import time
import yaml
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS_DIR = PROJECT_ROOT / "harness"
TEST_TARGET_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(HARNESS_DIR))
sys.path.insert(0, str(TEST_TARGET_DIR))

import store
store._DB_PATH = "/tmp/juiceshop_real_state.db"
import cache
cache.init_cache(db_path="/tmp/juiceshop_real_cache.db")

import orchestrator as orch_mod
from models import HttpExchange

with open(HARNESS_DIR / "config.yaml") as f:
    config = yaml.safe_load(f)

# In-memory only -- turns on real active validation for THIS run.
config.setdefault("validators", {})["active_enabled"] = True
config["validators"]["allow_mutating_replay"] = True
config["validators"]["max_burst_size"] = 5

orch = orch_mod.Orchestrator(config)


async def main():
    with open("/tmp/juiceshop_exchanges.json") as f:
        exchanges_raw = json.load(f)

    results = []
    for idx, e in enumerate(exchanges_raw):
        exchange = HttpExchange(
            url=e["url"], method=e["method"], request_headers=e["request_headers"],
            request_body=e["request_body"], response_status=e["response_status"],
            response_headers=e["response_headers"], response_body=e["response_body"],
        )
        t0 = time.monotonic()
        try:
            result = await orch.analyze(exchange)
            elapsed = time.monotonic() - t0
            entry = {
                "exchange_index": idx,
                "label": e["label"],
                "dispatched_agents": result.dispatched_agents,
                "findings": [f.model_dump() for r in result.agent_reports for f in r.findings],
                "components": [c.model_dump() for r in result.agent_reports for c in r.components],
                "validation_reports": [v.model_dump() for v in result.validation_reports],
                "summary": result.summary,
                "elapsed_seconds": round(elapsed, 1),
                "error": None,
            }
            results.append(entry)
            print(f"[{idx:2d}] {elapsed:6.1f}s  {e['label']}")
            print(f"      dispatched: {result.dispatched_agents}")
            for r in result.agent_reports:
                for f in r.findings:
                    print(f"      -> {f.vulnerability_class} (conf={f.confidence}, sev={f.severity}, confirmed={f.confirmed})")
            for v in result.validation_reports:
                print(f"      VALIDATOR {v.validator} -> status={v.status} confirmed={v.confirmed} conf={v.confidence}: {v.summary[:120]}")
        except Exception as exc:
            elapsed = time.monotonic() - t0
            results.append({
                "exchange_index": idx, "label": e["label"], "dispatched_agents": [],
                "findings": [], "components": [], "validation_reports": [],
                "summary": None, "elapsed_seconds": round(elapsed, 1), "error": repr(exc),
            })
            print(f"[{idx:2d}] {elapsed:6.1f}s  {e['label']}")
            print(f"      ERROR: {exc!r}")

    with open("/tmp/juiceshop_real_results.json", "w") as f:
        json.dump({"results": results}, f, indent=2)

    total_time = sum(r["elapsed_seconds"] for r in results)
    n_errors = sum(1 for r in results if r["error"])
    total_findings = sum(len(r["findings"]) for r in results)
    confirmed_findings = sum(1 for r in results for f in r["findings"] if f.get("confirmed"))
    total_validations = sum(len(r["validation_reports"]) for r in results)
    confirmed_validations = sum(1 for r in results for v in r["validation_reports"] if v.get("confirmed"))
    print()
    print(f"Ran {len(results)} exchanges through the REAL orchestrator with REAL Ollama calls and active validators ON.")
    print(f"Total wall time: {total_time:.1f}s. Errors: {n_errors}.")
    print(f"Findings: {total_findings} total, {confirmed_findings} confirmed=True.")
    print(f"Validation runs: {total_validations} total, {confirmed_validations} confirmed=True.")
    print(f"Full results -> /tmp/juiceshop_real_results.json")


asyncio.run(main())
