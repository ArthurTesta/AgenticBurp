"""
The REAL run: the orchestrator against the captured PixelMart exchanges
with NO substitution of any kind -- orch.ollama.chat_json /
chat_json_metered are left as the genuine OllamaClient methods, making
real HTTP calls to a real, locally-reachable Ollama instance
(http://localhost:11434, per harness/config.yaml) running the actual
configured models (llama3.1:8b, gemma2:9b).

Every prior run against this test target (phase1/phase2/phase3) used a
human-authored substitute for the LLM because Ollama was never reachable
from that sandbox. This script exists specifically to remove that
substitution now that it no longer needs to be there.
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
store._DB_PATH = "/tmp/pixelmart_real_state_v4.db"
import cache
cache.init_cache(db_path="/tmp/pixelmart_real_cache_v4.db")

import orchestrator as orch_mod
from models import HttpExchange

with open(HARNESS_DIR / "config.yaml") as f:
    config = yaml.safe_load(f)

orch = orch_mod.Orchestrator(config)
# Deliberately NOT touching orch.ollama.chat_json / chat_json_metered --
# those remain the real OllamaClient methods, making real network calls.


async def main():
    with open("/tmp/pixelmart_exchanges.json") as f:
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
            results.append({
                "exchange_index": idx,
                "label": e["label"],
                "dispatched_agents": result.dispatched_agents,
                "findings": [f.model_dump() for r in result.agent_reports for f in r.findings],
                "components": [c.model_dump() for r in result.agent_reports for c in r.components],
                "summary": result.summary,
                "elapsed_seconds": round(elapsed, 1),
                "error": None,
            })
            print(f"[{idx:2d}] {elapsed:6.1f}s  {e['label']}")
            print(f"      dispatched: {result.dispatched_agents}")
            for r in result.agent_reports:
                for f in r.findings:
                    print(f"      -> {f.vulnerability_class} (conf={f.confidence}, sev={f.severity})")
        except Exception as exc:
            elapsed = time.monotonic() - t0
            results.append({
                "exchange_index": idx,
                "label": e["label"],
                "dispatched_agents": [],
                "findings": [],
                "components": [],
                "summary": None,
                "elapsed_seconds": round(elapsed, 1),
                "error": repr(exc),
            })
            print(f"[{idx:2d}] {elapsed:6.1f}s  {e['label']}")
            print(f"      ERROR: {exc!r}")

    with open("/tmp/pixelmart_real_results_v4.json", "w") as f:
        json.dump({"results": results}, f, indent=2)

    total_time = sum(r["elapsed_seconds"] for r in results)
    n_errors = sum(1 for r in results if r["error"])
    print()
    print(f"Ran {len(results)} exchanges through the REAL orchestrator with REAL Ollama calls.")
    print(f"Total wall time: {total_time:.1f}s. Errors: {n_errors}.")
    print(f"Full results -> /tmp/pixelmart_real_results_v4.json")


asyncio.run(main())
