"""
capture_helper.py -- thin wrapper around `requests` that records every
call you make into the exchange JSON format harness_driver.py expects.
This has no knowledge of any specific target or attack -- you decide
what requests to send based on your own exploration of the target.

Usage pattern:

    from capture_helper import Capture
    cap = Capture(base_url="http://127.0.0.1:5001")

    cap.request("GET", "/api/health", label="baseline health check")
    cap.request("POST", "/api/login", json_body={"username": "alice", "password": "..."},
                label="normal login")
    # ... explore the target however you'd normally approach a black-box
    # REST API: enumerate endpoints, try common auth/session/injection
    # probes, vary parameters, compare responses ...

    cap.save("my_exchanges.json")

Nothing in this file tells you what to send -- that's the actual testing
work. This just handles the bookkeeping so your capture ends up in the
right shape for harness_driver.py.
"""
import json
import requests


class Capture:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.exchanges = []

    def request(self, method: str, path: str, headers: dict | None = None,
                json_body: dict | None = None, raw_body: str | None = None,
                label: str = "") -> requests.Response:
        headers = headers or {}
        url = self.base_url + path
        if json_body is not None:
            resp = requests.request(method, url, headers=headers, json=json_body, timeout=10)
            request_body = json.dumps(json_body)
        elif raw_body is not None:
            resp = requests.request(method, url, headers=headers, data=raw_body, timeout=10)
            request_body = raw_body
        else:
            resp = requests.request(method, url, headers=headers, timeout=10)
            request_body = ""

        self.exchanges.append({
            "label": label,
            "method": method,
            "url": url,
            "request_headers": dict(headers),
            "request_body": request_body,
            "response_status": resp.status_code,
            "response_headers": dict(resp.headers),
            "response_body": resp.text,
        })
        return resp

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.exchanges, f, indent=2)
        print(f"Saved {len(self.exchanges)} exchanges -> {path}")
