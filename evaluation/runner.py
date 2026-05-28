"""HTTP runner that dispatches payloads to the WAF and records results."""
from __future__ import annotations
import sys
import time
from dataclasses import dataclass
from typing import Any
import requests

_BLOCKED_STATUS = {400, 403, 429}


# Map (inject_point, param_name) -> endpoint path
ENDPOINTS = {
    ("query_param", "q"): "/search",
    ("query_param", "filename"): "/download",
    ("form_body", "username"): "/login",
    ("form_body", "password"): "/login",
    ("form_body", "content"): "/messages",
    ("form_body", "new_password"): "/profile/password",
    ("form_body", "filename"): "/admin/messages/delete",
    ("path", "filename"): "/download",
    ("filename", "avatar"): "/profile/avatar",
    ("header", "X-Forwarded-For"): "/search",
    ("header", "X-Real-IP"): "/search",
}


_FILE_CONTENT_BUILDERS: dict[str, bytes] = {
    "png-magic-padding": b"\x89PNG\r\n\x1a\n" + b"\x00" * 100,
    "jpg-magic-padding": b"\xff\xd8\xff\xe0" + b"\x00" * 100,
    "gif-magic-padding": b"GIF89a" + b"\x00" * 100,
    "php-payload": b"<?php system($_GET['c']); ?>",
    "polyglot-png-php": b"\x89PNG\r\n\x1a\n" + b"\x00" * 20 + b"<?php system($_GET['c']); ?>",
    "empty": b"",
    "plain-text": b"hello world",
}


def _build_file_content(kind: str) -> bytes:
    if kind not in _FILE_CONTENT_BUILDERS:
        raise ValueError(f"unknown file_content kind: {kind}")
    return _FILE_CONTENT_BUILDERS[kind]


@dataclass
class Result:
    payload_id: str
    category: str
    expected: str
    blocked: bool
    status_code: int | None
    latency_ms: float
    error: str | None

    @property
    def outcome(self) -> str:
        if self.expected == "blocked" and self.blocked:
            return "TP"
        if self.expected == "blocked" and not self.blocked:
            return "FN"
        if self.expected == "allowed" and self.blocked:
            return "FP"
        return "TN"


def _resolve_endpoint(inject_point: str, param_name: str) -> str:
    key = (inject_point, param_name)
    if key not in ENDPOINTS:
        raise ValueError(f"no endpoint mapping for inject_point={inject_point} param_name={param_name}")
    return ENDPOINTS[key]


def _build_request_kwargs(p: dict) -> tuple[str, str, dict[str, Any]]:
    inject = p["inject_point"]
    param = p["param_name"]
    payload = p["payload"]

    if inject == "query_param":
        url_path = _resolve_endpoint(inject, param)
        return "GET", url_path, {"params": {param: payload}}

    if inject == "form_body":
        url_path = _resolve_endpoint(inject, param)
        return "POST", url_path, {"data": {param: payload}}

    if inject == "path":
        url_path = _resolve_endpoint(inject, param)
        return "GET", url_path, {"params": {param: payload}}

    if inject == "filename":
        url_path = _resolve_endpoint(inject, param)
        content_kind = p.get("file_content", "png-magic-padding")
        content = _build_file_content(content_kind)
        ctype = p.get("file_content_type", "image/png")
        return "POST", url_path, {"files": {param: (payload, content, ctype)}}

    if inject == "header":
        url_path = _resolve_endpoint(inject, param)
        base_params = p.get("base_params", {"q": "test"})
        return "GET", url_path, {
            "params": base_params,
            "headers": {param: payload},
        }

    raise ValueError(f"unknown inject_point: {inject}")


def _login_for_session(waf_url: str, username: str = "alice", password: str = "alice123") -> requests.Session:
    s = requests.Session()
    try:
        resp = s.post(
            waf_url.rstrip("/") + "/login",
            data={"username": username, "password": password},
            timeout=5,
            allow_redirects=False,
        )
        if resp.status_code != 302:
            print(
                f"WARNING: login as '{username}' returned status {resp.status_code}; "
                f"runner will operate unauthenticated. "
                f"Endpoints requiring auth will likely fail.",
                file=sys.stderr,
            )
    except requests.RequestException as e:
        print(f"WARNING: login failed: {e}; runner will operate unauthenticated.", file=sys.stderr)
    return s


def _send_one(p: dict, waf_url: str, session: requests.Session) -> Result:
    method, url_path, kwargs = _build_request_kwargs(p)
    url = waf_url.rstrip("/") + url_path
    start = time.time()
    try:
        resp = session.request(method, url, allow_redirects=False, timeout=10, **kwargs)
        latency = (time.time() - start) * 1000.0
        blocked = resp.status_code in _BLOCKED_STATUS
        return Result(
            payload_id=p["id"], category=p["category"], expected=p["expected"],
            blocked=blocked, status_code=resp.status_code, latency_ms=latency, error=None,
        )
    except requests.RequestException as e:
        latency = (time.time() - start) * 1000.0
        return Result(
            payload_id=p["id"], category=p["category"], expected=p["expected"],
            blocked=False, status_code=None, latency_ms=latency, error=str(e),
        )


def _run_rate_limit_test(p: dict, waf_url: str) -> Result:
    burst = p.get("burst_count", 12)
    headers = p.get("headers", {})
    last_status = None
    start = time.time()
    s = requests.Session()
    try:
        for _ in range(burst):
            r = s.post(
                waf_url.rstrip("/") + "/login",
                data={"username": "rate-test", "password": "wrong"},
                headers=headers,
                timeout=5,
                allow_redirects=False,
            )
            last_status = r.status_code
        latency = (time.time() - start) * 1000.0
        blocked = last_status == 429
        return Result(
            payload_id=p["id"], category=p["category"], expected=p["expected"],
            blocked=blocked, status_code=last_status, latency_ms=latency, error=None,
        )
    except requests.RequestException as e:
        latency = (time.time() - start) * 1000.0
        return Result(
            payload_id=p["id"], category=p["category"], expected=p["expected"],
            blocked=False, status_code=None, latency_ms=latency, error=str(e),
        )


def run(payloads: list[dict], waf_url: str = "http://127.0.0.1:8080") -> list[Result]:
    """Send payloads to WAF, return results.

    Probes WAF reachability first; raises RuntimeError if unreachable.
    """
    try:
        requests.get(waf_url.rstrip("/") + "/", timeout=3, allow_redirects=False)
    except requests.RequestException as e:
        raise RuntimeError(
            f"WAF unreachable at {waf_url}: {e}. Start it with `python -m waf` first."
        )

    session = _login_for_session(waf_url)
    results: list[Result] = []
    for p in payloads:
        if p["category"] == "rate_limit":
            results.append(_run_rate_limit_test(p, waf_url))
        else:
            results.append(_send_one(p, waf_url, session))
    return results
