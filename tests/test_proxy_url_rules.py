"""Integration tests driving handle_request directly with mocked aiohttp objects."""
import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf.proxy import handle_request
from waf.url_rules import load_url_rules


# --- helpers ---------------------------------------------------------------

class _FakeURL:
    def __init__(self, path: str, query: dict | None = None):
        self.path = path
        self.query = query or {}


class _FakeRequest:
    """Minimal aiohttp.Request stand-in for handle_request."""
    def __init__(self, *, method="GET", path="/", query=None, headers=None,
                 form=None, content_type="application/x-www-form-urlencoded"):
        self.method = method
        self.path = path
        self.rel_url = _FakeURL(path, query or {})
        self.remote = "127.0.0.1"
        self.headers = headers or {}
        self.content_type = content_type
        self._form = form or {}
        self._read_body = b""

    async def post(self):
        return self._form

    async def read(self):
        return self._read_body


def _make_session_returning_200():
    """Mock aiohttp.ClientSession.request as an async context manager yielding a 200 backend response."""
    backend_resp = MagicMock()
    backend_resp.read = AsyncMock(return_value=b"OK")
    backend_resp.status = 200
    backend_resp.headers = {"Content-Type": "text/plain"}

    class _CtxMgr:
        async def __aenter__(self):
            return backend_resp
        async def __aexit__(self, *a):
            return False

    session = MagicMock()
    session.request = MagicMock(return_value=_CtxMgr())
    return session


def _logger():
    return logging.getLogger("test-waf-url-rules")


def _run(coro):
    return asyncio.run(coro)


def _config(rules: dict | None = None, url_rules=None, login_path="/login"):
    return {
        "rules": rules or {
            "sql_injection": True, "xss": True, "path_traversal": True,
            "cmd_injection": True, "file_upload": True,
            "rate_limit": True, "security_headers": True,
        },
        "rate_limit": {"max_failures": 10, "window": 60, "lockout": 300},
        "backend_url": "http://backend.invalid",
        "login_path": login_path,
        "url_rules": url_rules,
    }


# --- I2: url_rules narrows /search to [SQL, XSS] — PATH should pass through ----

def test_i2_path_narrowed_on_search(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - url: /search\n    detect: [SQL, XSS]\n", encoding="utf-8")
    ur = load_url_rules(str(rules_path))
    cfg = _config(url_rules=ur)
    req = _FakeRequest(method="GET", path="/search", query={"x": "../../etc/passwd"})
    resp = _run(handle_request(req, cfg, _logger(), _make_session_returning_200()))
    # PATH is narrowed away on /search — request reaches backend (200 not 403)
    assert resp.status == 200


# --- I3: same rules, /other path still has PATH on ----

def test_i3_path_still_blocks_unmatched(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - url: /search\n    detect: [SQL, XSS]\n", encoding="utf-8")
    ur = load_url_rules(str(rules_path))
    cfg = _config(url_rules=ur)
    req = _FakeRequest(method="GET", path="/other", query={"x": "../../etc/passwd"})
    resp = _run(handle_request(req, cfg, _logger(), _make_session_returning_200()))
    # /other doesn't match → default-on → PATH still blocks
    assert resp.status == 403


# --- I4: global xss=false + rule listing XSS — XSS not run on /search ----

def test_i4_global_cap_wins(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - url: /search\n    detect: [XSS]\n", encoding="utf-8")
    ur = load_url_rules(str(rules_path))
    cfg = _config(rules={
        "sql_injection": False, "xss": False, "path_traversal": False,
        "cmd_injection": False, "file_upload": False,
        "rate_limit": False, "security_headers": True,
    }, url_rules=ur)
    # With every detection globally off, the request must reach backend
    req = _FakeRequest(method="GET", path="/search", query={"x": "<script>alert(1)</script>"})
    resp = _run(handle_request(req, cfg, _logger(), _make_session_returning_200()))
    assert resp.status == 200  # nothing blocks


# --- I7: url_rules narrows /login but RATE still fires ----

def test_i7_rate_not_narrowed_by_url_rules(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - url: /login\n    detect: [SQL]\n", encoding="utf-8")
    ur = load_url_rules(str(rules_path))
    cfg = _config(url_rules=ur, login_path="/login")
    # Force rate-limit lockout: pre-load _rate_state with locked entry
    from waf.proxy import _rate_state
    _rate_state.clear()
    _rate_state["127.0.0.1"] = {"count": 999, "window_start": 0, "locked_until": 9_999_999_999}
    try:
        req = _FakeRequest(method="POST", path="/login", form={"u": "a", "p": "b"})
        resp = _run(handle_request(req, cfg, _logger(), _make_session_returning_200()))
        # RATE fires (429), ignoring url_rules narrowing
        assert resp.status == 429
    finally:
        _rate_state.clear()


# --- I8: security_headers still injected on a narrowed path ----

def test_i8_security_headers_not_narrowed(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - url: /foo\n    detect: [SQL]\n", encoding="utf-8")
    ur = load_url_rules(str(rules_path))
    cfg = _config(url_rules=ur)
    req = _FakeRequest(method="GET", path="/foo", query={"x": "hello"})
    resp = _run(handle_request(req, cfg, _logger(), _make_session_returning_200()))
    assert resp.status == 200
    assert "X-Frame-Options" in resp.headers
    assert "Content-Security-Policy" in resp.headers


# --- Drift guard: every internal key in _TOKEN_TO_KEY must be referenced by handle_request ----
#
# If a future change adds a 6th detection type to the proxy's dispatch, _TOKEN_TO_KEY
# must be extended in lockstep. This test catches silent drift (design doc §5 Risk #4).

def test_drift_internal_keys_referenced_by_proxy():
    from pathlib import Path
    from waf.url_rules import _TOKEN_TO_KEY

    proxy_src = Path(__file__).resolve().parents[1] / "waf" / "proxy.py"
    src = proxy_src.read_text(encoding="utf-8")
    for internal_key in _TOKEN_TO_KEY.values():
        assert f'"{internal_key}"' in src, (
            f"internal key {internal_key!r} declared in _TOKEN_TO_KEY but not "
            f"referenced in waf/proxy.py — token vocabulary may be out of sync"
        )
