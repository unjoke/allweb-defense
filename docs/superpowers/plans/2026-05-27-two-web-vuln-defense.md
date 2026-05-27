# WAF Reverse Proxy Implementation Plan

---
change: two-web-vuln-defense
design-doc: docs/superpowers/specs/2026-05-27-two-web-vuln-defense-design.md
base-ref: 423b0f7f1d7a3f9e326648219968d12a52a8c098
---

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone aiohttp-based reverse proxy WAF that intercepts attacks before forwarding requests to any HTTP backend, language-agnostic.

**Architecture:** `waf/detector.py` holds pure detection functions extracted from the existing Flask middleware (no framework deps). `waf/config.py` merges CLI args over YAML config. `waf/proxy.py` orchestrates detection, body reconstruction, forwarding, and security header injection using aiohttp.

**Tech Stack:** Python 3.x, aiohttp==3.9.5, pyyaml==6.0.2, pytest==8.4.2

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `requirements.txt` | Modify | Add aiohttp, pyyaml |
| `waf/__init__.py` | Create | Package marker |
| `waf/__main__.py` | Create | `python -m waf.proxy` entry point |
| `waf/detector.py` | Create | Pure detection/sanitization functions, no Flask |
| `waf/config.py` | Create | Load YAML + merge CLI args |
| `waf/config.yaml` | Create | Default configuration |
| `waf/proxy.py` | Create | aiohttp server, request handling, forwarding |
| `tests/test_detector.py` | Create | Unit tests for all detector functions |

---

## Task 1: Dependencies and package skeleton

**Files:**
- Modify: `requirements.txt`
- Create: `waf/__init__.py`
- Create: `waf/__main__.py`

- [ ] **Step 1: Add dependencies to requirements.txt**

Open `requirements.txt` and append two lines so it reads:

```
Flask==3.1.2
requests==2.32.5
pytest==8.4.2
Werkzeug==3.1.3
aiohttp==3.9.5
pyyaml==6.0.2
```

- [ ] **Step 2: Install new dependencies**

```bash
pip install aiohttp==3.9.5 pyyaml==6.0.2
```

Expected: both packages install without error.

- [ ] **Step 3: Create waf/__init__.py**

Create `waf/__init__.py` as an empty file (just a newline):

```python
```

- [ ] **Step 4: Create waf/__main__.py**

```python
from waf.proxy import main
main()
```

- [ ] **Step 5: Verify package is importable**

```bash
python -c "import waf; print('ok')"
```

Expected output: `ok`

---

## Task 2: waf/detector.py — pure detection functions

**Files:**
- Create: `waf/detector.py`

These functions are extracted from `app/protected/middleware.py` with Flask imports removed and rate-limit functions refactored to accept external state/config dicts.

- [ ] **Step 1: Write failing import test**

Create `tests/test_detector.py` with just the import check:

```python
def test_import_without_flask():
    import waf.detector  # must not raise ImportError
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
pytest tests/test_detector.py::test_import_without_flask -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'waf.detector'`

- [ ] **Step 3: Create waf/detector.py**

```python
import re
import os
import time
from html import escape

# SQL injection patterns
_SQL_PATTERN = re.compile(
    r"\b(union|select|insert|update|delete|drop|create|alter|exec|execute"
    r"|information_schema|sleep|benchmark|load_file|outfile)\b"
    r"|'[\s]*--"
    r"|--[\s]"
    r"|;\s*(drop|insert|update|delete|select)"
    r"|'\s*(or|and)\s+'?\d"
    r"|'\s*or\s*'",
    re.IGNORECASE,
)

# XSS patterns
_XSS_TAGS = re.compile(
    r"<\s*(script|iframe|object|embed|form|input|button|link|meta|style|svg|math|img|div|span)"
    r"|javascript\s*:"
    r"|\bon\w+\s*=",
    re.IGNORECASE,
)

# Path traversal
_PATH_TRAVERSAL = re.compile(r"\.\.[/\\]|\.\.%2[fF]|\.\.%5[cC]")

# Command injection shell metacharacters
_CMD_CHARS = re.compile(r"[;&|`$]|\$\(|>>?|<")

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif"}


def detect_sql_injection(value: str) -> bool:
    return bool(_SQL_PATTERN.search(value))


def sanitize_xss(value: str) -> str:
    if not _XSS_TAGS.search(value):
        return value
    result = escape(value, quote=True)
    result = re.sub(r"javascript\s*:", "javascript&#58;", result, flags=re.IGNORECASE)
    result = re.sub(r"\bon(\w+)\s*=", r"data-blocked-\1=", result, flags=re.IGNORECASE)
    return result


def detect_path_traversal(value: str) -> bool:
    return bool(_PATH_TRAVERSAL.search(value))


def detect_cmd_injection(value: str) -> bool:
    return bool(_CMD_CHARS.search(value))


def is_allowed_extension(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_EXTENSIONS


def check_rate_limit(ip: str, state: dict, config: dict) -> bool:
    now = time.time()
    entry = state.get(ip)
    if entry is None:
        return False
    return now < entry.get("locked_until", 0)


def record_login_failure(ip: str, state: dict, config: dict) -> None:
    now = time.time()
    entry = state.setdefault(ip, {"count": 0, "window_start": now, "locked_until": 0})
    if now - entry["window_start"] > config.get("window", 60):
        entry["count"] = 0
        entry["window_start"] = now
    entry["count"] += 1
    if entry["count"] > config.get("max_failures", 10):
        entry["locked_until"] = now + config.get("lockout", 300)
```

- [ ] **Step 4: Run import test — expect PASS**

```bash
pytest tests/test_detector.py::test_import_without_flask -v
```

Expected: PASS

---

## Task 3: Unit tests for detector functions

**Files:**
- Modify: `tests/test_detector.py`

- [ ] **Step 1: Add all detector unit tests**

Replace `tests/test_detector.py` with the full test suite:

```python
import time
import waf.detector as d


def test_import_without_flask():
    import waf.detector


# --- detect_sql_injection ---

def test_sql_union_injection():
    assert d.detect_sql_injection("' UNION SELECT * FROM users--") is True

def test_sql_or_injection():
    assert d.detect_sql_injection("' OR '1'='1") is True

def test_sql_drop_injection():
    assert d.detect_sql_injection("'; DROP TABLE users; --") is True

def test_sql_clean_string():
    assert d.detect_sql_injection("hello world") is False

def test_sql_normal_username():
    assert d.detect_sql_injection("alice123") is False


# --- sanitize_xss ---

def test_xss_script_tag_sanitized():
    result = d.sanitize_xss("<script>alert(1)</script>")
    assert "<script>" not in result

def test_xss_javascript_protocol_sanitized():
    result = d.sanitize_xss("javascript:alert(1)")
    assert "javascript:" not in result

def test_xss_event_handler_sanitized():
    result = d.sanitize_xss('<img onerror="alert(1)">')
    assert "onerror=" not in result

def test_xss_clean_string_unchanged():
    assert d.sanitize_xss("hello world") == "hello world"

def test_xss_normal_message_unchanged():
    assert d.sanitize_xss("Good morning!") == "Good morning!"


# --- detect_path_traversal ---

def test_path_traversal_dotdot_slash():
    assert d.detect_path_traversal("../../etc/passwd") is True

def test_path_traversal_encoded():
    assert d.detect_path_traversal("..%2fetc%2fpasswd") is True

def test_path_traversal_clean():
    assert d.detect_path_traversal("messages/msg_1.txt") is False

def test_path_traversal_normal_filename():
    assert d.detect_path_traversal("avatar.jpg") is False


# --- detect_cmd_injection ---

def test_cmd_semicolon():
    assert d.detect_cmd_injection("msg_1.txt; id") is True

def test_cmd_ampersand():
    assert d.detect_cmd_injection("msg_1.txt && cat /etc/passwd") is True

def test_cmd_pipe():
    assert d.detect_cmd_injection("msg_1.txt | whoami") is True

def test_cmd_clean_filename():
    assert d.detect_cmd_injection("msg_1_alice.txt") is False

def test_cmd_normal_string():
    assert d.detect_cmd_injection("hello world") is False


# --- is_allowed_extension ---

def test_extension_jpg_allowed():
    assert d.is_allowed_extension("avatar.jpg") is True

def test_extension_jpeg_allowed():
    assert d.is_allowed_extension("photo.jpeg") is True

def test_extension_png_allowed():
    assert d.is_allowed_extension("image.PNG") is True  # case-insensitive

def test_extension_gif_allowed():
    assert d.is_allowed_extension("anim.gif") is True

def test_extension_py_blocked():
    assert d.is_allowed_extension("shell.py") is False

def test_extension_php_blocked():
    assert d.is_allowed_extension("backdoor.php") is False

def test_extension_no_ext_blocked():
    assert d.is_allowed_extension("noextension") is False


# --- rate limit ---

def test_rate_limit_not_locked_initially():
    state = {}
    config = {"max_failures": 3, "window": 60, "lockout": 300}
    assert d.check_rate_limit("1.2.3.4", state, config) is False

def test_rate_limit_locked_after_threshold():
    state = {}
    config = {"max_failures": 3, "window": 60, "lockout": 300}
    ip = "1.2.3.4"
    for _ in range(4):  # one more than max_failures
        d.record_login_failure(ip, state, config)
    assert d.check_rate_limit(ip, state, config) is True

def test_rate_limit_not_locked_below_threshold():
    state = {}
    config = {"max_failures": 3, "window": 60, "lockout": 300}
    ip = "1.2.3.4"
    for _ in range(3):  # exactly max_failures, not exceeded
        d.record_login_failure(ip, state, config)
    assert d.check_rate_limit(ip, state, config) is False

def test_rate_limit_independent_ips():
    state = {}
    config = {"max_failures": 3, "window": 60, "lockout": 300}
    for _ in range(4):
        d.record_login_failure("1.1.1.1", state, config)
    assert d.check_rate_limit("1.1.1.1", state, config) is True
    assert d.check_rate_limit("2.2.2.2", state, config) is False
```

- [ ] **Step 2: Run all detector tests**

```bash
pytest tests/test_detector.py -v
```

Expected: all tests PASS (28 tests)

- [ ] **Step 3: Commit**

```bash
git add waf/__init__.py waf/__main__.py waf/detector.py tests/test_detector.py requirements.txt
git commit -m "feat: add waf package skeleton and detector pure functions with tests"
```

---

## Task 4: waf/config.yaml and waf/config.py

**Files:**
- Create: `waf/config.yaml`
- Create: `waf/config.py`

- [ ] **Step 1: Create waf/config.yaml**

```yaml
listen_port: 8080
backend_url: "http://127.0.0.1:5000"
login_path: "/login"
rules:
  sql_injection: true
  xss: true
  path_traversal: true
  cmd_injection: true
  rate_limit: true
  file_upload: true
  security_headers: true
rate_limit:
  max_failures: 10
  window: 60
  lockout: 300
log_path: "security.log"
```

- [ ] **Step 2: Create waf/config.py**

```python
import argparse
import sys
import yaml


DEFAULTS = {
    "listen_port": 8080,
    "backend_url": "http://127.0.0.1:5000",
    "login_path": "/login",
    "rules": {
        "sql_injection": True,
        "xss": True,
        "path_traversal": True,
        "cmd_injection": True,
        "rate_limit": True,
        "file_upload": True,
        "security_headers": True,
    },
    "rate_limit": {
        "max_failures": 10,
        "window": 60,
        "lockout": 300,
    },
    "log_path": "security.log",
}


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="WAF reverse proxy")
    p.add_argument("--listen", type=int, help="Port to listen on")
    p.add_argument("--backend", help="Backend URL, e.g. http://127.0.0.1:5000")
    p.add_argument("--config", help="Path to YAML config file")
    p.add_argument(
        "--disable",
        metavar="RULE",
        action="append",
        default=[],
        help="Disable a rule by name (repeatable). E.g. --disable sql_injection",
    )
    return p


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config(argv=None) -> dict:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    config = dict(DEFAULTS)
    config["rules"] = dict(DEFAULTS["rules"])
    config["rate_limit"] = dict(DEFAULTS["rate_limit"])

    # Load YAML file if provided or default path exists
    yaml_path = args.config
    if yaml_path is None:
        import os
        default = os.path.join(os.path.dirname(__file__), "config.yaml")
        if os.path.exists(default):
            yaml_path = default

    if yaml_path:
        try:
            with open(yaml_path, encoding="utf-8") as f:
                file_cfg = yaml.safe_load(f) or {}
            config = _deep_merge(config, file_cfg)
        except FileNotFoundError:
            print(f"ERROR: config file not found: {yaml_path}", file=sys.stderr)
            sys.exit(1)

    # CLI overrides
    if args.listen is not None:
        config["listen_port"] = args.listen
    if args.backend is not None:
        config["backend_url"] = args.backend

    # --disable flags
    for rule in args.disable:
        if rule in config["rules"]:
            config["rules"][rule] = False

    return config
```

- [ ] **Step 3: Verify config loads with defaults**

```bash
python -c "from waf.config import load_config; c = load_config([]); print(c['listen_port'], c['backend_url'])"
```

Expected output: `8080 http://127.0.0.1:5000`

- [ ] **Step 4: Verify CLI override works**

```bash
python -c "from waf.config import load_config; c = load_config(['--listen','9090']); print(c['listen_port'])"
```

Expected output: `9090`

---

## Task 5: waf/proxy.py — aiohttp reverse proxy

**Files:**
- Create: `waf/proxy.py`

- [ ] **Step 1: Create waf/proxy.py**

```python
import asyncio
import logging
import os
import urllib.parse

import aiohttp
from aiohttp import web

from waf.config import load_config
from waf.detector import (
    check_rate_limit,
    detect_cmd_injection,
    detect_path_traversal,
    detect_sql_injection,
    is_allowed_extension,
    record_login_failure,
    sanitize_xss,
)

_rate_state: dict = {}

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

_logger: logging.Logger | None = None


def _setup_logger(log_path: str) -> logging.Logger:
    logger = logging.getLogger("waf.security")
    if not logger.handlers:
        handler = logging.FileHandler(log_path, encoding="utf-8")
        handler.setFormatter(
            logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        )
        logger.addHandler(handler)
        logger.setLevel(logging.WARNING)
    return logger


def _log_block(logger, attack_type: str, ip: str, path: str, payload: str):
    logger.warning(
        "BLOCKED | type=%s | ip=%s | path=%s | payload=%s",
        attack_type, ip, path, payload[:200],
    )


def _log_sanitized(logger, ip: str, path: str, payload: str):
    logger.warning(
        "SANITIZED | type=xss | ip=%s | path=%s | payload=%s",
        ip, path, payload[:200],
    )


def _blocked(status: int, msg: str) -> web.Response:
    return web.Response(status=status, text=msg, content_type="text/plain")


async def _read_multipart(request: web.Request):
    """Read all multipart parts into memory. Returns (filenames, parts_data).
    parts_data is a list of (name, filename_or_None, content_type, bytes).
    """
    filenames = []
    parts_data = []
    reader = await request.multipart()
    async for part in reader:
        name = part.name
        filename = part.filename
        ct = part.headers.get(aiohttp.hdrs.CONTENT_TYPE, "application/octet-stream")
        data = await part.read()
        if filename:
            filenames.append(filename)
        parts_data.append((name, filename, ct, data))
    return filenames, parts_data


def _rebuild_multipart(parts_data) -> aiohttp.FormData:
    form = aiohttp.FormData()
    for name, filename, ct, data in parts_data:
        if filename:
            form.add_field(name, data, filename=filename, content_type=ct)
        else:
            form.add_field(name, data.decode("utf-8", errors="replace"), content_type=ct)
    return form


async def handle_request(request: web.Request, config: dict, logger: logging.Logger) -> web.Response:
    ip = request.remote or "unknown"
    path = request.path
    rules = config.get("rules", {})
    login_path = config.get("login_path", "/login")
    backend_url = config["backend_url"].rstrip("/")

    # 1. Rate limit check (before reading body)
    if rules.get("rate_limit", True):
        if request.method == "POST" and path == login_path:
            if check_rate_limit(ip, _rate_state, config["rate_limit"]):
                _log_block(logger, "brute-force", ip, path, f"ip={ip}")
                return _blocked(429, "Too Many Requests")
            record_login_failure(ip, _rate_state, config["rate_limit"])

    # 2. Parse body based on content-type
    content_type = request.content_type or ""
    get_params = dict(request.rel_url.query)
    post_params: dict = {}
    filenames: list = []
    parts_data = None
    raw_body: bytes | None = None

    if "multipart/form-data" in content_type:
        filenames, parts_data = await _read_multipart(request)
    elif "application/x-www-form-urlencoded" in content_type:
        post_params = dict(await request.post())
    else:
        raw_body = await request.read()

    # 3. Detection — scan GET + POST params
    all_str_values = list(get_params.values()) + list(post_params.values())
    for val in all_str_values:
        if rules.get("sql_injection", True) and detect_sql_injection(val):
            _log_block(logger, "sql-injection", ip, path, val)
            return _blocked(403, "Forbidden")
        if rules.get("path_traversal", True) and detect_path_traversal(val):
            _log_block(logger, "path-traversal", ip, path, val)
            return _blocked(403, "Forbidden")
        if rules.get("cmd_injection", True) and detect_cmd_injection(val):
            _log_block(logger, "cmd-injection", ip, path, val)
            return _blocked(403, "Forbidden")

    # 4. File extension check
    if rules.get("file_upload", True):
        for fname in filenames:
            if not is_allowed_extension(fname):
                _log_block(logger, "unsafe-upload", ip, path, fname)
                return _blocked(400, "Bad Request")

    # 5. XSS sanitization (mutate params, don't block)
    xss_found = False
    if rules.get("xss", True):
        sanitized_get = {}
        for k, v in get_params.items():
            sv = sanitize_xss(v)
            if sv != v:
                xss_found = True
            sanitized_get[k] = sv
        get_params = sanitized_get

        sanitized_post = {}
        for k, v in post_params.items():
            sv = sanitize_xss(v)
            if sv != v:
                xss_found = True
            sanitized_post[k] = sv
        post_params = sanitized_post

        if xss_found:
            _log_sanitized(logger, ip, path, str(request.rel_url))

    # 6. Rebuild body
    forward_data = None
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding")
    }
    forward_headers["X-Forwarded-For"] = ip

    if parts_data is not None:
        forward_data = _rebuild_multipart(parts_data)
    elif post_params:
        encoded = urllib.parse.urlencode(post_params)
        forward_data = encoded.encode("utf-8")
        forward_headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif raw_body is not None:
        forward_data = raw_body

    # Rebuild query string with sanitized GET params
    new_query = urllib.parse.urlencode(get_params)
    target_url = f"{backend_url}{path}"
    if new_query:
        target_url = f"{target_url}?{new_query}"

    # 7. Forward to backend
    async with aiohttp.ClientSession() as session:
        try:
            resp = await session.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                data=forward_data,
                allow_redirects=False,
                ssl=False,
            )
            body = await resp.read()
        except aiohttp.ClientConnectorError:
            return _blocked(502, "Bad Gateway: backend unreachable")

    # 8. Inject security headers
    response_headers = dict(resp.headers)
    response_headers.pop("Transfer-Encoding", None)
    response_headers.pop("Content-Encoding", None)
    if rules.get("security_headers", True):
        response_headers.update(SECURITY_HEADERS)

    return web.Response(
        status=resp.status,
        headers=response_headers,
        body=body,
    )


def main():
    config = load_config()
    logger = _setup_logger(config["log_path"])

    async def _handler(request: web.Request) -> web.Response:
        return await handle_request(request, config, logger)

    app = web.Application()
    app.router.add_route("*", "/{path_info:.*}", _handler)

    port = config["listen_port"]
    print(f"WAF proxy listening on :{port} → {config['backend_url']}")
    web.run_app(app, host="127.0.0.1", port=port)
```

- [ ] **Step 2: Smoke test — start proxy and verify it starts**

In one terminal, start the vulnerable backend:
```bash
python -m app.vulnerable.app
```

In another terminal, start the WAF proxy:
```bash
python -m waf.proxy --listen 8080 --backend http://127.0.0.1:5000
```

Expected output: `WAF proxy listening on :8080 → http://127.0.0.1:5000`

- [ ] **Step 3: Verify normal request passes through**

```bash
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/login
```

Expected: `200`

- [ ] **Step 4: Verify SQL injection is blocked**

```bash
curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/login?username=' OR '1'='1"
```

Expected: `403`

- [ ] **Step 5: Verify path traversal is blocked**

```bash
curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/download?filename=../../etc/passwd"
```

Expected: `403`

- [ ] **Step 6: Verify security headers are present**

```bash
curl -s -I http://127.0.0.1:8080/login | grep -i "x-frame-options"
```

Expected: `X-Frame-Options: DENY`

- [ ] **Step 7: Verify security.log is written on block**

```bash
tail -5 security.log
```

Expected: lines containing `BLOCKED | type=sql-injection` or `BLOCKED | type=path-traversal`

- [ ] **Step 8: Run full test suite to confirm no regressions**

```bash
pytest tests/test_detector.py -v
```

Expected: all tests PASS

---

## Task 6: Integration verification with attack scripts

**Files:** No new files — uses existing `attacks/` scripts

- [ ] **Step 1: Verify SQL injection attack is blocked via proxy**

With both backend (5000) and WAF proxy (8080) running:

```bash
python attacks/sql_injection.py 2>&1 | head -20
```

Run it once targeting port 5000 (should succeed), then edit the script's base URL to `http://127.0.0.1:8080` and run again (should be blocked with 403).

- [ ] **Step 2: Verify brute force is blocked via proxy**

```bash
python attacks/brute_force.py 2>&1 | tail -5
```

After 10+ attempts through port 8080, subsequent requests should return 429.

- [ ] **Step 3: Verify command injection is blocked via proxy**

```bash
python attacks/cmd_injection.py 2>&1 | head -10
```

Expected: 403 response when targeting port 8080.

- [ ] **Step 4: Verify normal login works through proxy**

```bash
curl -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST http://127.0.0.1:8080/login \
  -d "username=admin&password=admin123" \
  -w "\nHTTP %{http_code}\n"
```

Expected: HTTP 302 (redirect to /messages) — normal business flow unaffected.

- [ ] **Step 5: Final commit**

```bash
git add waf/config.yaml waf/config.py waf/proxy.py
git commit -m "feat: add waf proxy with aiohttp reverse proxy, config loader, and integration"
```

---

## Self-Review Checklist

- [x] **Spec coverage:** All 8 requirements from waf-proxy, waf-config, waf-detector specs are covered
- [x] **No placeholders:** All steps contain actual code or commands
- [x] **Type consistency:** `check_rate_limit(ip, state, config)` and `record_login_failure(ip, state, config)` signatures match across detector.py, proxy.py, and tests
- [x] **multipart handling:** Task 5 implements full read + rebuild (approach A)
- [x] **urlencoded handling:** Task 5 reads, sanitizes, re-encodes body
- [x] **Rate limit on request count:** proxy.py counts every POST to /login, not just failures
- [x] **Spec patch scenario covered:** `record_login_failure` called on every /login POST regardless of backend result
