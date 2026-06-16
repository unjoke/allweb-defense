import asyncio
import logging
import os
import sys
import urllib.parse
from datetime import datetime

import aiohttp
from aiohttp import web
from jinja2 import Environment, FileSystemLoader, select_autoescape

from waf.config import load_config
from waf.detector import (
    check_rate_limit,
    detect_cmd_injection,
    detect_path_traversal,
    detect_sql_injection,
    is_allowed_extension,
    is_allowed_magic_bytes,
    normalize,
    record_login_failure,
    sanitize_xss,
)
from waf.url_rules import is_rule_enabled

_rate_state: dict = {}

_APP_TEMPLATES = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "app", "templates"
)
_block_jinja = Environment(
    loader=FileSystemLoader(_APP_TEMPLATES),
    autoescape=select_autoescape(["html"]),
)
_block_jinja.globals["get_flashed_messages"] = lambda *a, **kw: []


def _render_block_page(template_name: str, **ctx) -> str:
    ctx.setdefault("session", {})
    ctx.setdefault("mode", "vulnerable")
    return _block_jinja.get_template(template_name).render(**ctx)

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

# --- logging ---

def _setup_logger(log_path: str) -> logging.Logger:
    logger = logging.getLogger("waf.security")
    if not logger.handlers:
        handler = logging.FileHandler(log_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def _log_block(logger, attack_type: str, ip: str, path: str, payload: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"{ts} | BLOCKED | type={attack_type} | ip={ip} | path={path} | payload={payload[:100]}")


def _log_sanitized(logger, ip: str, path: str, payload: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"{ts} | SANITIZED | type=xss | ip={ip} | path={path} | payload={payload[:100]}")


# --- response helpers ---

def _blocked(status: int, msg: str) -> web.Response:
    """Return a styled error page when available, plain text otherwise."""
    if status == 403:
        body = _render_block_page("403.html", message=msg)
        return web.Response(status=403, text=body, content_type="text/html")
    if status == 429:
        body = _render_block_page("429.html")
        return web.Response(status=429, text=body, content_type="text/html")
    return web.Response(status=status, text=msg)


# --- multipart helpers ---

async def _read_multipart(request: web.Request):
    """Read all multipart parts into memory. Returns (filenames, parts_data).

    filenames: list of (field_name, filename) for file parts
    parts_data: list of (field_name, filename_or_None, content_type, data_bytes)
    """
    reader = await request.multipart()
    filenames = []
    parts_data = []
    async for part in reader:
        data = await part.read()
        filename = part.filename
        if filename:
            filenames.append((part.name, filename))
        parts_data.append((part.name, filename, part.headers.get(aiohttp.hdrs.CONTENT_TYPE), data))
    return filenames, parts_data


def _rebuild_multipart(parts_data) -> aiohttp.FormData:
    form = aiohttp.FormData()
    for name, filename, content_type, data in parts_data:
        kwargs = {}
        if filename:
            kwargs["filename"] = filename
        if content_type:
            kwargs["content_type"] = content_type
        form.add_field(name, data, **kwargs)
    return form


# --- main handler ---

async def handle_request(request: web.Request, config: dict, logger: logging.Logger, session: aiohttp.ClientSession) -> web.Response:
    ip = request.remote or "unknown"
    path = request.path
    rules = config.get("rules", {})
    rate_cfg = config.get("rate_limit", {})
    login_path = config.get("login_path", "/login")

    # 1. Rate limit check (login POST only)
    if rules.get("rate_limit", True) and request.method == "POST" and path == login_path:
        if check_rate_limit(ip, _rate_state):
            _log_block(logger, "brute-force", ip, path, "rate-limit-exceeded")
            return _blocked(429, "Too Many Requests")
        record_login_failure(ip, _rate_state, rate_cfg)

    # 2. Parse params
    get_params = dict(request.rel_url.query)
    post_params = {}
    filenames = []
    parts_data = []
    raw_body = None
    content_type = request.content_type or ""

    if request.method in ("POST", "PUT", "PATCH"):
        if "application/x-www-form-urlencoded" in content_type:
            post_params = dict(await request.post())
        elif "multipart/form-data" in content_type:
            filenames, parts_data = await _read_multipart(request)
        else:
            raw_body = await request.read()

    all_string_params = {**get_params, **post_params}

    # 3. Detection (block on first hit)
    for key, val in all_string_params.items():
        nval = normalize(val)
        if is_rule_enabled(config, path, "sql_injection") and detect_sql_injection(nval):
            _log_block(logger, "sql-injection", ip, path, val)
            return _blocked(403, "Forbidden")
        if is_rule_enabled(config, path, "path_traversal") and detect_path_traversal(nval):
            _log_block(logger, "path-traversal", ip, path, val)
            return _blocked(403, "Forbidden")
        if is_rule_enabled(config, path, "cmd_injection") and detect_cmd_injection(nval):
            _log_block(logger, "cmd-injection", ip, path, val)
            return _blocked(403, "Forbidden")

    for field_name, filename in filenames:
        if is_rule_enabled(config, path, "file_upload"):
            if not is_allowed_extension(filename):
                _log_block(logger, "file-upload", ip, path, filename)
                return _blocked(400, "Bad Request")
            file_data = next(
                (d for n, fn, ct, d in parts_data if n == field_name and fn == filename),
                b"",
            )
            if file_data and not is_allowed_magic_bytes(file_data):
                _log_block(logger, "file-upload-magic", ip, path, filename)
                return _blocked(400, "Bad Request")

    # 4. XSS sanitize (not block)
    if is_rule_enabled(config, path, "xss"):
        sanitized_get = {}
        for k, v in get_params.items():
            nv = normalize(v)
            sv = sanitize_xss(nv)
            if sv != nv:
                _log_sanitized(logger, ip, path, v)
            sanitized_get[k] = sv

        sanitized_post = {}
        for k, v in post_params.items():
            nv = normalize(v)
            sv = sanitize_xss(nv)
            if sv != nv:
                _log_sanitized(logger, ip, path, v)
            sanitized_post[k] = sv
    else:
        sanitized_get = get_params
        sanitized_post = post_params

    # 5. Rebuild body for forwarding
    if "application/x-www-form-urlencoded" in content_type and sanitized_post:
        forward_body = urllib.parse.urlencode(sanitized_post).encode()
    elif "multipart/form-data" in content_type and parts_data:
        forward_body = _rebuild_multipart(parts_data)
    elif raw_body is not None:
        forward_body = raw_body
    else:
        forward_body = None

    # 6. Build forward URL
    backend = config["backend_url"].rstrip("/")
    query_string = urllib.parse.urlencode(sanitized_get) if sanitized_get else ""
    forward_url = backend + path
    if query_string:
        forward_url += "?" + query_string

    # 7. Filter headers — remove hop-by-hop and host, add X-Forwarded-For
    is_multipart = "multipart/form-data" in content_type
    skip_headers = {"host", "transfer-encoding", "content-length"}
    if is_multipart:
        skip_headers.add("content-type")
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in skip_headers
    }
    forward_headers["X-Forwarded-For"] = ip

    # 8. Forward request to backend
    async with session.request(
        method=request.method,
        url=forward_url,
        headers=forward_headers,
        data=forward_body,
        allow_redirects=False,
    ) as backend_resp:
        body = await backend_resp.read()
        resp_headers = dict(backend_resp.headers)
        # Remove hop-by-hop headers that aiohttp already handles
        for h in ("Transfer-Encoding", "Content-Encoding", "Content-Length"):
            resp_headers.pop(h, None)
        # Inject security headers
        if rules.get("security_headers", True):
            resp_headers.update(SECURITY_HEADERS)
        return web.Response(
            status=backend_resp.status,
            headers=resp_headers,
            body=body,
        )


# --- entry point ---

def main():
    config = load_config()
    logger = _setup_logger(config["log_path"])

    from waf.dashboard import make_app as make_dashboard_app

    async def _run():
        # Proxy app
        proxy_app = web.Application()

        async def _on_startup(app):
            app["session"] = aiohttp.ClientSession()

        async def _on_cleanup(app):
            await app["session"].close()

        async def _handler(request):
            try:
                return await handle_request(request, config, logger, request.app["session"])
            except Exception as e:
                logger.error(f"Proxy error: {e}")
                return web.Response(status=502, text="Bad Gateway")

        proxy_app.on_startup.append(_on_startup)
        proxy_app.on_cleanup.append(_on_cleanup)
        proxy_app.router.add_route("*", "/{path_info:.*}", _handler)

        proxy_runner = web.AppRunner(proxy_app)
        await proxy_runner.setup()
        proxy_site = web.TCPSite(proxy_runner, port=config["listen_port"])
        await proxy_site.start()

        # Dashboard app
        dash_app = make_dashboard_app(config)
        dash_runner = web.AppRunner(dash_app)
        await dash_runner.setup()
        dash_port = config.get("dashboard_port", 8081)
        dash_site = web.TCPSite(dash_runner, port=dash_port)
        await dash_site.start()

        print(f"WAF proxy listening on :{config['listen_port']}, forwarding to {config['backend_url']}", file=sys.stderr)
        print(f"WAF dashboard listening on :{dash_port}", file=sys.stderr)

        try:
            await asyncio.Event().wait()
        finally:
            await proxy_runner.cleanup()
            await dash_runner.cleanup()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
