"""
WAF Dashboard — independent aiohttp app on :8081
Reads security.log and pushes new events via SSE.
"""
import asyncio
import json
import os
import time
from typing import Optional

from aiohttp import web
from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
_jinja = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
)

_stats: dict = {
    "sql-injection": 0,
    "xss": 0,
    "path-traversal": 0,
    "cmd-injection": 0,
    "file-upload": 0,
    "brute-force": 0,
}


def _parse_attack_type(line: str) -> Optional[str]:
    """Extract `type=<value>` from a security.log line."""
    idx = line.find("type=")
    if idx < 0:
        return None
    rest = line[idx + 5:]
    end = rest.find(" ")
    if end < 0:
        end = len(rest)
    t = rest[:end].strip()
    return t or None


async def _index(request: web.Request) -> web.Response:
    config = request.app["config"]
    rules = config.get("rules", {})
    template = _jinja.get_template("dashboard.html")
    html = template.render(rules=rules, stats=_stats)
    return web.Response(text=html, content_type="text/html")


async def _stats_json(request: web.Request) -> web.Response:
    return web.json_response(_stats)


async def _events(request: web.Request) -> web.StreamResponse:
    log_path = request.app["log_path"]
    response = web.StreamResponse(
        status=200,
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
    await response.prepare(request)

    # Wait for log file to exist
    while not os.path.exists(log_path):
        await asyncio.sleep(0.5)

    with open(log_path, "r", encoding="utf-8") as f:
        f.seek(0, 2)  # seek to end
        last_activity = time.monotonic()
        while True:
            line = f.readline()
            if line:
                line_stripped = line.rstrip("\n")
                attack_type = _parse_attack_type(line_stripped)
                if attack_type and attack_type in _stats:
                    _stats[attack_type] += 1
                payload = json.dumps({"line": line_stripped, "type": attack_type})
                await response.write(f"data: {payload}\n\n".encode("utf-8"))
                last_activity = time.monotonic()
            else:
                if time.monotonic() - last_activity > 30:
                    await response.write(b": keepalive\n\n")
                    last_activity = time.monotonic()
                await asyncio.sleep(0.5)


def make_app(config: dict) -> web.Application:
    app = web.Application()
    app["config"] = config
    app["log_path"] = config.get("log_path", "security.log")
    app.router.add_get("/", _index)
    app.router.add_get("/events", _events)
    app.router.add_get("/stats", _stats_json)
    return app
