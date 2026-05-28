---
change: waf-ui-redesign
design-doc: docs/superpowers/specs/2026-05-27-waf-ui-redesign-design.md
base-ref: 4ff8705e9251671669abc8d70986345c53211e10
---

# WAF UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增 WAF 实时日志 Dashboard（:8081），并将 `shared/templates/` 全部 10 个模板从 Bootstrap 圆润风格重写为黑白线条风格。

**Architecture:** 单进程 asyncio event loop 同时启动两个 aiohttp app（代理 :8080 + Dashboard :8081）。Dashboard 用 Jinja2 渲染（已有依赖），通过 SSE tail `security.log`，模块级计数器维护攻击统计。前端主题用纯内联 CSS（无 Bootstrap），CSS 变量系统管理黑白配色。

**Tech Stack:** Python 3.12 + aiohttp + Jinja2（已存在）+ 纯 HTML/CSS/JS（无外部框架）

---

## Task 1: WAF Dashboard 后端模块

**Files:**
- Create: `waf/dashboard.py`

- [ ] **Step 1: 创建 dashboard.py 模块骨架**

创建 `waf/dashboard.py`：

```python
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
```

- [ ] **Step 2: 提交**

```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
git add waf/dashboard.py
git commit -m "feat(waf): add dashboard module with SSE log stream and stats"
```

---

## Task 2: Dashboard HTML 模板

**Files:**
- Create: `waf/templates/dashboard.html`

- [ ] **Step 1: 创建模板目录与文件**

创建 `waf/templates/dashboard.html`：

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>WAF DASHBOARD :8081</title>
<style>
  :root {
    --bg: #0a0a0a; --bg-2: #111; --bg-3: #1a1a1a;
    --fg: #e8e8e8; --fg-dim: #888;
    --red: #ff3333; --green: #00ff41;
    --border: #333; --border-bright: #555;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--bg); color: var(--fg);
    font-family: 'Consolas', 'Courier New', monospace;
    margin: 0; padding: 0;
    border-top: 2px solid var(--red);
  }
  header {
    background: var(--bg-2);
    padding: 16px 24px;
    border-bottom: 1px solid var(--border);
    display: flex; justify-content: space-between; align-items: center;
  }
  header h1 {
    margin: 0; font-size: 18px; letter-spacing: 2px;
    color: var(--fg); font-weight: bold;
  }
  header .meta { color: var(--fg-dim); font-size: 13px; }
  .grid {
    display: grid;
    grid-template-columns: 1fr 2fr;
    gap: 0;
    border-bottom: 1px solid var(--border);
  }
  .panel {
    padding: 20px 24px;
  }
  .panel + .panel { border-left: 1px solid var(--border); }
  .panel h2 {
    margin: 0 0 16px 0; font-size: 13px;
    letter-spacing: 2px; color: var(--fg-dim);
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px; font-weight: normal;
  }
  .rule-row, .stat-row {
    display: flex; justify-content: space-between;
    padding: 6px 0; font-size: 14px;
  }
  .rule-row + .rule-row, .stat-row + .stat-row {
    border-top: 1px dashed var(--border);
  }
  .rule-name, .stat-name { color: var(--fg); }
  .rule-status.on { color: var(--green); }
  .rule-status.off { color: var(--red); }
  .stat-value {
    color: var(--fg); font-weight: bold;
    min-width: 40px; text-align: right;
  }
  .log-section {
    padding: 20px 24px;
  }
  .log-section h2 {
    margin: 0 0 16px 0; font-size: 13px;
    letter-spacing: 2px; color: var(--fg-dim);
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px; font-weight: normal;
  }
  #log {
    list-style: none; margin: 0; padding: 0;
    max-height: 60vh; overflow-y: auto;
    background: var(--bg-2);
    border: 1px solid var(--border);
  }
  #log li {
    padding: 6px 12px; font-size: 13px;
    border-bottom: 1px dashed var(--border);
    white-space: pre-wrap; word-break: break-all;
  }
  #log li:hover { background: var(--bg-3); }
  #log li.empty { color: var(--fg-dim); font-style: italic; }
  .badge { color: var(--red); font-weight: bold; }
  .conn-status {
    display: inline-block; width: 8px; height: 8px;
    background: var(--green); margin-right: 6px;
    vertical-align: middle;
  }
  .conn-status.disconnected { background: var(--red); }
</style>
</head>
<body>
<header>
  <h1>&gt; WAF DASHBOARD</h1>
  <div class="meta">
    <span id="conn-indicator" class="conn-status"></span>
    <span id="conn-text">CONNECTING...</span>
    &nbsp;:8081
  </div>
</header>

<div class="grid">
  <div class="panel">
    <h2>// RULES</h2>
    {% for name, enabled in rules.items() %}
    <div class="rule-row">
      <span class="rule-name">{{ name }}</span>
      <span class="rule-status {{ 'on' if enabled else 'off' }}">
        [{{ 'ON ' if enabled else 'OFF' }}]
      </span>
    </div>
    {% endfor %}
  </div>

  <div class="panel">
    <h2>// ATTACK STATS</h2>
    {% for name, count in stats.items() %}
    <div class="stat-row">
      <span class="stat-name">{{ name }}</span>
      <span class="stat-value" data-stat="{{ name }}">[{{ '%4d' % count }}]</span>
    </div>
    {% endfor %}
  </div>
</div>

<div class="log-section">
  <h2>// LIVE LOG</h2>
  <ul id="log">
    <li class="empty">waiting for events...</li>
  </ul>
</div>

<script>
(function () {
  const logEl = document.getElementById("log");
  const connIndicator = document.getElementById("conn-indicator");
  const connText = document.getElementById("conn-text");
  const MAX_LINES = 100;
  let emptyRemoved = false;

  function setConnected(ok) {
    if (ok) {
      connIndicator.classList.remove("disconnected");
      connText.textContent = "LIVE";
    } else {
      connIndicator.classList.add("disconnected");
      connText.textContent = "DISCONNECTED";
    }
  }

  function bumpStat(type) {
    const el = document.querySelector('[data-stat="' + type + '"]');
    if (!el) return;
    const m = el.textContent.match(/\d+/);
    const next = (m ? parseInt(m[0], 10) : 0) + 1;
    el.textContent = "[" + String(next).padStart(4, " ") + "]";
  }

  function prependLog(line) {
    if (!emptyRemoved) {
      logEl.innerHTML = "";
      emptyRemoved = true;
    }
    const li = document.createElement("li");
    li.textContent = "> " + line;
    logEl.insertBefore(li, logEl.firstChild);
    while (logEl.children.length > MAX_LINES) {
      logEl.removeChild(logEl.lastChild);
    }
  }

  const es = new EventSource("/events");
  es.onopen = () => setConnected(true);
  es.onerror = () => setConnected(false);
  es.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      if (data.line) prependLog(data.line);
      if (data.type) bumpStat(data.type);
    } catch (err) {
      prependLog(e.data);
    }
  };
})();
</script>
</body>
</html>
```

- [ ] **Step 2: 提交**

```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
git add waf/templates/dashboard.html
git commit -m "feat(waf): add dashboard.html template with SSE client"
```

---

## Task 3: 修改 proxy.py 双服务启动

**Files:**
- Modify: `waf/proxy.py:212-239` (the `main()` function)

- [ ] **Step 1: 替换 main() 函数为双 runner 启动**

将 `waf/proxy.py` 文件末尾的 `def main():` 函数（从第 214 行开始到文件末尾）整个替换为：

```python
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
```

- [ ] **Step 2: 启动验证 — 同时启动两个服务**

启动 vulnerable app（一个终端）：
```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
python -m app.vulnerable.app
```

另一个终端启动 WAF：
```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
python -m waf
```
预期 stderr 输出：
```
WAF proxy listening on :8080, forwarding to http://127.0.0.1:5000
WAF dashboard listening on :8081
```

curl 测试两个端口：
```bash
curl -sI http://127.0.0.1:8080/ | head -1
curl -sI http://127.0.0.1:8081/ | head -1
```
两个都应返回 200。停止 WAF（Ctrl+C）。

- [ ] **Step 3: 提交**

```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
git add waf/proxy.py
git commit -m "feat(waf): start proxy and dashboard on shared event loop"
```

---

## Task 4: Dashboard 端到端验证

**Files:** （无修改，仅手动验证）

- [ ] **Step 1: 启动 vulnerable app + WAF**

终端 1：
```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
python -m app.vulnerable.app
```

终端 2：
```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
python -m waf
```

- [ ] **Step 2: 浏览器访问 :8081**

打开 `http://127.0.0.1:8081/`。
预期：
- 页面背景黑色，monospace 字体
- 左侧 RULES 区显示 6 个规则及 [ON]/[OFF] 状态
- 右侧 ATTACK STATS 区显示 6 个攻击类型，初始全部 `[   0]`
- 底部 LIVE LOG 显示 "waiting for events..."
- 右上角 conn 指示器为绿色 `LIVE`

- [ ] **Step 3: 触发 SQL 注入，验证实时推送**

在另一个终端运行：
```bash
curl "http://127.0.0.1:8080/login?test=1' OR 1=1--"
```

预期：
- :8080 返回 403
- Dashboard 页面 LIVE LOG 区在 1 秒内出现 `> 2026-... | BLOCKED | type=sql-injection | ...`
- ATTACK STATS 中 `sql-injection` 计数从 `[   0]` 变成 `[   1]`

- [ ] **Step 4: 触发 path-traversal 验证多类型计数**

```bash
curl "http://127.0.0.1:8080/download?filename=../../etc/passwd"
```

预期：`path-traversal` 计数 +1。

- [ ] **Step 5: 关闭 WAF 和 vulnerable app**

两个终端 Ctrl+C 即可。如果以上 4 步全部通过，进入下一个 Task。如有问题，回到 Task 1-3 检查代码。

---

## Task 5: 重写 base.html — 黑白主题基础层

**Files:**
- Modify: `shared/templates/base.html` (全文替换)

- [ ] **Step 1: 全文替换 base.html**

将 `shared/templates/base.html` 整个文件内容替换为：

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}留言管理系统{% endblock %}</title>
<style>
  :root {
    --bg: #0a0a0a; --bg-2: #111; --bg-3: #1a1a1a;
    --fg: #e8e8e8; --fg-dim: #888;
    --red: #ff3333; --green: #00ff41;
    --border: #333; --border-bright: #555;
  }
  * { box-sizing: border-box; border-radius: 0 !important; }
  html, body { margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--fg);
    font-family: 'Consolas', 'Courier New', monospace;
    line-height: 1.5;
    border-top: 2px solid var(--red);
  }
  a { color: var(--fg); text-decoration: none; border-bottom: 1px dotted var(--fg-dim); }
  a:hover { color: #fff; border-bottom-color: #fff; }
  h1, h2, h3, h4, h5, h6 { font-weight: normal; letter-spacing: 1px; }
  h4 { font-size: 16px; color: var(--fg); margin: 24px 0 16px 0; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
  hr { border: 0; border-top: 1px solid var(--border); margin: 16px 0; }

  /* nav */
  .nav {
    background: var(--bg-2);
    border-bottom: 1px solid var(--border);
    padding: 12px 0;
  }
  .nav-inner {
    max-width: 1100px; margin: 0 auto; padding: 0 24px;
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;
  }
  .brand {
    color: var(--fg); font-weight: bold; letter-spacing: 2px; font-size: 14px;
    border-bottom: none;
  }
  .brand:hover { color: #fff; }
  .tag {
    display: inline-block; margin-left: 8px; padding: 2px 6px;
    font-size: 11px; letter-spacing: 1px;
    border: 1px solid currentColor;
  }
  .tag.vuln { color: var(--red); }
  .tag.safe { color: var(--green); }
  .nav-links { display: flex; gap: 18px; flex-wrap: wrap; }
  .nav-links a {
    color: var(--fg); border-bottom: none; font-size: 13px;
    letter-spacing: 1px; padding: 4px 0;
  }
  .nav-links a:hover { color: #fff; border-bottom: 1px solid #fff; }
  .nav-links a.admin { color: var(--red); }
  .nav-links a.admin:hover { color: #fff; border-bottom-color: var(--red); }

  /* container */
  .container { max-width: 1100px; margin: 0 auto; padding: 24px; }

  /* form controls */
  input[type=text], input[type=password], input[type=email], input[type=file],
  textarea, select {
    background: var(--bg-2); color: var(--fg);
    border: 1px solid var(--border);
    padding: 8px 10px; font-family: inherit; font-size: 14px;
    width: 100%; outline: none;
  }
  input[type=text]:focus, input[type=password]:focus, input[type=email]:focus,
  input[type=file]:focus, textarea:focus, select:focus { border-color: var(--fg); }
  textarea { resize: vertical; min-height: 80px; }
  label {
    display: block; margin-bottom: 6px;
    color: var(--fg-dim); font-size: 12px; letter-spacing: 1px;
  }
  .field { margin-bottom: 16px; }

  /* buttons */
  .btn {
    display: inline-block; padding: 8px 18px;
    background: transparent; color: var(--fg);
    border: 1px solid var(--border-bright);
    font-family: inherit; font-size: 13px; letter-spacing: 1px;
    cursor: pointer; text-decoration: none;
    transition: none;
  }
  .btn:hover { color: #fff; border-color: #fff; }
  .btn-primary {
    background: var(--fg); color: var(--bg);
    border: 1px solid var(--fg);
  }
  .btn-primary:hover { background: var(--bg); color: var(--fg); border-color: var(--fg); }
  .btn-danger { color: var(--red); border-color: var(--red); }
  .btn-danger:hover { background: var(--red); color: #000; border-color: var(--red); }
  .btn-block { display: block; width: 100%; text-align: center; }
  .btn-sm { padding: 4px 10px; font-size: 12px; }

  /* flash */
  .flash {
    padding: 10px 14px; margin-bottom: 12px;
    background: var(--bg-2); position: relative;
    border-left: 3px solid var(--fg-dim);
  }
  .flash.success { border-left-color: var(--green); color: var(--green); }
  .flash.danger  { border-left-color: var(--red);   color: var(--red); }
  .flash.warning { border-left-color: #ffaa00;      color: #ffaa00; }
  .flash.info    { border-left-color: var(--fg);    color: var(--fg); }
  .flash-close {
    position: absolute; top: 8px; right: 12px;
    background: transparent; border: 0; color: inherit;
    cursor: pointer; font-family: inherit; font-size: 16px;
  }

  /* table */
  table { width: 100%; border-collapse: collapse; border: 1px solid var(--border); }
  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: var(--bg-2); color: var(--fg-dim); font-weight: normal; letter-spacing: 1px; font-size: 12px; }
  tbody tr:hover { background: var(--bg-3); }

  /* badges */
  .role { font-weight: bold; letter-spacing: 1px; }
  .role.admin { color: var(--red); }
  .role.user  { color: var(--fg-dim); }

  /* layout */
  .row { display: flex; flex-wrap: wrap; gap: 24px; }
  .col-main { flex: 2; min-width: 320px; }
  .col-side { flex: 1; min-width: 240px; }
  .center { display: flex; justify-content: center; }
  .panel {
    border: 1px solid var(--border);
    background: var(--bg-2);
    padding: 18px;
    margin-bottom: 16px;
  }
  .panel-title {
    color: var(--fg-dim); font-size: 12px; letter-spacing: 2px;
    margin: 0 0 12px 0; padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }
  .muted { color: var(--fg-dim); }
  code, pre { background: var(--bg-3); padding: 2px 6px; color: var(--fg); font-family: inherit; }
</style>
{% block extra_style %}{% endblock %}
</head>
<body>
<nav class="nav">
  <div class="nav-inner">
    <a class="brand" href="/">&gt; WAF-DEMO
      {% if mode == 'vulnerable' %}
        <span class="tag vuln">VULN</span>
      {% else %}
        <span class="tag safe">PROTECTED</span>
      {% endif %}
    </a>
    <div class="nav-links">
      {% if session.get('user_id') %}
        <a href="/messages">留言板</a>
        <a href="/search">搜索</a>
        <a href="/profile">个人设置</a>
        {% if session.get('role') == 'admin' %}
          <a class="admin" href="/admin/users">用户管理</a>
          <a class="admin" href="/admin/messages">文件管理</a>
        {% endif %}
        <a href="/logout">退出 [{{ session.get('username') }}]</a>
      {% else %}
        <a href="/login">登录</a>
        <a href="/register">注册</a>
      {% endif %}
    </div>
  </div>
</nav>

<div class="container">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for cat, msg in messages %}
      <div class="flash {{ cat }}">{{ msg }}<button class="flash-close" type="button">×</button></div>
    {% endfor %}
  {% endwith %}
  {% block content %}{% endblock %}
</div>

<script>
document.querySelectorAll(".flash-close").forEach(function (btn) {
  btn.addEventListener("click", function () {
    var flash = btn.closest(".flash");
    if (flash) flash.parentNode.removeChild(flash);
  });
});
</script>
</body>
</html>
```

- [ ] **Step 2: 提交**

```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
git add shared/templates/base.html
git commit -m "feat(theme): rewrite base.html with black/white sharp theme"
```

---

## Task 6: 重写 login.html 和 register.html

**Files:**
- Modify: `shared/templates/login.html` (全文替换)
- Modify: `shared/templates/register.html` (全文替换)

- [ ] **Step 1: 全文替换 login.html**

```html
{% extends "base.html" %}
{% block title %}登录{% endblock %}
{% block content %}
<div class="center">
  <div style="width: 360px;">
    <h4>// LOGIN</h4>
    <div class="panel">
      <form method="POST" action="/login">
        {% if csrf_token is defined %}
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        {% endif %}
        <div class="field">
          <label>USERNAME</label>
          <input type="text" name="username" required autofocus>
        </div>
        <div class="field">
          <label>PASSWORD</label>
          <input type="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary btn-block">LOG IN</button>
      </form>
      <hr>
      <p class="muted" style="text-align:center; margin:0;">
        没有账号？<a href="/register">注册新用户</a>
      </p>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 2: 全文替换 register.html**

```html
{% extends "base.html" %}
{% block title %}注册{% endblock %}
{% block content %}
<div class="center">
  <div style="width: 360px;">
    <h4>// REGISTER</h4>
    <div class="panel">
      <form method="POST" action="/register">
        {% if csrf_token is defined %}
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        {% endif %}
        <div class="field">
          <label>USERNAME</label>
          <input type="text" name="username" required autofocus>
        </div>
        <div class="field">
          <label>PASSWORD</label>
          <input type="password" name="password" required>
        </div>
        <div class="field">
          <label>EMAIL</label>
          <input type="email" name="email">
        </div>
        <button type="submit" class="btn btn-primary btn-block">CREATE ACCOUNT</button>
      </form>
      <hr>
      <p class="muted" style="text-align:center; margin:0;">
        已有账号？<a href="/login">直接登录</a>
      </p>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 3: 提交**

```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
git add shared/templates/login.html shared/templates/register.html
git commit -m "feat(theme): rewrite login/register templates"
```

---

## Task 7: 重写 messages.html 和 search.html

**Files:**
- Modify: `shared/templates/messages.html` (全文替换)
- Modify: `shared/templates/search.html` (全文替换)

- [ ] **Step 1: 全文替换 messages.html**

```html
{% extends "base.html" %}
{% block title %}留言板{% endblock %}
{% block extra_style %}
<style>
  .msg-item {
    border: 1px solid var(--border);
    background: var(--bg-2);
    padding: 14px 16px;
    margin-bottom: 10px;
  }
  .msg-head {
    display: flex; justify-content: space-between; align-items: baseline;
    margin-bottom: 8px;
    border-bottom: 1px dashed var(--border); padding-bottom: 6px;
  }
  .msg-author { color: var(--fg); font-weight: bold; }
  .msg-time { color: var(--fg-dim); font-size: 12px; }
  .msg-body { margin: 8px 0 12px 0; color: var(--fg); }
  .msg-actions { display: flex; gap: 8px; }
</style>
{% endblock %}
{% block content %}
<div class="row">
  <div class="col-main">
    <h4>// MESSAGE BOARD</h4>
    <div class="panel">
      <form method="POST" action="/messages">
        {% if csrf_token is defined %}
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        {% endif %}
        <div class="field">
          <textarea name="content" rows="3" placeholder="> 写下你的留言..." required></textarea>
        </div>
        <button type="submit" class="btn btn-primary">PUBLISH</button>
      </form>
    </div>

    {% for msg in messages %}
    <div class="msg-item">
      <div class="msg-head">
        <span class="msg-author">[{{ msg.username }}]</span>
        <span class="msg-time">{{ msg.created_at }}</span>
      </div>
      <div class="msg-body">{{ msg.content | safe }}</div>
      <div class="msg-actions">
        <a class="btn btn-sm" href="/download?filename=msg_{{ msg.id }}_{{ msg.username }}.txt">DOWNLOAD</a>
        <form method="POST" action="/messages/delete" style="display:inline">
          {% if csrf_token is defined %}
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          {% endif %}
          <input type="hidden" name="msg_id" value="{{ msg.id }}">
          <button type="submit" class="btn btn-sm btn-danger">DELETE</button>
        </form>
      </div>
    </div>
    {% else %}
    <p class="muted">// no messages yet</p>
    {% endfor %}
  </div>

  <div class="col-side">
    <h4>// QUICK SEARCH</h4>
    <div class="panel">
      <form method="GET" action="/search">
        <div class="field">
          <input type="text" name="q" placeholder="search messages...">
        </div>
        <button class="btn btn-block" type="submit">SEARCH</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 2: 全文替换 search.html**

```html
{% extends "base.html" %}
{% block title %}搜索结果{% endblock %}
{% block extra_style %}
<style>
  .res-item { border: 1px solid var(--border); background: var(--bg-2); padding: 12px 14px; margin-bottom: 8px; }
  .res-head { display: flex; gap: 12px; align-items: baseline; margin-bottom: 6px; border-bottom: 1px dashed var(--border); padding-bottom: 4px; }
  .res-author { color: var(--fg); font-weight: bold; }
  .res-time { color: var(--fg-dim); font-size: 12px; }
</style>
{% endblock %}
{% block content %}
<h4>// SEARCH RESULTS</h4>
<p class="muted">关键词：<code>{{ q | safe }}</code></p>

{% if results %}
  {% for msg in results %}
  <div class="res-item">
    <div class="res-head">
      <span class="res-author">[{{ msg.username }}]</span>
      <span class="res-time">{{ msg.created_at }}</span>
    </div>
    <div>{{ msg.content | safe }}</div>
  </div>
  {% endfor %}
{% else %}
  <p class="muted">// 未找到相关留言</p>
{% endif %}

<a href="/messages" class="btn">&larr; BACK TO BOARD</a>
{% endblock %}
```

- [ ] **Step 3: 提交**

```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
git add shared/templates/messages.html shared/templates/search.html
git commit -m "feat(theme): rewrite messages/search templates"
```

---

## Task 8: 重写 profile.html

**Files:**
- Modify: `shared/templates/profile.html` (全文替换)

- [ ] **Step 1: 全文替换 profile.html**

```html
{% extends "base.html" %}
{% block title %}个人设置{% endblock %}
{% block content %}
<div class="center">
  <div style="width: 480px;">
    <h4>// PROFILE</h4>

    <div class="panel">
      <h5 class="panel-title">CHANGE PASSWORD</h5>
      <form method="POST" action="/profile/password">
        {% if csrf_token is defined %}
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        {% endif %}
        <div class="field">
          <label>NEW PASSWORD</label>
          <input type="password" name="new_password" required>
        </div>
        <button type="submit" class="btn btn-primary">UPDATE PASSWORD</button>
      </form>
    </div>

    <div class="panel">
      <h5 class="panel-title">UPLOAD AVATAR</h5>
      <form method="POST" action="/profile/avatar" enctype="multipart/form-data">
        {% if csrf_token is defined %}
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        {% endif %}
        <div class="field">
          <input type="file" name="avatar">
        </div>
        <button type="submit" class="btn">UPLOAD FILE</button>
      </form>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 2: 提交**

```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
git add shared/templates/profile.html
git commit -m "feat(theme): rewrite profile template"
```

---

## Task 9: 重写 admin_users.html 和 admin_messages.html

**Files:**
- Modify: `shared/templates/admin_users.html` (全文替换)
- Modify: `shared/templates/admin_messages.html` (全文替换)

- [ ] **Step 1: 全文替换 admin_users.html**

```html
{% extends "base.html" %}
{% block title %}用户管理{% endblock %}
{% block content %}
<h4>// USER MANAGEMENT <span class="role admin" style="font-size:12px; margin-left:8px;">[ADMIN]</span></h4>

<table>
  <thead>
    <tr>
      <th>ID</th>
      <th>USERNAME</th>
      <th>ROLE</th>
      <th>EMAIL</th>
      <th>ACTION</th>
    </tr>
  </thead>
  <tbody>
    {% for u in users %}
    <tr>
      <td>{{ u.id }}</td>
      <td>{{ u.username }}</td>
      <td>
        {% if u.role == 'admin' %}
          <span class="role admin">[ADMIN]</span>
        {% else %}
          <span class="role user">[USER]</span>
        {% endif %}
      </td>
      <td>{{ u.email }}</td>
      <td>
        <form method="POST" action="/admin/users/delete" style="display:inline">
          {% if csrf_token is defined %}
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          {% endif %}
          <input type="hidden" name="user_id" value="{{ u.id }}">
          <button type="submit" class="btn btn-sm btn-danger"
            onclick="return confirm('确认删除？')">DELETE</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
```

- [ ] **Step 2: 全文替换 admin_messages.html**

```html
{% extends "base.html" %}
{% block title %}留言文件管理{% endblock %}
{% block content %}
<h4>// MESSAGE FILES <span class="role admin" style="font-size:12px; margin-left:8px;">[ADMIN]</span></h4>
<p class="muted">// 留言文件存储在服务器 <code>messages/</code> 目录</p>

<table>
  <thead>
    <tr>
      <th>FILENAME</th>
      <th>ACTION</th>
    </tr>
  </thead>
  <tbody>
    {% for fname in files %}
    <tr>
      <td><code>{{ fname }}</code></td>
      <td>
        <form method="POST" action="/admin/messages/delete" style="display:inline">
          {% if csrf_token is defined %}
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          {% endif %}
          <input type="hidden" name="filename" value="{{ fname }}">
          <button type="submit" class="btn btn-sm btn-danger">DELETE</button>
        </form>
      </td>
    </tr>
    {% else %}
    <tr><td colspan="2" class="muted">// no files</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
```

- [ ] **Step 3: 提交**

```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
git add shared/templates/admin_users.html shared/templates/admin_messages.html
git commit -m "feat(theme): rewrite admin pages with sharp tabular style"
```

---

## Task 10: 重写错误页 403.html 和 429.html

**Files:**
- Modify: `shared/templates/403.html` (全文替换)
- Modify: `shared/templates/429.html` (全文替换)

- [ ] **Step 1: 全文替换 403.html**

```html
{% extends "base.html" %}
{% block title %}403 FORBIDDEN{% endblock %}
{% block content %}
<div class="center" style="margin-top: 60px;">
  <div style="text-align: center; max-width: 500px;">
    <h1 style="font-size: 96px; color: var(--red); margin: 0; letter-spacing: 8px;">403</h1>
    <h4 style="border: 0; color: var(--red); letter-spacing: 4px;">// FORBIDDEN</h4>
    <p class="muted" style="margin: 24px 0;">
      {{ message | default('您没有权限访问此页面') }}
    </p>
    <a href="/" class="btn btn-danger">&larr; RETURN HOME</a>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 2: 全文替换 429.html**

```html
{% extends "base.html" %}
{% block title %}429 RATE LIMITED{% endblock %}
{% block content %}
<div class="center" style="margin-top: 60px;">
  <div style="text-align: center; max-width: 500px;">
    <h1 style="font-size: 96px; color: var(--red); margin: 0; letter-spacing: 8px;">429</h1>
    <h4 style="border: 0; color: var(--red); letter-spacing: 4px;">// TOO MANY REQUESTS</h4>
    <p class="muted" style="margin: 24px 0;">
      请求过于频繁，请稍后再试
    </p>
    <a href="/login" class="btn btn-danger">&larr; BACK TO LOGIN</a>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 3: 提交**

```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
git add shared/templates/403.html shared/templates/429.html
git commit -m "feat(theme): rewrite 403/429 error pages"
```

---

## Task 11: 端到端验证整个系统

**Files:** （无修改，仅手动验证 + 勾选 OpenSpec tasks.md）

- [ ] **Step 1: 启动 vulnerable app + WAF**

终端 1：
```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
python -m app.vulnerable.app
```

终端 2：
```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
python -m waf
```

确认 stderr 输出两行端口监听信息。

- [ ] **Step 2: 浏览器走完所有用户路径**

访问以下页面，逐一确认黑白线条风格一致、无 Bootstrap 残留（无圆角、无蓝色按钮）：

1. `http://127.0.0.1:8080/login` — 登录页
2. `http://127.0.0.1:8080/register` — 注册页（用一个新用户注册）
3. 注册并登录后，重定向到 `/messages` — 留言板
4. 发布一条测试留言，确认显示
5. `http://127.0.0.1:8080/search?q=test` — 搜索结果
6. `http://127.0.0.1:8080/profile` — 个人设置
7. 用 admin 账号登录（先在 vulnerable 数据库里有 admin），访问 `/admin/users` 和 `/admin/messages`

每个页面：
- 顶部导航有红色顶边线 + `[VULN]` 标签
- 字体为 monospace
- 无圆角、无 Bootstrap 蓝按钮

- [ ] **Step 3: 触发错误页**

```bash
curl -s "http://127.0.0.1:8080/login?x=' OR 1=1--"
```
浏览器访问 `http://127.0.0.1:8080/login?x=' OR 1=1--` 应直接看到黑底红字的 403 页面。

连续 11 次 POST 错误密码触发限速，应看到 429 页面（或在 curl 里看到 429 状态）。

- [ ] **Step 4: Dashboard 联动验证**

打开 `http://127.0.0.1:8081/`，确认 step 3 的攻击已被记录到 LIVE LOG 和统计计数。

- [ ] **Step 5: 关闭服务并勾选 OpenSpec tasks.md**

Ctrl+C 关闭两个终端。

将 `openspec/changes/waf-ui-redesign/tasks.md` 中所有 `- [ ]` 改为 `- [x]`（全部 14 项任务）。

```bash
cd "E:/学校文件/大三下/计算机与网络安全/allweb-defense"
git add openspec/changes/waf-ui-redesign/tasks.md
git commit -m "chore(openspec): mark waf-ui-redesign tasks complete"
```

如果 step 1-4 任何一步失败，回到对应 Task 修复后再次验证。
