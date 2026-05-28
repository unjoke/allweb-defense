---
comet_change: waf-ui-redesign
role: technical-design
canonical_spec: openspec
archived-with: 2026-05-28-waf-ui-redesign
status: final
---

# WAF UI Redesign — Technical Design

## Architecture Overview

单进程 asyncio event loop 内运行两个独立 aiohttp app：

```
单进程 asyncio event loop
├── Proxy App (:8080)   — waf/proxy.py (现有，不改检测逻辑)
│   └── writes → security.log
└── Dashboard App (:8081) — waf/dashboard.py (新建)
    ├── GET /         → dashboard.html (Jinja2)
    ├── GET /events   → SSE 实时日志流
    └── GET /stats    → JSON 攻击统计
        └── tails ← security.log
```

两个 app 共享同一 `config` dict 和 `logger` 对象，通过 `aiohttp.web.AppRunner` + `TCPSite` 在同一 event loop 启动。

## Module: waf/dashboard.py

### 初始化

```python
from jinja2 import Environment, FileSystemLoader
_jinja = Environment(loader=FileSystemLoader(
    os.path.join(os.path.dirname(__file__), "templates")
))
_stats: dict[str, int] = {
    "sql-injection": 0, "xss": 0, "path-traversal": 0,
    "cmd-injection": 0, "file-upload": 0, "brute-force": 0,
}
```

模块级 Jinja2 环境和统计计数器，进程生命周期内持久。

### 路由: GET /

读取 `config["rules"]` 状态，渲染 `dashboard.html`，传入 `rules` 和 `stats`。

### 路由: GET /events (SSE)

```
1. response = StreamResponse(headers={"Content-Type": "text/event-stream"})
2. await response.prepare(request)
3. f = open(log_path); f.seek(0, 2)  # 从末尾开始
4. last_activity = time.monotonic()
5. loop:
   line = f.readline()
   if line:
     parse line → update _stats[attack_type]
     await response.write(f"data: {line}\n\n".encode())
     last_activity = now
   else:
     if now - last_activity > 30:
       await response.write(b": keepalive\n\n")
       last_activity = now
     await asyncio.sleep(0.5)
```

日志行格式：`YYYY-MM-DD HH:MM:SS | BLOCKED | type=<attack_type> | ip=... | path=... | payload=...`
解析 `type=` 字段更新 `_stats`。

### 路由: GET /stats

返回 `_stats` 的 JSON 快照，供前端初始化时加载历史统计（可选）。

## proxy.py 修改：双服务启动

`main()` 函数改为：

```python
async def _run():
    # 代理 app
    proxy_runner = web.AppRunner(proxy_app)
    await proxy_runner.setup()
    await web.TCPSite(proxy_runner, port=proxy_port).start()

    # Dashboard app
    dash_runner = web.AppRunner(dash_app)
    await dash_runner.setup()
    await web.TCPSite(dash_runner, port=8081).start()

    print(f"WAF proxy :{proxy_port} → {backend}", file=sys.stderr)
    print(f"WAF dashboard :8081", file=sys.stderr)
    await asyncio.Event().wait()  # 永久阻塞

asyncio.run(_run())
```

替换原来的 `web.run_app()`。

## Dashboard 模板: waf/templates/dashboard.html

布局（三区块，黑白线条风格）：

```
┌─────────────────────────────────────────────────────┐ ← border-top: 2px solid #ff3333
│  WAF DASHBOARD                          :8081        │
├──────────────────┬──────────────────────────────────┤
│  RULES           │  ATTACK STATS                    │
│  sql_injection   │  sql-injection    [  0]           │
│  [ON]  [ON]  ... │  xss              [  0]           │
│                  │  path-traversal   [  0]           │
│                  │  ...                              │
├──────────────────┴──────────────────────────────────┤
│  LIVE LOG                                           │
│  > 2026-05-27 12:00:01 | BLOCKED | type=sql-inj... │
│  > 2026-05-27 12:00:00 | BLOCKED | type=xss ...    │
│  ...                                                │
└─────────────────────────────────────────────────────┘
```

SSE 客户端 JS（内联，约 30 行）：
- `new EventSource("/events")` 连接
- `onmessage`: 解析 `type=` 字段，更新对应计数器 DOM，prepend 日志行到列表顶部
- 日志列表保留最近 100 条（超出时移除末尾）

## 前端主题: shared/templates/base.html

CSS 变量系统（内联 `<style>`，无外部依赖）：

```css
:root {
  --bg: #0a0a0a; --bg-2: #111; --bg-3: #1a1a1a;
  --fg: #e8e8e8; --fg-dim: #888;
  --red: #ff3333; --green: #00ff41;
  --border: #333; --border-bright: #555;
}
* { border-radius: 0 !important; box-sizing: border-box; }
body { background: var(--bg); color: var(--fg); font-family: monospace; margin: 0; }
```

组件样式：
- **导航栏**: `border-top: 2px solid var(--red)`, `background: var(--bg-2)`
- **输入框**: `background: var(--bg-2); border: 1px solid var(--border); color: var(--fg)` → focus `border-color: var(--fg)`
- **主按钮**: `background: var(--fg); color: var(--bg); border: 1px solid var(--fg)` → hover 反转
- **危险按钮**: `color: var(--red); border: 1px solid var(--red)` → hover `background: var(--red); color: #000`
- **Flash 成功**: `border-left: 3px solid var(--green); color: var(--green)`
- **Flash 危险**: `border-left: 3px solid var(--red); color: var(--red)`
- **表格**: `border: 1px solid var(--border)`, thead `background: var(--bg-2)`, tr:hover `background: var(--bg-3)`
- **角色标签**: `[ADMIN]` → `color: var(--red)`, `[USER]` → `color: var(--fg-dim)`

Flash 消息关闭（原生 JS，替代 Bootstrap JS）：
```javascript
document.querySelectorAll(".flash-close").forEach(btn => {
  btn.onclick = () => btn.closest(".flash").remove();
});
```

## 文件变更清单

| 文件 | 操作 |
|------|------|
| `waf/dashboard.py` | 新建 |
| `waf/templates/dashboard.html` | 新建 |
| `waf/proxy.py` | 修改 `main()` |
| `shared/templates/base.html` | 重写 |
| `shared/templates/login.html` | 重写 |
| `shared/templates/register.html` | 重写 |
| `shared/templates/messages.html` | 重写 |
| `shared/templates/search.html` | 重写 |
| `shared/templates/profile.html` | 重写 |
| `shared/templates/admin_users.html` | 重写 |
| `shared/templates/admin_messages.html` | 重写 |
| `shared/templates/403.html` | 重写 |
| `shared/templates/429.html` | 重写 |

## Testing Strategy

手动验证（无自动化测试，演示项目）：

1. `python -m waf` 启动，确认 stderr 输出两行（:8080 和 :8081）
2. 访问 `:8081`，确认规则状态和统计显示
3. 通过 `:8080` 发送 SQL 注入请求（`?q=' OR 1=1--`），确认 Dashboard 实时收到日志并计数器 +1
4. 访问 `:8080` 的各页面，确认黑白线条风格一致，无 Bootstrap 残留
5. 断网环境下访问，确认无 CDN 加载失败

## Risks

| 风险 | 缓解 |
|------|------|
| `asyncio.run()` 替换 `web.run_app()` 可能改变信号处理行为 | 添加 `SIGINT/SIGTERM` handler 优雅关闭两个 runner |
| SSE 连接在文件不存在时崩溃 | 检查 log_path 存在，不存在时等待创建 |
| Jinja2 模板路径在不同工作目录下失效 | 用 `__file__` 的绝对路径构建 loader |

## Verification-time Patch: WAF 拦截响应主题化

验证阶段发现 `proxy.py:_blocked()` 一直返回 `web.Response(text="Forbidden")`（plain text，9 字节）。原架构依赖 `app/protected/app.py` 的 `@errorhandler(403)` 渲染 403.html，但本次将演示路径改为 WAF 直接拦截后，Flask 不再有机会渲染——styled error pages 变成死代码，与「黑白主题完整覆盖」的目标矛盾。

**修复**：在 `waf/proxy.py` 模块级初始化 Jinja2 Environment 指向 `shared/templates/`，添加 `_render_block_page()` helper；`_blocked(status, msg)` 在 status 为 403/429 时渲染对应模板返回 HTML（`text/html`），其他 status 退回原 plain text 行为。

**注意**：`base.html` 引用了 Flask 专属的 `get_flashed_messages`，独立 Jinja2 渲染时需注入 stub `_block_jinja.globals["get_flashed_messages"] = lambda *a, **kw: []`。

**结果**：403/429 响应从 9 字节 plain text 变为 ~6.4-6.5 KB 黑白主题 HTML，包含 WAF-DEMO 品牌、`var(--red)` 主题色、`FORBIDDEN`/`TOO MANY REQUESTS` 文案。已写回 OpenSpec delta `specs/waf-proxy/spec.md` 新增 acceptance scenarios。

