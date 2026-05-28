## Context

项目是一个 Web 安全演示系统，包含：
- `app/vulnerable/`：故意存在漏洞的 Flask 应用（:5000）
- `app/protected/`：有防护中间件的 Flask 应用（:5001，不再展示）
- `waf/`：基于 aiohttp 的反向代理 WAF（:8080）

当前演示路径是双 App 对比，改为 WAF 单一保护路径后，需要 WAF 自身提供可视化界面来展示其工作状态。前端模板全部使用 Bootstrap 5，风格与安全工具定位不符。

## Goals / Non-Goals

**Goals:**
- WAF 在 :8081 提供独立 Dashboard，实时展示 security.log 中的拦截记录
- Dashboard 展示攻击类型统计（SQL注入/XSS/路径穿越/命令注入/文件上传/限速）
- Dashboard 展示当前规则启用状态（从 config 读取）
- `shared/templates/` 全部 10 个模板重写为黑白直角线条风格
- 移除所有模板对 Bootstrap CDN 的依赖，改用内联 CSS

**Non-Goals:**
- 不修改 WAF 的代理逻辑（proxy.py 的检测/转发逻辑不变）
- 不删除 `app/protected/` 代码
- Dashboard 不提供规则热更新功能（只读展示）
- 不引入 JavaScript 框架，保持纯 HTML + 少量 JS

## Decisions

### 决策 1：Dashboard 服务方式 — 独立 aiohttp app vs 子路由

**选择**：在 `waf/proxy.py` 的 `main()` 中启动第二个 aiohttp app，监听 :8081，与代理 app 共享同一 event loop。

**理由**：
- 避免引入新进程或新文件入口
- aiohttp 支持在同一 event loop 运行多个 AppRunner
- Dashboard 与代理共享 `config` 和 `logger` 对象，无需 IPC

**备选**：Flask 子进程 → 需要额外进程管理，复杂度高；子路由挂在 :8080 → 与代理路由冲突风险

### 决策 2：日志读取方式 — 轮询文件 vs SSE 实时推送

**选择**：Dashboard 页面通过 SSE（Server-Sent Events）实时推送新日志行，后端用 `asyncio` 异步 tail 文件。

**理由**：
- 演示场景需要实时性，轮询有延迟且浪费请求
- SSE 比 WebSocket 实现更简单，单向推送足够
- aiohttp 原生支持 StreamResponse

**备选**：前端 JS 定时 fetch → 有延迟，不够直观

### 决策 3：前端样式方案 — 内联 CSS vs 外部 CSS 文件

**选择**：在 `base.html` 的 `<style>` 块中定义全部 CSS 变量和基础样式，子模板通过 `{% block extra_style %}` 扩展。

**理由**：
- 消除对 CDN 的依赖（Bootstrap CDN 在演示环境可能不可用）
- 单文件便于演示时修改和展示
- 模板数量有限（10个），不需要构建工具

**备选**：独立 `.css` 文件 → 需要 Flask static 路由，增加配置复杂度

### 决策 4：前端风格语言

黑底（`#0a0a0a`）、白字（`#e8e8e8`）、红色高亮（`#ff3333`）用于危险/拦截，绿色（`#00ff41`）用于通过/安全。
边框统一 `1px solid #333`，`border-radius: 0`，字体 `monospace`。
导航栏用顶部细线（`border-top: 2px solid #ff3333`）替代背景色区分。

## Risks / Trade-offs

- **SSE 连接数**：演示环境单用户，无并发压力，可接受
- **日志文件增长**：tail 实现需要记录文件偏移量，避免重复发送历史记录 → 用 `seek(0, 2)` 从末尾开始
- **模板重写工作量**：10 个模板全部重写，需确保所有 Jinja2 变量和 form action 保持不变，只改样式
- **Bootstrap 移除**：部分 Bootstrap JS 功能（alert dismiss）需用原生 JS 替代
