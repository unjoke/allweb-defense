# Comet Design Handoff

- Change: waf-ui-redesign
- Phase: design
- Mode: compact
- Context hash: e7a7032e8b48d269e3efa485c97988d9c4008cf8f87c65f82d12f0fba3b2252c

Generated-by: comet-handoff.sh

OpenSpec remains the canonical capability spec. This handoff is a deterministic, source-traceable context pack, not an agent-authored summary.

## openspec/changes/waf-ui-redesign/proposal.md

- Source: openspec/changes/waf-ui-redesign/proposal.md
- Lines: 1-29
- SHA256: 71c4334e7991a18023fb92f869a0477a9fffb7039329177ead106b2fddacb023

```md
## Why

当前项目以"漏洞版 vs 防护版"双 App 对比的方式展示安全防护，但这种方式需要维护两套应用代码，且无法直观展示 WAF 的实时拦截过程。改为"WAF 代理直接保护漏洞版应用"的单一演示路径，并为 WAF 增加实时日志 Dashboard，能更清晰地展示通防 WAF 的核心价值。同时，现有前端使用 Bootstrap 5 圆润风格，与安全工具的专业气质不符，需要重设计为黑白配色、线条感强的成熟风格。

## What Changes

- **移除 `app/protected` 的展示入口**：保留代码文件但不再在任何 UI 或文档中引导用户访问 :5001，演示路径统一为 WAF(:8080) → vulnerable app(:5000)
- **新增 WAF Dashboard**：WAF 在独立端口（:8081）提供实时日志查看界面，展示拦截记录、攻击类型统计、规则开关状态
- **全站前端重设计**：`shared/templates/` 下所有 10 个模板从 Bootstrap 圆润风格重写为黑白配色、直角、线条感强的终端/工业风格
- **WAF Dashboard 模板**：新增 WAF 专属模板目录 `waf/templates/`，包含 dashboard 主页

## Capabilities

### New Capabilities

- `waf-dashboard`: WAF 实时日志 Dashboard，独立 Web 界面，展示拦截日志流、攻击类型分布、规则启用状态
- `frontend-theme`: 全站黑白锐利主题，替换 Bootstrap 圆润风格，统一应用于 shared/templates 所有页面

### Modified Capabilities

- `waf-proxy`: WAF 代理新增 Dashboard 子服务，在 :8081 端口提供管理界面（现有代理逻辑不变）

## Impact

- `waf/proxy.py`：新增 Dashboard HTTP 服务器（独立 aiohttp app 或子路由）
- `waf/templates/`：新建目录，存放 Dashboard HTML 模板
- `shared/templates/*.html`：全部重写，移除 Bootstrap 依赖，改用自定义 CSS
- `app/protected/`：代码保留，不删除，但不再被任何入口引用
- `security.log`：Dashboard 读取此文件实时展示
```

## openspec/changes/waf-ui-redesign/design.md

- Source: openspec/changes/waf-ui-redesign/design.md
- Lines: 1-71
- SHA256: 139c013c7b4ce942c560b9f0a6ed9d88466a4a5e5b45979c45a3f179827fedbb

```md
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
```

## openspec/changes/waf-ui-redesign/tasks.md

- Source: openspec/changes/waf-ui-redesign/tasks.md
- Lines: 1-36
- SHA256: 316fa97f940f35662b61fb495f288b2c21f005ebb2499a9823f800d028244288

```md
## 1. WAF Dashboard 后端

- [ ] 1.1 在 `waf/` 下新建 `dashboard.py`，实现 aiohttp Dashboard app，包含 `/`（主页）和 `/events`（SSE）两个路由
- [ ] 1.2 实现 SSE 端点：异步 tail `security.log`，从文件末尾开始，每 0.5s 检查新行，推送新增行，30s 无新行发送 keepalive
- [ ] 1.3 实现内存攻击统计计数器（按攻击类型），在 SSE 推送时同步更新，通过 `/stats` JSON 端点暴露
- [ ] 1.4 修改 `waf/proxy.py` 的 `main()` 函数，使用 `aiohttp.web.AppRunner` 同时启动代理（:8080）和 Dashboard（:8081）
- [ ] 1.5 Dashboard 主页路由读取当前 `config["rules"]` 状态，传入模板渲染

## 2. WAF Dashboard 前端模板

- [ ] 2.1 新建 `waf/templates/` 目录，创建 `dashboard.html`：黑白线条风格，顶部显示规则状态列表，中部显示攻击统计卡片，底部显示实时日志流
- [ ] 2.2 在 `dashboard.html` 中实现 SSE 客户端 JS：连接 `/events`，新日志行插入日志列表顶部，同步更新统计计数器

## 3. 前端主题基础层

- [ ] 3.1 重写 `shared/templates/base.html`：移除 Bootstrap CDN，定义全局 CSS（黑底、白字、monospace、直角、红色顶边线导航栏），保留所有 Jinja2 变量和 block 结构
- [ ] 3.2 在 `base.html` 中实现原生 JS 的 flash 消息关闭功能（替代 Bootstrap JS）

## 4. 应用页面模板重写

- [ ] 4.1 重写 `shared/templates/login.html`：直角输入框，白底黑字登录按钮，无卡片阴影
- [ ] 4.2 重写 `shared/templates/register.html`：与 login 风格一致
- [ ] 4.3 重写 `shared/templates/messages.html`：留言列表用线条分隔替代卡片，发布按钮白底黑字，删除按钮红色线条
- [ ] 4.4 重写 `shared/templates/search.html`：搜索框直角，结果列表线条风格
- [ ] 4.5 重写 `shared/templates/profile.html`：两个功能区用线条分隔，按钮风格统一
- [ ] 4.6 重写 `shared/templates/admin_users.html`：表格线条风格，角色标签改为 [ADMIN]/[USER] 文本
- [ ] 4.7 重写 `shared/templates/admin_messages.html`：文件列表线条风格，删除按钮红色
- [ ] 4.8 重写 `shared/templates/403.html`：黑底红字错误页，显示 "403 FORBIDDEN"
- [ ] 4.9 重写 `shared/templates/429.html`：黑底红字错误页，显示 "429 TOO MANY REQUESTS"

## 5. 验证

- [ ] 5.1 启动 vulnerable app（:5000）和 WAF（:8080/:8081），验证代理正常转发
- [ ] 5.2 访问 Dashboard（:8081），验证规则状态和统计显示正确
- [ ] 5.3 发送一个 SQL 注入请求，验证 Dashboard 实时收到拦截日志并更新计数
- [ ] 5.4 检查所有 10 个模板页面的视觉效果，确认黑白线条风格一致
```

## openspec/changes/waf-ui-redesign/specs/frontend-theme/spec.md

- Source: openspec/changes/waf-ui-redesign/specs/frontend-theme/spec.md
- Lines: 1-75
- SHA256: 408a0c5c86ee65a38a233d9004e2bd21c958320a3f0976a09dafccaf0f61deb8

```md
## ADDED Requirements

### Requirement: 黑白直角主题基础样式
`shared/templates/base.html` SHALL 定义全局 CSS 变量和基础样式，实现黑底白字、直角边框、monospace 字体的主题，不依赖任何外部 CSS 框架或 CDN。

#### Scenario: 页面基础外观
- **WHEN** 用户访问任意页面
- **THEN** 页面背景为 #0a0a0a，主文字颜色为 #e8e8e8，字体为 monospace，所有边框 border-radius 为 0

#### Scenario: 无外部依赖
- **WHEN** 在无网络环境下访问页面
- **THEN** 页面样式完整显示，无 CDN 加载失败导致的样式缺失

### Requirement: 导航栏样式
导航栏 SHALL 使用顶部红色细线（`border-top: 2px solid #ff3333`）作为视觉标识，背景为深黑色，链接为白色。

#### Scenario: 导航栏外观
- **WHEN** 用户访问任意页面
- **THEN** 顶部导航栏显示红色顶边线，背景 #111，链接颜色 #e8e8e8，hover 时变为 #ffffff

#### Scenario: 漏洞版标识
- **WHEN** mode 为 'vulnerable'
- **THEN** 导航栏品牌名旁显示红色 [VULN] 标签

#### Scenario: 防护版标识
- **WHEN** mode 不为 'vulnerable'（或为 'protected'）
- **THEN** 导航栏品牌名旁显示绿色 [PROTECTED] 标签

### Requirement: 表单控件样式
所有表单输入框、按钮 SHALL 使用直角、黑底、白色边框线条风格。

#### Scenario: 输入框外观
- **WHEN** 用户查看任意包含表单的页面
- **THEN** input/textarea 背景为 #111，边框为 1px solid #444，文字为 #e8e8e8，focus 时边框变为 #ffffff，border-radius 为 0

#### Scenario: 主操作按钮
- **WHEN** 用户查看主操作按钮（登录、发布、提交等）
- **THEN** 按钮为白底黑字，border 1px solid #fff，hover 时反转为黑底白字

#### Scenario: 危险操作按钮
- **WHEN** 用户查看删除等危险操作按钮
- **THEN** 按钮边框和文字为 #ff3333，hover 时背景变为 #ff3333，文字变为 #000

### Requirement: Flash 消息样式
Flash 消息 SHALL 使用线条边框风格替代 Bootstrap alert 的圆角填充风格。

#### Scenario: 成功消息
- **WHEN** 页面显示 success 类型 flash 消息
- **THEN** 消息框左边框为 3px solid #00ff41，背景为 #0a0a0a，文字为 #00ff41

#### Scenario: 危险/错误消息
- **WHEN** 页面显示 danger 类型 flash 消息
- **THEN** 消息框左边框为 3px solid #ff3333，背景为 #0a0a0a，文字为 #ff3333

#### Scenario: 消息可关闭
- **WHEN** 用户点击消息框的关闭按钮
- **THEN** 消息框从页面移除（原生 JS 实现，不依赖 Bootstrap JS）

### Requirement: 数据表格样式
管理页面的数据表格 SHALL 使用线条分隔风格，无圆角，无背景色交替。

#### Scenario: 表格外观
- **WHEN** 用户访问用户管理或留言管理页面
- **THEN** 表格使用 1px solid #333 边框，表头背景 #111，行 hover 背景 #1a1a1a，无圆角

### Requirement: 角色/状态标签样式
角色标签（admin/user）和状态标签 SHALL 使用方括号文本风格替代 Bootstrap badge 圆角胶囊。

#### Scenario: Admin 标签
- **WHEN** 用户角色为 admin
- **THEN** 显示为 [ADMIN] 文本，颜色 #ff3333

#### Scenario: User 标签
- **WHEN** 用户角色为 user
- **THEN** 显示为 [USER] 文本，颜色 #888
```

## openspec/changes/waf-ui-redesign/specs/waf-dashboard/spec.md

- Source: openspec/changes/waf-ui-redesign/specs/waf-dashboard/spec.md
- Lines: 1-52
- SHA256: 4d33a1b7e74710a78d76c1d4387d2264021a2a65dafd68994e3e4de5e4f27d15

```md
## ADDED Requirements

### Requirement: Dashboard 服务启动
WAF 代理启动时 SHALL 同时在 :8081 端口启动 Dashboard HTTP 服务，与代理共享同一 asyncio event loop。

#### Scenario: 代理启动时 Dashboard 同步启动
- **WHEN** 执行 `python -m waf` 启动 WAF 代理
- **THEN** :8080 代理服务和 :8081 Dashboard 服务均可访问

#### Scenario: Dashboard 端口冲突
- **WHEN** :8081 端口已被占用
- **THEN** WAF 启动失败并输出明确错误信息

### Requirement: 实时日志流
Dashboard SHALL 通过 SSE 端点 `/events` 实时推送 security.log 中的新增日志行。

#### Scenario: 新拦截事件推送
- **WHEN** WAF 拦截一个请求并写入 security.log
- **THEN** Dashboard 页面在 2 秒内收到该日志行并显示在日志列表顶部

#### Scenario: 无新日志时保持连接
- **WHEN** 30 秒内无新日志写入
- **THEN** SSE 连接保持，发送 keepalive 注释行（`: keepalive`）

#### Scenario: 从当前末尾开始推送
- **WHEN** 用户打开 Dashboard 页面
- **THEN** 仅推送页面打开后的新日志，不重放历史记录

### Requirement: 攻击统计展示
Dashboard 主页 SHALL 展示自 WAF 启动以来各攻击类型的拦截计数。

#### Scenario: 统计分类显示
- **WHEN** 用户访问 Dashboard 主页
- **THEN** 页面显示以下分类的拦截计数：sql-injection、xss、path-traversal、cmd-injection、file-upload、brute-force

#### Scenario: 计数实时更新
- **WHEN** 新的拦截事件通过 SSE 推送到前端
- **THEN** 对应攻击类型的计数器自动加一，无需刷新页面

### Requirement: 规则状态展示
Dashboard 主页 SHALL 展示当前 WAF 配置中各规则的启用/禁用状态。

#### Scenario: 规则状态列表
- **WHEN** 用户访问 Dashboard 主页
- **THEN** 页面显示所有规则名称及其 true/false 状态，启用显示为绿色 [ON]，禁用显示为红色 [OFF]

### Requirement: Dashboard 页面风格
Dashboard 页面 SHALL 使用与 shared/templates 一致的黑白线条风格，不依赖外部 CSS 框架。

#### Scenario: 页面样式一致性
- **WHEN** 用户访问 Dashboard 页面
- **THEN** 页面使用黑底白字、monospace 字体、直角边框，与应用主界面风格一致
```

## openspec/changes/waf-ui-redesign/specs/waf-proxy/spec.md

- Source: openspec/changes/waf-ui-redesign/specs/waf-proxy/spec.md
- Lines: 1-12
- SHA256: 32e77c78e02a4c706859b092689568a15fab46aeca000609e84882b5dd3c2bfd

```md
## ADDED Requirements

### Requirement: Dashboard 子服务共存
WAF 代理 SHALL 在启动时同时运行 Dashboard 子服务（:8081），两个服务共享同一 asyncio event loop 和配置对象。

#### Scenario: 双服务同时运行
- **WHEN** 执行 `python -m waf` 启动 WAF
- **THEN** :8080 代理服务和 :8081 Dashboard 服务均正常响应请求，互不干扰

#### Scenario: 启动日志输出
- **WHEN** WAF 启动成功
- **THEN** stderr 输出两行：代理监听信息和 Dashboard 监听信息
```

