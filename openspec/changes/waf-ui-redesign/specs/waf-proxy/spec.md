## ADDED Requirements

### Requirement: Dashboard 子服务共存
WAF 代理 SHALL 在启动时同时运行 Dashboard 子服务（:8081），两个服务共享同一 asyncio event loop 和配置对象。

#### Scenario: 双服务同时运行
- **WHEN** 执行 `python -m waf` 启动 WAF
- **THEN** :8080 代理服务和 :8081 Dashboard 服务均正常响应请求，互不干扰

#### Scenario: 启动日志输出
- **WHEN** WAF 启动成功
- **THEN** stderr 输出两行：代理监听信息和 Dashboard 监听信息

### Requirement: 拦截响应使用主题样式
WAF 代理拦截请求并返回 403 或 429 时 SHALL 渲染 `shared/templates/403.html` 或 `shared/templates/429.html`，使用与应用主界面一致的黑白线条风格，而不是返回 plain text。

#### Scenario: 403 拦截返回样式化页面
- **WHEN** WAF 拦截一个攻击请求（SQL 注入、路径穿越、命令注入、非法上传）
- **THEN** 响应 Content-Type 为 `text/html`，body 包含 `403`、`FORBIDDEN`、`WAF-DEMO` 品牌标识，无 Bootstrap CDN 引用

#### Scenario: 429 限速返回样式化页面
- **WHEN** WAF 限速拦截一个登录请求
- **THEN** 响应 Content-Type 为 `text/html`，body 包含 `429`、`TOO MANY REQUESTS`、`WAF-DEMO` 品牌标识

