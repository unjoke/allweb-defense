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
