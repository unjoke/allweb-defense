## ADDED Requirements

### Requirement: WAF 代理进程启动
WAF 代理 SHALL 作为独立进程启动，监听指定端口，将合法请求转发给配置的后端地址。

#### Scenario: 默认配置启动
- **WHEN** 执行 `python -m waf.proxy` 且存在 `waf/config.yaml`
- **THEN** 代理监听 config.yaml 中指定的端口，转发到 config.yaml 中指定的后端地址

#### Scenario: 命令行参数启动
- **WHEN** 执行 `python -m waf.proxy --listen 8080 --backend http://127.0.0.1:5000`
- **THEN** 代理监听 8080 端口，转发到 http://127.0.0.1:5000

### Requirement: 请求检测与拦截
WAF 代理 SHALL 在转发请求前对所有入站请求执行安全检测，检测到攻击时返回对应错误码并记录日志，不转发给后端。

#### Scenario: SQL 注入拦截
- **WHEN** 请求的 GET 或 POST 参数中包含 SQL 注入特征字符串
- **THEN** 代理返回 403，不转发请求，写入 security.log

#### Scenario: 路径穿越拦截
- **WHEN** 请求参数中包含 `../` 或其编码变体
- **THEN** 代理返回 403，不转发请求，写入 security.log

#### Scenario: 命令注入拦截
- **WHEN** 请求参数中包含 shell 特殊字符（`;`、`&&`、`|`、`` ` ``、`$(`）
- **THEN** 代理返回 403，不转发请求，写入 security.log

#### Scenario: 非法文件扩展名拦截
- **WHEN** 上传文件的扩展名不在白名单（`.jpg`、`.jpeg`、`.png`、`.gif`）内
- **THEN** 代理返回 400，不转发请求，写入 security.log

#### Scenario: 频率限制拦截
- **WHEN** 同一 IP 在时间窗口内登录失败次数超过阈值
- **THEN** 代理返回 429，不转发请求，写入 security.log

#### Scenario: 频率限制基于请求次数而非后端认证结果
- **WHEN** 同一 IP 对 `/login` 路径发送 POST 请求超过阈值次数
- **THEN** 代理返回 429，不区分后端认证是否成功（代理层无法感知后端认证结果）

### Requirement: XSS 净化转发
WAF 代理 SHALL 对包含 XSS 特征的参数值进行 HTML 实体编码净化，净化后继续转发请求（不拦截）。

#### Scenario: XSS 净化
- **WHEN** 请求参数中包含 `<script>`、`javascript:` 或 `on*=` 等 XSS 特征
- **THEN** 代理将该参数值 HTML 实体编码后转发给后端，写入 security.log

### Requirement: 安全响应头注入
WAF 代理 SHALL 在所有后端响应中注入安全响应头后再返回给客户端。

#### Scenario: 安全头注入
- **WHEN** 后端返回任意 HTTP 响应
- **THEN** 代理在响应中添加 `Content-Security-Policy`、`X-Frame-Options`、`X-Content-Type-Options`、`X-XSS-Protection`、`Referrer-Policy` 头

### Requirement: 请求透明转发
WAF 代理 SHALL 对通过检测的请求保持原始 method、headers 和 body 不变地转发给后端。

#### Scenario: 合法请求转发
- **WHEN** 请求通过所有安全检测
- **THEN** 代理将原始请求（含 method、headers、body）转发给后端，将后端响应原样返回给客户端

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
