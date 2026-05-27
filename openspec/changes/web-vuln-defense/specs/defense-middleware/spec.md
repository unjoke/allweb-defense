## ADDED Requirements

### Requirement: 输入检测拦截 SQL 注入
中间件 SHALL 在每个请求的 GET 参数、POST 表单数据中检测 SQL 注入关键字模式（`OR`、`UNION`、`SELECT`、`DROP`、`INSERT`、`--`、`'` 等组合），命中时返回 403 并记录日志。

#### Scenario: SQL 注入请求被拦截
- **WHEN** 请求参数包含 `' OR '1'='1`
- **THEN** 中间件返回 HTTP 403，业务逻辑不执行，日志记录攻击类型和来源 IP

### Requirement: 输入检测拦截 XSS
中间件 SHALL 检测请求参数中的 XSS 模式（`<script>`、`javascript:`、`on*=` 事件属性、`<img`、`<iframe` 等），命中时对输入进行 HTML 实体编码后传递。

#### Scenario: XSS payload 被净化
- **WHEN** 请求参数包含 `<script>alert(1)</script>`
- **THEN** 中间件将其转义为 `&lt;script&gt;alert(1)&lt;/script&gt;` 后传递，页面不执行脚本

### Requirement: 路径穿越检测
中间件 SHALL 检测请求参数中包含 `../` 或 `..\` 的路径穿越序列，命中时返回 403。

#### Scenario: 路径穿越请求被拦截
- **WHEN** 请求参数包含 `../../app.py`
- **THEN** 中间件返回 HTTP 403，文件不被读取

### Requirement: CSRF Token 验证
中间件 SHALL 对所有 POST 请求验证 CSRF Token，Token 存储于用户 session，表单中通过隐藏字段提交，不匹配时返回 403。

#### Scenario: 缺少 CSRF Token 的 POST 请求被拒绝
- **WHEN** POST 请求未携带有效 CSRF Token
- **THEN** 中间件返回 HTTP 403，操作不执行

### Requirement: 越权访问控制
中间件 SHALL 维护一张路由权限表，对每个请求校验 session 中的用户角色是否有权访问该路由，普通用户访问 admin 路由时返回 403。

#### Scenario: 普通用户访问 admin 路由被拦截
- **WHEN** session 中角色为 user 的用户请求 `/admin/*` 路径
- **THEN** 中间件返回 HTTP 403，不执行 admin 业务逻辑

#### Scenario: 水平越权操作被拦截
- **WHEN** 用户 A 请求操作属于用户 B 的资源（msg_id 不属于当前用户）
- **THEN** 中间件返回 HTTP 403

### Requirement: 文件上传类型校验
中间件 SHALL 对文件上传请求校验文件扩展名，仅允许白名单扩展名（`.jpg`、`.jpeg`、`.png`、`.gif`），其他扩展名返回 400。

#### Scenario: 上传非法扩展名文件被拒绝
- **WHEN** 用户上传扩展名为 `.py` 或 `.php` 的文件
- **THEN** 中间件返回 HTTP 400，文件不被保存

### Requirement: 命令注入检测
中间件 SHALL 检测请求参数中包含 shell 特殊字符（`&`、`|`、`;`、`` ` ``、`$(`、`>`、`<`）的命令注入模式，命中时返回 403。

#### Scenario: 命令注入 payload 被拦截
- **WHEN** ping 工具输入框提交 `127.0.0.1 && whoami`
- **THEN** 中间件返回 HTTP 403，系统命令不执行

### Requirement: 登录频率限制
中间件 SHALL 对同一 IP 的登录请求进行频率限制，60 秒内超过 10 次失败尝试时返回 429 并锁定 5 分钟。

#### Scenario: 暴力破解触发频率限制
- **WHEN** 同一 IP 在 60 秒内发送超过 10 次登录失败请求
- **THEN** 中间件返回 HTTP 429，后续请求在锁定期内直接拒绝

### Requirement: 安全响应头注入
中间件 SHALL 在每个响应中添加安全头：`Content-Security-Policy: default-src 'self'`、`X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff`、`X-XSS-Protection: 1; mode=block`，并关闭 Flask 调试模式以防止敏感信息泄露。

#### Scenario: 响应包含安全头
- **WHEN** 任意请求得到响应
- **THEN** 响应头包含上述全部安全字段

### Requirement: 拦截日志记录
中间件 SHALL 将每次拦截事件记录到 `security.log`，包含时间戳、来源 IP、请求路径、攻击类型、原始 payload（截断至 200 字符）。

#### Scenario: 拦截事件写入日志
- **WHEN** 中间件拦截一次攻击请求
- **THEN** security.log 新增一条包含上述字段的记录
