## ADDED Requirements

### Requirement: URL 维度规则词汇表

WAF SHALL 在 URL 规则文件中只接受以下 detection token：`SQL`、`XSS`、`PATH`、`CMD`、`UPLOAD`，对应到 WAF 代理层既有的检测：SQL 注入、XSS 净化、路径穿越、命令注入、文件上传校验（含扩展名白名单与 magic bytes）。

#### Scenario: 合法 token
- **WHEN** URL 规则中 `detect: [SQL, XSS, PATH, CMD, UPLOAD]`
- **THEN** 加载成功，匹配该 URL 时这五项检测均启用（受全局开关与匹配语义约束）

#### Scenario: 非法 token RATE / CSRF
- **WHEN** URL 规则中 `detect: [RATE]` 或 `detect: [CSRF]`
- **THEN** 加载失败并退出，错误信息说明 `RATE` 与 `CSRF` 不在 URL 规则词汇表中

#### Scenario: token 大小写敏感
- **WHEN** URL 规则中 `detect: [sql]`（小写）或 `detect: [Sql]`（混合大小写）
- **THEN** 加载失败并退出，错误信息提示合法 token 仅限大写 `SQL / XSS / PATH / CMD / UPLOAD`

### Requirement: URL 匹配语法

WAF URL 规则匹配 SHALL 仅支持两种语法：

- **精确匹配**：`url` 不含 `*`，仅当请求路径与该字符串严格相等时命中
- **前缀通配符**：`url` 以 `/*` 结尾，匹配 URL 前缀部分（不含 `*`）后跟随 `/` 或本身就等于该前缀去掉 `/*` 后再加 `/` 的路径；其中 `/*` 单独使用为全匹配兜底

#### Scenario: 精确匹配
- **WHEN** URL 规则 `url: /login`，请求路径为 `/login`
- **THEN** 命中

#### Scenario: 精确匹配不命中尾随 slash
- **WHEN** URL 规则 `url: /login`，请求路径为 `/login/`
- **THEN** 不命中

#### Scenario: 前缀通配符命中子路径
- **WHEN** URL 规则 `url: /api/*`，请求路径为 `/api/foo` 或 `/api/foo/bar`
- **THEN** 命中

#### Scenario: 前缀通配符要求斜杠分段
- **WHEN** URL 规则 `url: /api/*`，请求路径为 `/apifoo` 或 `/api`
- **THEN** 不命中

#### Scenario: 兜底全匹配
- **WHEN** URL 规则 `url: /*`，请求路径为任意非空路径
- **THEN** 命中

#### Scenario: 匹配输入为已解码 path
- **WHEN** 请求 URL 含 `%2F`（编码的 `/`），如 `/api%2Fadmin`，aiohttp `request.path` 解码后为 `/api/admin`
- **THEN** URL 规则 `/api/*` 命中（按解码后路径生效），规则文件中的 URL 应针对解码后形态编写

### Requirement: URL 规则匹配策略

WAF SHALL 按 URL 规则文件中条目从上到下的顺序进行匹配，**首个命中的规则胜出**；后续规则即使也能匹配同一路径亦不参与决策。

#### Scenario: 上方规则优先
- **WHEN** URL 规则文件依次为 `/api/admin/* → [SQL]` 与 `/api/* → [SQL, XSS]`，请求路径为 `/api/admin/users`
- **THEN** 命中第一条，仅启用 `SQL`

#### Scenario: 都不命中走默认
- **WHEN** URL 规则文件中所有条目均不匹配请求路径
- **THEN** 该路径上所有 `SQL/XSS/PATH/CMD/UPLOAD` 检测保持启用（受全局开关上限约束）

### Requirement: Effective 规则计算

WAF SHALL 以 `effective(path, rule) = global_rules[rule] AND (no_url_rule_match(path) OR rule ∈ first_match.detect)` 来决定 `path` 上是否运行某项检测。其中 `global_rules` 来自 `waf/config.yaml::rules.*`，`rule` 取值为 `sql_injection / xss / path_traversal / cmd_injection / file_upload`（由 URL 规则中的 token `SQL / XSS / PATH / CMD / UPLOAD` 一一映射）。

#### Scenario: URL 规则未命中、全局开启
- **WHEN** 全局 `rules.sql_injection: true`，URL 规则文件中无任何 URL 命中当前路径
- **THEN** SQL 注入检测在该路径上启用

#### Scenario: URL 规则命中但未列出该 rule
- **WHEN** 全局 `rules.sql_injection: true`，URL 规则首个命中条目为 `detect: [XSS]`
- **THEN** SQL 注入检测在该路径上**不**启用（被 URL 规则裁掉），XSS 启用

#### Scenario: URL 规则命中且列出该 rule，但全局已关
- **WHEN** 全局 `rules.xss: false`，URL 规则首个命中条目为 `detect: [XSS]`
- **THEN** XSS 检测在该路径上**不**启用（受全局上限约束），且不阻止其它规则继续按效力评估

#### Scenario: 未配置 URL 规则文件 → 完全等价于现有行为
- **WHEN** `config["url_rules"]` 为 `None`
- **THEN** 任意路径上 `effective(path, rule) == global_rules[rule]`，与未引入本变更前的行为一致

### Requirement: URL 规则不影响 RATE 与 security_headers

URL 规则 SHALL 仅作用于词汇表内的五项检测（`sql_injection`、`xss`、`path_traversal`、`cmd_injection`、`file_upload`）。速率限制（`rate_limit`）与安全响应头注入（`security_headers`）SHALL 始终按 `waf/config.yaml::rules.*` 的全局开关行为，不受 URL 规则裁剪。

#### Scenario: URL 规则不裁剪 RATE
- **WHEN** url_rules 中 `/login` 命中且 `detect: [SQL]`，全局 `rules.rate_limit: true`
- **THEN** POST `/login` 仍触发速率限制（与未配置 url_rules 时行为一致）

#### Scenario: URL 规则不裁剪 security_headers
- **WHEN** url_rules 中 `/foo` 命中且 `detect: [SQL]`，全局 `rules.security_headers: true`
- **THEN** `/foo` 的响应仍注入 CSP / X-Frame-Options 等安全头
