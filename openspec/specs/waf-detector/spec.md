## ADDED Requirements

### Requirement: 框架无关的检测函数
`waf/detector.py` SHALL 提供所有安全检测函数，不依赖任何 Web 框架，仅使用 Python 标准库和 `re` 模块。

#### Scenario: 无框架依赖导入
- **WHEN** 在非 Flask 环境中 `import waf.detector`
- **THEN** 导入成功，无 ImportError

### Requirement: SQL 注入检测
检测函数 SHALL 识别常见 SQL 注入特征字符串。

#### Scenario: 检测 UNION 注入
- **WHEN** 调用 `detect_sql_injection("' UNION SELECT * FROM users--")`
- **THEN** 返回 `True`

#### Scenario: 正常字符串不误报
- **WHEN** 调用 `detect_sql_injection("hello world")`
- **THEN** 返回 `False`

### Requirement: XSS 净化
净化函数 SHALL 对包含 XSS 特征的字符串进行 HTML 实体编码，对不含特征的字符串原样返回。

#### Scenario: 净化 script 标签
- **WHEN** 调用 `sanitize_xss("<script>alert(1)</script>")`
- **THEN** 返回不含原始 `<script>` 标签的净化字符串

#### Scenario: 正常字符串不修改
- **WHEN** 调用 `sanitize_xss("hello world")`
- **THEN** 返回 `"hello world"`

### Requirement: 路径穿越检测
检测函数 SHALL 识别 `../` 及其 URL 编码变体。

#### Scenario: 检测路径穿越
- **WHEN** 调用 `detect_path_traversal("../../etc/passwd")`
- **THEN** 返回 `True`

#### Scenario: 正常路径不误报
- **WHEN** 调用 `detect_path_traversal("messages/msg_1.txt")`
- **THEN** 返回 `False`

### Requirement: 命令注入检测
检测函数 SHALL 识别 shell 特殊字符（`;`、`&&`、`|`、`` ` ``、`$(`、`>`、`<`）。

#### Scenario: 检测分号注入
- **WHEN** 调用 `detect_cmd_injection("msg_1.txt; id")`
- **THEN** 返回 `True`

#### Scenario: 正常文件名不误报
- **WHEN** 调用 `detect_cmd_injection("msg_1_alice.txt")`
- **THEN** 返回 `False`

### Requirement: 文件扩展名白名单校验
校验函数 SHALL 仅允许 `.jpg`、`.jpeg`、`.png`、`.gif` 扩展名通过。

#### Scenario: 允许合法扩展名
- **WHEN** 调用 `is_allowed_extension("avatar.jpg")`
- **THEN** 返回 `True`

#### Scenario: 拒绝非法扩展名
- **WHEN** 调用 `is_allowed_extension("shell.py")`
- **THEN** 返回 `False`

### Requirement: IP 频率限制状态管理
频率限制函数 SHALL 基于传入的状态字典和配置字典管理 IP 锁定状态，不使用全局变量。

#### Scenario: 超阈值后锁定
- **WHEN** 同一 IP 调用 `record_login_failure` 超过 `config.max_failures` 次
- **THEN** `check_rate_limit` 对该 IP 返回 `True`（已锁定）

#### Scenario: 未超阈值不锁定
- **WHEN** 同一 IP 调用 `record_login_failure` 未超过阈值
- **THEN** `check_rate_limit` 对该 IP 返回 `False`
