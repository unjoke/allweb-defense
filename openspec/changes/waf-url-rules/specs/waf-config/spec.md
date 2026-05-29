## ADDED Requirements

### Requirement: URL 规则文件路径配置

WAF 配置模块 SHALL 支持指定一个独立的 URL 规则文件路径。该路径可通过命令行 `--url-rules <path>` 指定，亦可通过 `waf/config.yaml::url_rules_file` 字段指定，前者优先于后者；二者皆未提供时不加载任何 URL 规则。

#### Scenario: CLI 指定 URL 规则文件
- **WHEN** 启动时传入 `--url-rules path/to/url_rules.yaml`
- **THEN** 配置中 `url_rules` 由该路径加载得到的 matcher 对象填充

#### Scenario: 配置文件中指定 URL 规则文件
- **WHEN** `waf/config.yaml` 中包含 `url_rules_file: path/to/url_rules.yaml` 且未传 `--url-rules`
- **THEN** 配置中 `url_rules` 由该路径加载得到的 matcher 对象填充

#### Scenario: CLI 优先于配置文件
- **WHEN** 配置文件中 `url_rules_file: a.yaml` 与 CLI `--url-rules b.yaml` 同时存在
- **THEN** 加载 `b.yaml`，忽略 `a.yaml`

#### Scenario: 未提供 URL 规则文件
- **WHEN** 既未传 `--url-rules` 也未在配置文件中设置 `url_rules_file`
- **THEN** 配置中 `url_rules` 为 `None`，运行时所有路径上的所有检测保持全开（受全局 `rules.*` 开关上限约束）

#### Scenario: 显式指定但文件不存在
- **WHEN** 传入 `--url-rules /missing.yaml` 但该文件不存在
- **THEN** 报错并退出（与 `--config` 显式指定但缺失时一致）

### Requirement: URL 规则文件 Strict 加载

WAF 配置模块 SHALL 在加载 URL 规则文件时执行严格校验。任一以下情况发生时 SHALL 终止启动并以非零退出码退出，并向 stderr 打印含位置（条目索引或字段名）的错误信息：

- YAML 解析失败
- 顶层不是映射或缺少 `rules` 键，或 `rules` 不是序列
- 任一条目缺少 `url` 或 `detect` 字段
- 条目出现未声明的字段
- `url` 不以 `/` 开头，或 `*` 通配符不在尾部
- `detect` 中出现未知 token（合法 token 仅限 `SQL`、`XSS`、`PATH`、`CMD`、`UPLOAD`，大小写敏感）
- `detect` 是空列表（`[]`）
- 同一 `url` 字面量出现在多条规则中

#### Scenario: YAML 解析错
- **WHEN** URL 规则文件含语法错误（例如不闭合的引号）
- **THEN** 报错并以非零退出码退出，stderr 包含文件路径

#### Scenario: 未知 detect token
- **WHEN** URL 规则文件中包含 `detect: [SQL, FOO]`
- **THEN** 报错退出，错误信息提示 `FOO` 不是合法的 detection 类型并列出合法值

#### Scenario: url 通配符位置非法
- **WHEN** URL 规则文件中包含 `url: /api/*/admin`
- **THEN** 报错退出，错误信息提示 `*` 必须出现在末尾

#### Scenario: 重复 URL
- **WHEN** URL 规则文件中两条规则的 `url` 相同（如均为 `/search`）
- **THEN** 报错退出，错误信息指出重复的 URL 字面量

#### Scenario: 未知字段
- **WHEN** URL 规则文件条目中出现 `method: POST` 这类未声明字段
- **THEN** 报错退出，错误信息列出该条目允许的字段集合

#### Scenario: 空 detect 列表
- **WHEN** URL 规则文件中某条目为 `detect: []`
- **THEN** 报错退出，错误信息提示该条目 `detect` 不能为空

### Requirement: URL 规则与全局开关的告警

WAF 配置模块 SHALL 在 URL 规则加载完成后，扫描各条 `detect` token 与全局 `rules.*` 开关的对应关系；若某条规则中的 token 对应的全局开关为 `false`，SHALL 向 stderr 打印一条 warning，但不阻止启动。

#### Scenario: URL 规则启用了被全局关闭的检测
- **WHEN** 全局 `rules.xss: false`，URL 规则中存在 `detect: [XSS, SQL]`
- **THEN** 启动成功，stderr 出现一条警告，提示该 URL 规则的 `XSS` 不会生效（被全局关闭）
