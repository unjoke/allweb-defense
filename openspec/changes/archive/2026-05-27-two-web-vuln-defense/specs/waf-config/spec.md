## ADDED Requirements

### Requirement: YAML 配置文件加载
WAF 配置模块 SHALL 支持从 YAML 文件加载配置，文件路径可通过 `--config` 参数指定，默认读取 `waf/config.yaml`。

#### Scenario: 指定配置文件
- **WHEN** 执行时传入 `--config path/to/config.yaml`
- **THEN** 从指定路径读取配置，文件不存在时报错退出

#### Scenario: 默认配置文件
- **WHEN** 未传入 `--config` 且 `waf/config.yaml` 存在
- **THEN** 自动读取 `waf/config.yaml` 作为配置

### Requirement: 命令行参数优先覆盖
WAF 配置模块 SHALL 支持通过命令行参数覆盖配置文件中的对应字段，命令行参数优先级高于配置文件。

#### Scenario: 命令行覆盖端口
- **WHEN** 配置文件中 `listen_port: 8080`，同时传入 `--listen 9090`
- **THEN** 最终使用端口 9090

#### Scenario: 命令行覆盖后端地址
- **WHEN** 配置文件中 `backend_url: http://127.0.0.1:5000`，同时传入 `--backend http://127.0.0.1:6000`
- **THEN** 最终转发到 http://127.0.0.1:6000

### Requirement: 规则开关
WAF 配置 SHALL 支持对每项检测规则单独开启或关闭。

#### Scenario: 禁用某项规则
- **WHEN** 配置中 `rules.sql_injection: false` 或传入 `--disable sql_injection`
- **THEN** 代理跳过 SQL 注入检测，其他规则不受影响

### Requirement: 默认配置值
WAF 配置模块 SHALL 在未提供配置文件且未传入命令行参数时使用内置默认值。

#### Scenario: 使用默认值
- **WHEN** 未提供任何配置
- **THEN** 使用 `listen_port=8080`、`backend_url=http://127.0.0.1:5000`、所有规则开启、`rate_limit.max_failures=10`、`rate_limit.window=60`、`rate_limit.lockout=300`、`log_path=security.log`
