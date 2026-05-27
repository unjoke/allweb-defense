# Comet Design Handoff

- Change: two-web-vuln-defense
- Phase: design
- Mode: compact
- Context hash: b8d881fac6f5f22db0050ee40c8ce294ef0506873ffacb4d30041bb41c72e5e7

Generated-by: comet-handoff.sh

OpenSpec remains the canonical capability spec. This handoff is a deterministic, source-traceable context pack, not an agent-authored summary.

## openspec/changes/two-web-vuln-defense/proposal.md

- Source: openspec/changes/two-web-vuln-defense/proposal.md
- Lines: 1-30
- SHA256: 8a62450a3c00bd4909ba56f44218fc2267bb098910625cb57d71963f38a1c1d7

```md
## Why

现有通防中间件（`app/protected/middleware.py`）通过 Flask `before_request` 钩子绑定在留言系统上，与业务代码耦合，无法保护其他语言或框架编写的后端。本 change 将通防能力提取为独立的反向代理进程，实现语言无关的通用 WAF，同时保留原有 Flask 内嵌通防作为对比演示。

## What Changes

- 新增 `waf/` 目录，实现基于 `aiohttp` 的异步反向代理 WAF 进程
- 新增 `waf/detector.py`，从 `middleware.py` 提取所有纯检测函数，去除 Flask 依赖
- 新增 `waf/config.py`，支持命令行参数与 YAML 配置文件两种方式，命令行优先
- 新增 `waf/config.yaml`，提供默认配置（监听端口、后端地址、规则开关、频率限制参数）
- 新增 `tests/test_detector.py`，对 `detector.py` 中的纯函数进行单元测试
- 更新 `requirements.txt`，新增 `aiohttp==3.9.5` 和 `pyyaml==6.0.2`

## Capabilities

### New Capabilities

- `waf-proxy`: 独立反向代理 WAF 进程，监听可配置端口，对所有入站请求执行安全检测后转发给后端；支持 SQL 注入、XSS、路径穿越、命令注入、文件上传、频率限制检测，以及安全响应头注入
- `waf-config`: WAF 配置加载模块，支持 YAML 文件与命令行参数混合配置，命令行参数优先覆盖文件配置
- `waf-detector`: 框架无关的安全检测函数库，所有函数无副作用，可独立单元测试

### Modified Capabilities

## Impact

- 新增依赖：`aiohttp==3.9.5`、`pyyaml==6.0.2`
- `app/protected/middleware.py` 保留不动，作为"Flask 内嵌通防"演示
- `app/vulnerable/app.py`（端口 5000）无需改动，直接作为 WAF 代理的后端目标
- 攻击演示脚本可改为打 WAF 代理端口（8080），验证代理层拦截效果
- 课设报告新增"绑定式通防 vs 代理式通防"对比章节
```

## openspec/changes/two-web-vuln-defense/design.md

- Source: openspec/changes/two-web-vuln-defense/design.md
- Lines: 1-58
- SHA256: 7f5d86af8d1de3bbdf7c7db1249b61b728fefdfe9804cfa53f61879eccf6a581

```md
## Context

当前项目（`web-vuln-defense`）已实现一个留言管理系统，分漏洞版（端口 5000）和防护版（端口 5001）。防护版通过 Flask `before_request` / `after_request` 钩子加载通防中间件（`app/protected/middleware.py`），中间件与 Flask app 耦合，无法保护非 Python/Flask 后端。

本 change 在现有项目基础上新增 `waf/` 目录，实现一个独立的反向代理 WAF 进程，将通防能力从 Flask 解耦，使其可以保护任意语言编写的 HTTP 后端。

## Goals / Non-Goals

**Goals:**
- 实现独立的异步反向代理 WAF 进程，监听可配置端口
- 支持命令行参数与 YAML 配置文件混合配置，命令行优先
- 复用现有检测逻辑（SQL 注入、XSS、路径穿越、命令注入、文件上传、频率限制）
- 对后端完全透明，不要求后端做任何改动
- 提供与现有 Flask 内嵌通防的对比演示场景

**Non-Goals:**
- 不实现 HTTPS 终止
- 不实现 CSRF 防护（代理层无法感知后端 session 状态）
- 不实现多进程共享的频率限制状态
- 不实现机器学习检测或流量镜像
- 不部署到公网

## Decisions

**决策1：使用 aiohttp 实现异步反向代理**
- 理由：aiohttp 同时提供 HTTP 服务器和客户端，单库完成代理所需的收发两端；异步模型适合 I/O 密集的代理场景；依赖轻量，课设环境易安装
- 备选：Flask + requests（同步，性能差）；httpx + uvicorn（依赖更多）；mitmproxy（重依赖，报告难讲清自己写了什么）

**决策2：detector.py 从 middleware.py 提取纯函数，去除 Flask 依赖**
- 理由：检测逻辑本身不依赖 Flask，提取后可在代理层和 Flask 层复用，也便于独立单元测试
- 备选：直接在 proxy.py 中重写检测逻辑（代码重复，维护成本高）

**决策3：命令行参数优先于 YAML 配置文件**
- 理由：符合 Unix 惯例（环境变量/命令行覆盖配置文件），便于在不修改配置文件的情况下临时调整参数
- 实现：argparse 解析命令行，PyYAML 读取配置文件，命令行非 None 值覆盖文件值

**决策4：XSS 在代理层净化而非拦截**
- 理由：与 middleware.py 保持一致的处理策略；净化后转发可让后端正常处理业务逻辑，而不是直接返回 403
- 风险：净化后的值与原始值不同，极少数情况下可能影响后端业务逻辑（已列入局限性）

**决策5：CSRF 防护在代理层关闭**
- 理由：CSRF Token 的生成和校验依赖 session 状态，无状态代理无法独立完成；强行实现需要代理与后端共享 session，超出通用代理的职责范围
- 报告价值：这是通防局限性的典型案例，可在报告中专门讨论

## Risks / Trade-offs

- **正则检测可被编码绕过** → 报告中诚实讨论，作为通防局限性章节内容
- **XSS 净化修改了请求参数** → 后端收到净化后的值，极少数情况下可能影响业务逻辑；课设场景下可接受
- **频率限制状态存于内存** → 多进程部署时状态不共享；单进程课设场景下无影响
- **aiohttp 版本兼容性** → 固定 `aiohttp==3.9.5` 避免 API 变动

## Migration Plan

无需迁移。新增 `waf/` 目录，不修改现有任何文件。安装新依赖后即可独立启动 WAF 代理进程。

## Open Questions

无。
```

## openspec/changes/two-web-vuln-defense/tasks.md

- Source: openspec/changes/two-web-vuln-defense/tasks.md
- Lines: 1-44
- SHA256: 60e7c4ed1b0102e941c3481da4bed4f6bfea8d3e7db1bd9f2038ce7da1630054

```md
## 1. 依赖与目录结构

- [ ] 1.1 在 `requirements.txt` 中新增 `aiohttp==3.9.5` 和 `pyyaml==6.0.2`
- [ ] 1.2 创建 `waf/` 目录，添加 `waf/__init__.py`（空文件）

## 2. waf/detector.py — 框架无关检测函数库

- [ ] 2.1 从 `app/protected/middleware.py` 提取 `detect_sql_injection`、`sanitize_xss`、`detect_path_traversal`、`detect_cmd_injection`、`is_allowed_extension` 五个纯函数，去除所有 Flask 导入，写入 `waf/detector.py`
- [ ] 2.2 将频率限制函数 `check_rate_limit` 和 `record_login_failure` 改写为接受外部 `state: dict` 和 `config: dict` 参数（不使用全局变量），写入 `waf/detector.py`
- [ ] 2.3 验证 `import waf.detector` 在无 Flask 环境下成功

## 3. waf/config.py — 配置加载模块

- [ ] 3.1 实现 `load_config(args) -> dict`：先读取 YAML 文件（`--config` 指定路径或默认 `waf/config.yaml`），再用命令行非 None 参数覆盖对应字段，返回合并后的配置字典
- [ ] 3.2 实现 `build_arg_parser() -> ArgumentParser`：定义 `--listen`、`--backend`、`--config`、`--disable` 参数
- [ ] 3.3 编写 `waf/config.yaml` 默认配置文件，包含 `listen_port`、`backend_url`、`rules`（各规则开关）、`rate_limit`（`max_failures`、`window`、`lockout`）、`log_path`

## 4. waf/proxy.py — 异步反向代理主入口

- [ ] 4.1 实现请求处理函数 `handle_request(request, config, state, logger)`：提取 GET 参数、POST 表单、上传文件名，依次调用 detector 函数，命中则返回对应错误响应并记录日志
- [ ] 4.2 实现 XSS 净化逻辑：对 GET/POST 参数值调用 `sanitize_xss`，将净化后的值写入转发请求
- [ ] 4.3 实现请求转发：使用 `aiohttp.ClientSession` 将通过检测的请求（保留原始 method、headers、body）转发给后端，替换 Host header
- [ ] 4.4 实现响应处理：将后端响应注入安全响应头（CSP、X-Frame-Options、X-Content-Type-Options、X-XSS-Protection、Referrer-Policy）后返回给客户端
- [ ] 4.5 实现 `main()` 入口：解析参数，加载配置，初始化 aiohttp web.Application，启动服务器
- [ ] 4.6 添加 `waf/__main__.py`，使 `python -m waf.proxy` 可直接启动

## 5. tests/test_detector.py — 单元测试

- [ ] 5.1 为 `detect_sql_injection` 编写正例（UNION 注入、OR 注入）和反例（正常字符串）测试用例
- [ ] 5.2 为 `sanitize_xss` 编写正例（script 标签、javascript: 协议、on* 事件）和反例测试用例
- [ ] 5.3 为 `detect_path_traversal` 编写正例（`../`、URL 编码变体）和反例测试用例
- [ ] 5.4 为 `detect_cmd_injection` 编写正例（`;`、`&&`、`|`）和反例测试用例
- [ ] 5.5 为 `is_allowed_extension` 编写白名单内和白名单外的测试用例
- [ ] 5.6 为频率限制函数编写超阈值锁定和未超阈值不锁定的测试用例
- [ ] 5.7 运行 `pytest tests/test_detector.py`，确认全部通过

## 6. 集成验证

- [ ] 6.1 安装新依赖：`pip install aiohttp==3.9.5 pyyaml==6.0.2`
- [ ] 6.2 启动漏洞版后端（端口 5000），启动 WAF 代理（端口 8080，后端指向 5000）
- [ ] 6.3 对 8080 端口重放 SQL 注入、路径穿越、命令注入攻击，验证均返回 403 并写入 security.log
- [ ] 6.4 对 8080 端口重放 XSS payload，验证参数被净化后转发
- [ ] 6.5 验证正常业务请求（登录、留言、搜索）通过代理后功能正常
- [ ] 6.6 验证所有响应包含安全响应头
```

## openspec/changes/two-web-vuln-defense/specs/waf-config/spec.md

- Source: openspec/changes/two-web-vuln-defense/specs/waf-config/spec.md
- Lines: 1-37
- SHA256: eac1e611ed3c7a655e17e714316621b95a2b9e1f8d3465a183110cc8198ff53c

```md
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
```

## openspec/changes/two-web-vuln-defense/specs/waf-detector/spec.md

- Source: openspec/changes/two-web-vuln-defense/specs/waf-detector/spec.md
- Lines: 1-74
- SHA256: a4e32f660c3f1e3d7cc529e1c78bf4ec56519c4f055b4eb4ea6b415f30090bd7

```md
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
```

## openspec/changes/two-web-vuln-defense/specs/waf-proxy/spec.md

- Source: openspec/changes/two-web-vuln-defense/specs/waf-proxy/spec.md
- Lines: 1-60
- SHA256: 4efe69d9a45835abc31e14965d63565f943af56d6ceb335e8bfe44dc4d36ba40

```md
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
```

