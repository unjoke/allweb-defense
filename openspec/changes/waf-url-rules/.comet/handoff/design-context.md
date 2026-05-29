# Comet Design Handoff

- Change: waf-url-rules
- Phase: design
- Mode: compact
- Context hash: d8030bc403904b64f42c9ee12540ea7e7f4971d4f5bc548fc7619d751776182e

Generated-by: comet-handoff.sh

OpenSpec remains the canonical capability spec. This handoff is a deterministic, source-traceable context pack, not an agent-authored summary.

## openspec/changes/waf-url-rules/proposal.md

- Source: openspec/changes/waf-url-rules/proposal.md
- Lines: 1-62
- SHA256: 48a254f8d19a6695360c859eaac1bfdf7f6acba4fdd3636a21a8cd56ffd1427d

```md
## Why

WAF 当前的检测规则只有全局开关（`waf/config.yaml::rules.{sql_injection,xss,path_traversal,cmd_injection,file_upload,...}`），无法表达「只对 `/search` 跑 SQL+XSS、只对 `/upload/*` 跑 UPLOAD+PATH」这类按 URL 收紧的需求。引入一个独立的 URL 规则文件填补这个能力空缺，让用户在不放弃全局兜底的前提下，按路由裁剪检测面，既减少误报又减少不必要的扫描开销。

## What Changes

- 新增独立 URL 规则文件（YAML），按 URL 列出该路由要启用的检测类型；与 `waf/config.yaml` 解耦
- 文件示例（顶部以注释列出全部支持词汇）：

  ```yaml
  # WAF URL rule file
  # Supported detection types: SQL, XSS, PATH, CMD, UPLOAD
  # URL match: exact (/login) or prefix-wildcard (/api/*)
  # Match policy: first match wins (top-to-bottom)
  # Unmatched URLs: all detections enabled (subject to global toggles)
  # Global toggles in waf/config.yaml are an upper bound — what's off there
  # cannot be re-enabled here.
  rules:
    - url: /search
      detect: [XSS, SQL]
    - url: /upload/*
      detect: [UPLOAD, PATH]
  ```

- URL 匹配：精确匹配（如 `/login`）+ 前缀通配符（如 `/api/*` 要求斜杠分段；`/*` 为全匹配兜底）；不引入正则
- 匹配策略：**首个命中胜出**（按文件中从上到下的顺序，nginx-style）
- 命中行为：**未命中** 时全部检测保持开启（向后兼容）；**命中** 时只跑该 URL 的 `detect` 列表
- 全局上限：`waf/config.yaml` 中关闭的检测，URL 规则无法重新启用，等价于
  `effective(url, rule) = global[rule] AND (no_match(url) OR rule ∈ matched.detect)`
- 支持词汇表：`SQL`、`XSS`、`PATH`、`CMD`、`UPLOAD`（仅 WAF 代理层确实在做的检测）
- 加载策略：**Strict** —— YAML 解析错 / 未知 detect token / 未知字段 / 重复 URL → 启动报错并退出
- 配置入口：CLI `--url-rules <path>` 与 `waf/config.yaml::url_rules_file` 并存，CLI 优先；两者都未提供 → 不加载（保持全开 default）；显式指定但文件不存在 → 报错退出（与 `--config` 行为一致）
- 提供示例规则文件 `waf/url_rules.example.yaml` 与单元测试

### Non-Goals

- 不引入正则匹配
- 不做规则热重载（仅启动时加载）
- 不引入 HTTP method 维度过滤（仅 URL）
- 不替换现有 `waf/config.yaml`
- 不在 WAF 层补 CSRF 验证逻辑（CSRF 仍由 `app/protected/middleware.py` 负责）
- 不修改现有的 `rate_limit` / `security_headers` 行为（仍按全局开关；`RATE` 因仅作用于 `login_path` 不纳入 URL 规则词汇）

## Capabilities

### New Capabilities

（无）

### Modified Capabilities

- `waf-config`: ADD `--url-rules` CLI flag 与 `url_rules_file` 配置项；定义 Strict 加载语义、CLI vs YAML 优先级、默认行为
- `waf-detector`: ADD URL 维度规则语义 —— 词汇表（SQL/XSS/PATH/CMD/UPLOAD）、匹配语法（精确 + 前缀通配符）、匹配策略（首个命中胜出）、effective 公式（global AND url）

## Impact

- 代码：新增 `waf/url_rules.py`（loader + matcher）；修改 `waf/config.py`（CLI flag + 配置键）；修改 `waf/proxy.py::handle_request`（用 `effective_for(path, rule)` 替换原 `rules.get(rule, True)`）
- 配置：`waf/config.yaml` 新增可选 `url_rules_file` 键；新增 `waf/url_rules.example.yaml` 示例
- 测试：新增 `tests/test_url_rules.py`（loader、matcher、global-cap、strict-error）；现有 `tests/test_proxy*.py` 在不指定 URL 规则时行为应保持不变（向后兼容验证）
- 依赖：复用现有 `PyYAML`，无新增依赖
- 文档：在 `README.md` / 配置说明里补充 URL 规则文件的格式与用法
- 向后兼容：未提供 URL 规则文件时与当前行为完全一致；提供后只可能让某些 URL 的检测**更严**（被裁剪）或保持原状，不会让任何 URL 的检测**变宽松**（受全局上限保护）
```

## openspec/changes/waf-url-rules/design.md

- Source: openspec/changes/waf-url-rules/design.md
- Lines: 1-131
- SHA256: 366fd92a7f1bbccaa4e89cad0987f70a500283210bf0a0e6fc6a05905d4700a8

[TRUNCATED]

```md
## Context

WAF 反向代理（`waf/proxy.py`）通过 `waf/config.yaml::rules.{sql_injection, xss, path_traversal, cmd_injection, file_upload, rate_limit, security_headers}` 这一组扁平的全局开关来控制各检测函数是否生效。`handle_request` 在每个请求里逐个 `if rules.get("X", True): detect_X(...)`。这种粒度无法表达「同样开启 SQL 检测，但只在 `/search` 路由跑」之类的需求 —— 现实里 `/search` 之外的路由可能完全不需要 SQL 检测，开着只徒增误报与开销。

现有相关代码：
- `waf/config.py::load_config` —— 解析 CLI + YAML，输出含 `rules` 字典的扁平 config
- `waf/proxy.py::handle_request` —— 对每个请求按 `rules.get("X", True)` 分派检测
- `waf/detector.py` —— 五个检测原语（SQL/XSS/PATH/CMD/UPLOAD）+ 两个不在 URL 规则范围里的（rate_limit, magic_bytes 是 UPLOAD 的子步骤）

约束：
- 必须**向后兼容**：未提供 URL 规则文件时行为与当前完全一致
- 必须保持 `waf/config.yaml` 全局开关作为「上限」（global mask）
- 不引入正则、不引入热重载、不引入 method 维度

## Goals / Non-Goals

**Goals:**
- 让用户用一份独立 YAML 文件按 URL 收紧 WAF 检测面，词汇表限定为 `SQL / XSS / PATH / CMD / UPLOAD`
- URL 匹配支持精确匹配与 `/prefix/*` 前缀通配符（含 `/*` 兜底），无正则
- 加载严格：解析错 / 未知 token / 未知字段 / 重复 URL → 启动报错退出
- 配置入口与现有 CLI 一致：`--url-rules` 优先于 `waf/config.yaml::url_rules_file`，二者皆未给则不加载
- 全局上限保护：`effective(url, rule) = global[rule] AND (no_match(url) OR rule ∈ matched.detect)`
- 保持 `waf/proxy.py::handle_request` 主流程结构不变，仅把 `rules.get("X", True)` 替换为新的 `is_rule_enabled(path, "X")`

**Non-Goals:**
- 不支持正则、不支持中缀/后缀通配符（仅前缀）
- 不支持热重载（启动时一次性加载）
- 不引入 HTTP method 过滤
- 不替换 `waf/config.yaml`、不改动 `rate_limit` / `security_headers` / CSRF 现有行为
- 不重写 `handle_request` 的 control flow

## Decisions

### D1：新增独立模块 `waf/url_rules.py`，不在 `config.py` 内联

`config.py` 已经承担 CLI 与 YAML 合并职责，再塞入「URL 模式编译 + 匹配器」会让该文件混合两层职责。独立模块的好处：
- 单元测试边界清晰（`tests/test_url_rules.py` 直接对 loader / matcher 写白盒测试）
- 数据结构可冷藏在 config 中：`config["url_rules"]` 持有一个 **已编译的 matcher 对象**（或 `None`），`proxy.py` 只调用 `matcher.is_enabled(path, rule)`，无需关心内部表示
- 后续若扩展（如 method 维度）只动这一个文件

替代方案：直接在 `config.py` 末尾解析。否决理由：把「IO+合并」与「模式语义」捆绑会让两边都更难改。

### D2：URL 匹配语法 —— 精确 + 前缀通配符，**首个命中胜出**

语法：
- `/login` —— 精确匹配，仅 `path == "/login"`
- `/api/*` —— 前缀通配符，匹配「以 `/api/` 开头的任意路径」（要求斜杠分段，`/apifoo` 不匹配）
- `/*` —— 全匹配兜底，匹配任意 path
- 不支持中缀/后缀通配符、不支持正则

匹配策略：**首个命中胜出**（按 YAML 列表的从上到下顺序）。这是 nginx-style，可预测，零隐式优先级。

替代方案：
- *最长前缀优先 + exact 优先于 prefix*：直觉更好但需要一个比较器和稳定排序，多 30 行代码与一组 corner-case 测试，本场景收益有限。
- *全部命中并集*：会因为多条规则重叠把被裁剪掉的检测重新加回来，违反「URL 是收紧」的语义。

实现：loader 在加载时把每条规则编译成 `(matcher_kind, pattern, detect_set)`，运行时 `is_enabled(path, rule)` 顺序遍历，第一条 matcher 命中即返回该 detect_set 是否包含 rule；都不命中则返回 `True`（全开 default）。

### D3：词汇表锁定为 `SQL / XSS / PATH / CMD / UPLOAD`

这五项是 `waf/proxy.py::handle_request` 真正会按规则开关分派的检测。
- `RATE` 仅作用于 POST `login_path`，将其暴露为 URL 规则会让用户写出"仅对 /search 关掉 RATE"这种没有实际效果的配置 —— 反生误导
- `CSRF` 在 `app/protected/middleware.py` 而非 WAF 层，词汇里不出现避免误导
- `security_headers` 是响应阶段注入，不属于「检测」语义

内部 token → 现有 config key 映射（loader 内做归一化，运行时直接传 token）：

| YAML token | 内部 key（与现有 `rules.*` 对齐） |
| --- | --- |
| `SQL` | `sql_injection` |
| `XSS` | `xss` |
| `PATH` | `path_traversal` |
| `CMD` | `cmd_injection` |
| `UPLOAD` | `file_upload` |

`is_enabled(path, key)` 接收的是**内部 key**（与 `proxy.py` 当前的 `rules.get("sql_injection", True)` 完全同名），方便最小改动 proxy.py。loader 负责把外部 token 翻译成内部 key 后存进数据结构。

### D4：Strict 加载语义

任一异常即启动失败：
```

Full source: openspec/changes/waf-url-rules/design.md

## openspec/changes/waf-url-rules/tasks.md

- Source: openspec/changes/waf-url-rules/tasks.md
- Lines: 1-55
- SHA256: 0443c39d71f101a6f54f0e934832fd0b00e7428a21515dab0c8a04b3dea9c51b

```md
## 1. URL 规则模块（loader + matcher）

- [ ] 1.1 新建 `waf/url_rules.py`，定义内部 token 映射表（`SQL → sql_injection` 等）与合法 token 集合
- [ ] 1.2 实现 `load_url_rules(path: str) -> UrlRules` 函数：读取并 `yaml.safe_load`，按 design.md D4 列出的全部 Strict 规则校验失败时 `raise UrlRulesError(msg)`（含条目索引或字段名）
- [ ] 1.3 在 loader 中将每条 YAML 规则编译为 `(matcher_kind: Literal["exact","prefix","wildcard"], pattern: str, detect_keys: frozenset[str])`，按文件顺序保留为列表
- [ ] 1.4 实现 `UrlRules.is_enabled(path: str, key: str) -> bool`：按列表顺序遍历，首个命中即返回 `key in detect_keys`；都不命中返回 `True`
- [ ] 1.5 实现匹配语义：精确匹配为 `path == pattern`；`/prefix/*` 匹配 `path.startswith(prefix + "/")` 或 `path == prefix`（但根据 spec，`/api/*` 不应匹配 `/api`，需调整为仅 `path.startswith(prefix + "/")`，并将 `/*` 当作 `path.startswith("/")` 即恒真特殊处理）
- [ ] 1.6 暴露 module-level 帮助函数 `is_rule_enabled(config: dict, path: str, key: str) -> bool`：当 `config["url_rules"]` 为 `None` 时返回 `True`，否则委托给 matcher 对象

## 2. 配置层接入（`waf/config.py`）

- [ ] 2.1 在 `build_arg_parser` 中新增 `--url-rules <path>` 参数（`default=_UNSET`，与现有 `--config` 一致）
- [ ] 2.2 在 `DEFAULTS` 中显式记录 `url_rules_file: None`（保留键，让 `_deep_merge` 可被 YAML 覆盖）
- [ ] 2.3 在 `load_config` 末尾根据"CLI 优先 / YAML 次之 / 都没有则不加载"的规则确定 URL 规则文件路径
- [ ] 2.4 调用 `load_url_rules(...)`：捕获 `FileNotFoundError`（显式指定时报错退出）与 `UrlRulesError`（任何 Strict 校验失败时报错退出）；写入 `config["url_rules"]`
- [ ] 2.5 加载成功后扫描全局开关 vs URL 规则 token 不一致情况，向 stderr 打印 warning（不退出）
- [ ] 2.6 当 `--url-rules` 与 `url_rules_file` 都未设置时，`config["url_rules"] = None`

## 3. 代理层接入（`waf/proxy.py`）

- [ ] 3.1 在 `handle_request` 顶部从 `config` 取出 `url_rules` 对象（可能为 `None`）
- [ ] 3.2 把 `rules.get("sql_injection", True)` 替换为 `is_rule_enabled(config, path, "sql_injection")`，对其余四项 `xss / path_traversal / cmd_injection / file_upload` 依次替换
- [ ] 3.3 不改 control flow、不改 multipart 解析、不改 `rate_limit` / `security_headers` 的开关读法（这两项继续直接读 `rules.get(...)`）

## 4. 示例文件与文档

- [ ] 4.1 新建 `waf/url_rules.example.yaml`，文件顶部以注释列出全部支持词汇（SQL / XSS / PATH / CMD / UPLOAD）、匹配语法说明、匹配策略、未命中默认值、全局上限关系；body 含 `/search`、`/upload/*`、`/api/*` 三条示例
- [ ] 4.2 在 `README.md` 中新增"URL 规则文件"一节，给出 CLI 与 YAML 两种启用方式、首个命中胜出与全局上限语义、错误诊断提示

## 5. 单元测试（loader + matcher）

- [ ] 5.1 新建 `tests/test_url_rules.py`
- [ ] 5.2 loader：合法 YAML 加载成功 → 返回非空 `UrlRules`
- [ ] 5.3 loader：YAML 语法错 / 顶层非 dict / `rules` 非 list / 缺 `url` / 缺 `detect` → `UrlRulesError`
- [ ] 5.4 loader：未知 token / 未知字段 / 通配符不在末尾 / `url` 不以 `/` 开头 / 重复 URL → `UrlRulesError`
- [ ] 5.5 matcher：精确匹配命中与不命中（含尾随斜杠不命中）
- [ ] 5.6 matcher：前缀通配符 `/api/*` 匹配 `/api/foo` 与 `/api/foo/bar`，不匹配 `/api`、`/apifoo`
- [ ] 5.7 matcher：`/*` 兜底匹配任意路径
- [ ] 5.8 matcher：首个命中胜出（上方更具体规则生效，下方更宽规则被忽略）
- [ ] 5.9 `is_rule_enabled` 对 `url_rules=None` 永远返回 `True`
- [ ] 5.10 `is_rule_enabled` 在命中条目不含 token 时返回 `False`，含 token 时返回 `True`

## 6. 集成测试（proxy + url_rules）

- [ ] 6.1 在 `tests/test_proxy*.py` 或新建 `tests/test_proxy_url_rules.py` 中：未配置 `url_rules` 时所有现有 proxy 测试全部通过（向后兼容回归）
- [ ] 6.2 加载一份 url_rules，把 `/search` 限定为 `[XSS, SQL]`，验证 `/search?x=../../etc/passwd` **不**被 PATH 检测拦截，但 `/other?x=../../etc/passwd` 仍被拦截
- [ ] 6.3 全局 `rules.xss: false` + URL 规则中 `/search → [XSS]`，验证 `/search` 上 XSS 不生效（全局上限），且启动时 stderr 出现 warning
- [ ] 6.4 配置文件 `url_rules_file: a.yaml` 与 `--url-rules b.yaml` 并存时，加载的是 `b.yaml`
- [ ] 6.5 显式 `--url-rules /missing.yaml` → 启动时 `SystemExit`

## 7. 验证与收尾

- [ ] 7.1 `pytest -q` 全量通过（含新增 `test_url_rules.py` 与改动后的现有测试）
- [ ] 7.2 手动启动一遍 `python -m waf.proxy --url-rules waf/url_rules.example.yaml`，确认日志含「url-rules loaded」之类提示且未异常退出
- [ ] 7.3 运行 `openspec validate waf-url-rules`，确保 spec 校验通过
```

## openspec/changes/waf-url-rules/specs/waf-config/spec.md

- Source: openspec/changes/waf-url-rules/specs/waf-config/spec.md
- Lines: 1-70
- SHA256: f397482678a68717947ea9e1027ea88f7cb88936a9226c99c1aef917ee44c095

```md
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
```

## openspec/changes/waf-url-rules/specs/waf-detector/spec.md

- Source: openspec/changes/waf-url-rules/specs/waf-detector/spec.md
- Lines: 1-92
- SHA256: d6ab90292ddfe8b76bb6331faaa9c744a83bc5536e41bd80ef7a18a380617e6c

[TRUNCATED]

```md
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
```

Full source: openspec/changes/waf-url-rules/specs/waf-detector/spec.md

