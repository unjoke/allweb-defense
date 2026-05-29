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
