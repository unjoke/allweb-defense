## 1. URL 规则模块（loader + matcher）

- [x] 1.1 新建 `waf/url_rules.py`，定义内部 token 映射表（`SQL → sql_injection` 等）与合法 token 集合
- [x] 1.2 实现 `load_url_rules(path: str) -> UrlRules` 函数：读取并 `yaml.safe_load`，按 design.md D4 列出的全部 Strict 规则校验失败时 `raise UrlRulesError(msg)`（含条目索引或字段名）
- [x] 1.3 在 loader 中将每条 YAML 规则编译为 `(matcher_kind: Literal["exact","prefix","wildcard"], pattern: str, detect_keys: frozenset[str])`，按文件顺序保留为列表
- [x] 1.4 实现 `UrlRules.is_enabled(path: str, key: str) -> bool`：按列表顺序遍历，首个命中即返回 `key in detect_keys`；都不命中返回 `True`
- [x] 1.5 实现匹配语义：精确匹配为 `path == pattern`；`/prefix/*` 匹配 `path.startswith(prefix + "/")` 或 `path == prefix`（但根据 spec，`/api/*` 不应匹配 `/api`，需调整为仅 `path.startswith(prefix + "/")`，并将 `/*` 当作 `path.startswith("/")` 即恒真特殊处理）
- [x] 1.6 暴露 module-level 帮助函数 `is_rule_enabled(config: dict, path: str, key: str) -> bool`：当 `config["url_rules"]` 为 `None` 时返回 `True`，否则委托给 matcher 对象

## 2. 配置层接入（`waf/config.py`）

- [x] 2.1 在 `build_arg_parser` 中新增 `--url-rules <path>` 参数（`default=_UNSET`，与现有 `--config` 一致）
- [x] 2.2 在 `DEFAULTS` 中显式记录 `url_rules_file: None`（保留键，让 `_deep_merge` 可被 YAML 覆盖）
- [x] 2.3 在 `load_config` 末尾根据"CLI 优先 / YAML 次之 / 都没有则不加载"的规则确定 URL 规则文件路径
- [x] 2.4 调用 `load_url_rules(...)`：捕获 `FileNotFoundError`（显式指定时报错退出）与 `UrlRulesError`（任何 Strict 校验失败时报错退出）；写入 `config["url_rules"]`
- [x] 2.5 加载成功后扫描全局开关 vs URL 规则 token 不一致情况，向 stderr 打印 warning（不退出）
- [x] 2.6 当 `--url-rules` 与 `url_rules_file` 都未设置时，`config["url_rules"] = None`

## 3. 代理层接入（`waf/proxy.py`）

- [x] 3.1 在 `handle_request` 顶部从 `config` 取出 `url_rules` 对象（可能为 `None`）
- [x] 3.2 把 `rules.get("sql_injection", True)` 替换为 `is_rule_enabled(config, path, "sql_injection")`，对其余四项 `xss / path_traversal / cmd_injection / file_upload` 依次替换
- [x] 3.3 不改 control flow、不改 multipart 解析、不改 `rate_limit` / `security_headers` 的开关读法（这两项继续直接读 `rules.get(...)`）

## 4. 示例文件与文档

- [x] 4.1 新建 `waf/url_rules.example.yaml`，文件顶部以注释列出全部支持词汇（SQL / XSS / PATH / CMD / UPLOAD）、匹配语法说明、匹配策略、未命中默认值、全局上限关系；body 含 `/search`、`/upload/*`、`/api/*` 三条示例
- [x] 4.2 在 `README.md` 中新增"URL 规则文件"一节，给出 CLI 与 YAML 两种启用方式、首个命中胜出与全局上限语义、错误诊断提示

## 5. 单元测试（loader + matcher）

- [x] 5.1 新建 `tests/test_url_rules.py`
- [x] 5.2 loader：合法 YAML 加载成功 → 返回非空 `UrlRules`
- [x] 5.3 loader：YAML 语法错 / 顶层非 dict / `rules` 非 list / 缺 `url` / 缺 `detect` → `UrlRulesError`
- [x] 5.4 loader：未知 token / 未知字段 / 通配符不在末尾 / `url` 不以 `/` 开头 / 重复 URL → `UrlRulesError`
- [x] 5.5 matcher：精确匹配命中与不命中（含尾随斜杠不命中）
- [x] 5.6 matcher：前缀通配符 `/api/*` 匹配 `/api/foo` 与 `/api/foo/bar`，不匹配 `/api`、`/apifoo`
- [x] 5.7 matcher：`/*` 兜底匹配任意路径
- [x] 5.8 matcher：首个命中胜出（上方更具体规则生效，下方更宽规则被忽略）
- [x] 5.9 `is_rule_enabled` 对 `url_rules=None` 永远返回 `True`
- [x] 5.10 `is_rule_enabled` 在命中条目不含 token 时返回 `False`，含 token 时返回 `True`

## 6. 集成测试（proxy + url_rules）

- [x] 6.1 在 `tests/test_proxy*.py` 或新建 `tests/test_proxy_url_rules.py` 中：未配置 `url_rules` 时所有现有 proxy 测试全部通过（向后兼容回归）
- [x] 6.2 加载一份 url_rules，把 `/search` 限定为 `[XSS, SQL]`，验证 `/search?x=../../etc/passwd` **不**被 PATH 检测拦截，但 `/other?x=../../etc/passwd` 仍被拦截
- [x] 6.3 全局 `rules.xss: false` + URL 规则中 `/search → [XSS]`，验证 `/search` 上 XSS 不生效（全局上限），且启动时 stderr 出现 warning
- [x] 6.4 配置文件 `url_rules_file: a.yaml` 与 `--url-rules b.yaml` 并存时，加载的是 `b.yaml`
- [x] 6.5 显式 `--url-rules /missing.yaml` → 启动时 `SystemExit`

## 7. 验证与收尾

- [x] 7.1 `pytest -q` 全量通过（含新增 `test_url_rules.py` 与改动后的现有测试）
- [x] 7.2 手动启动一遍 `python -m waf.proxy --url-rules waf/url_rules.example.yaml`，确认日志含「url-rules loaded」之类提示且未异常退出
- [x] 7.3 运行 `openspec validate waf-url-rules`，确保 spec 校验通过
