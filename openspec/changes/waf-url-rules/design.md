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
- 文件存在但 YAML 解析报错 → 退出
- 顶层不是 `dict` 或缺 `rules` 键、`rules` 不是 list → 退出
- 任一条目缺 `url` 或 `detect` 字段 → 退出
- `url` 不以 `/` 开头 / 含非法字符 / 通配符不在结尾 → 退出
- `detect` 元素不在词汇表 → 退出
- 同一 URL 出现两次（`detect` 集应一致才合并？不，直接拒绝）→ 退出
- 出现未知顶层字段或条目字段 → 退出

行为参考现有 `--config` 显式指定但缺失时的退出语义（`waf/config.py:69-78`），保持一致。错误信息要带行号或条目索引以便定位。

替代方案：宽松模式（跳过坏条目并 stderr 警告）。否决理由：安全相关配置不能默默丢掉规则；启动失败比"看似启动了但少了几条规则"更安全。

### D5：CLI vs YAML 优先级与默认行为

- `--url-rules <path>` （CLI）→ 优先
- `waf/config.yaml::url_rules_file: <path>` → 次之
- 都没有 → 不加载，`config["url_rules"] = None`，`is_enabled(path, key)` 永远返回 `True`
- 显式给出但文件不存在 → 报错退出（与 `--config` 行为一致）

替代方案：把 URL 规则塞回 `waf/config.yaml`。否决理由：CLAUDE 让 URL 规则文件可单独被运维管控、版本化、对外分发；和 listen_port 这种基础设施配置混在一起会让运维流程变重。

### D6：与 `proxy.py` 的最小改动

`waf/proxy.py::handle_request` 改动只有两点：
1. 函数顶部从 `rules = config.get("rules", {})` 改为构造一个 `is_rule_enabled = make_is_enabled(config, path)` 闭包（或直接调用 module-level 函数 `is_rule_enabled(config, path, key)`）
2. 把所有 `rules.get("X", True)` 替换为 `is_rule_enabled("X")` —— 5 处

不改 control flow、不改 multipart 解析、不改返回值。不引入新的「block / sanitize / log」语义。

### D7：示例文件命名 `waf/url_rules.example.yaml`

带 `.example` 后缀避免被运维误以为是默认会被加载的文件。`waf/url_rules.yaml` 这个"看起来像默认"的路径**不**自动加载（与 `waf/config.yaml` 的处理不同）—— URL 规则只通过显式配置生效，避免悄悄启用裁剪导致检测变宽松。

## Risks / Trade-offs

- **首个命中胜出 vs 用户直觉** → 文件顶部注释里明示规则；示例里把更具体的 URL 放在更上面；并在 README 里给一个「错位」反例。
- **Strict 启动失败** → 把详细错误信息（条目 index、字段名、不合法值）打到 stderr，避免运维盲调。
- **全局上限的隐式行为**（用户在 URL 规则里写了 `XSS` 但全局关了 XSS → 实际不跑）→ loader 在加载完后扫描一遍：若某条规则的 `detect` token 对应的 key 在全局是 `false`，stderr 打"warning: rule on /xx lists XSS but global xss=false; this rule has no effect for XSS"。不退出，仅提示。
- **`/*` 全匹配兜底容易意外裁掉所有 URL 的检测** → 文档里给警告，并在示例文件里**不**包含 `/*` 条目。
- **将来扩展 method 维度的兼容性** → 数据结构上每条规则保留为 dict（不是 tuple），后续可不破坏地加 `method` 字段；本次实现明确"忽略未知字段"的反面：现在选 Strict（不允许未知字段），将来需要扩展时由该 spec 的下一次变更显式开放。

## Migration Plan

无破坏性变更：
1. 部署后默认行为不变（不指定 `--url-rules` / `url_rules_file`）
2. 运维选择性启用：从 `waf/url_rules.example.yaml` 拷贝出生产文件，按需收紧
3. 回滚：移除 CLI flag 与 YAML 键即可，无数据库或状态迁移

## Open Questions

无（已在 explore 阶段全部澄清：词汇表只支持 SQL/XSS/PATH/CMD/UPLOAD；首个命中胜出；Strict；CLI 与 YAML 都支持）。
