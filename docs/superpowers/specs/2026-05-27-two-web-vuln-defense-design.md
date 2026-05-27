---
comet_change: two-web-vuln-defense
role: technical-design
canonical_spec: openspec
archived-with: 2026-05-27-two-web-vuln-defense
status: final
---

## 架构与数据流

```
aiohttp web.Server
       │
       ▼
handle_request(request)
       │
       ├─ 1. 解析输入
       │       GET params          → dict[str, str]
       │       POST urlencoded     → dict[str, str]
       │       POST multipart      → dict[str, str] (文件名) + parts[]
       │       其他 body           → bytes (透传，不检测)
       │
       ├─ 2. 检测阶段（按顺序，命中即返回，不继续检测）
       │       rate_limit(ip, state, config)   → 429
       │       detect_sql_injection(val)        → 403
       │       detect_path_traversal(val)       → 403
       │       detect_cmd_injection(val)        → 403
       │       is_allowed_extension(filename)   → 400
       │
       ├─ 3. XSS 净化（不拦截，修改参数值后继续）
       │       sanitize_xss(val) 应用于所有 GET/POST 字符串参数
       │
       ├─ 4. 重构请求 body
       │       urlencoded → urllib.parse.urlencode(净化后 dict)
       │       multipart  → aiohttp.FormData 重新打包（含净化后文件名）
       │       其他        → 原始 bytes 不变
       │
       ├─ 5. 转发
       │       aiohttp.ClientSession.request(
       │           method, backend_url + path + query,
       │           headers=filtered_headers,
       │           data=reconstructed_body
       │       )
       │       filtered_headers: 去掉 Host，加 X-Forwarded-For
       │
       └─ 6. 注入安全响应头后返回给客户端
              写 security.log（仅拦截和净化事件）
```

## 模块职责边界

| 模块 | 职责 | 不做什么 |
|------|------|---------|
| `waf/detector.py` | 纯函数检测/净化，无 I/O，无状态，仅依赖标准库和 `re` | 不知道 HTTP，不写日志，不持有状态 |
| `waf/config.py` | 加载 YAML 配置，合并 CLI 参数，返回配置字典 | 不验证业务逻辑，不启动服务 |
| `waf/proxy.py` | 编排检测、重构请求、转发、注入响应头、写日志、管理 rate_limit state | 不包含检测正则，不直接读配置文件 |

## 关键实现决策

### 1. multipart/form-data 完整读取后重构

aiohttp 的 multipart 是异步流式读取，消费后不可重放。实现上需要：
1. `await request.multipart()` 逐 part 读取
2. 对每个 part 提取 filename（若有）做扩展名检测
3. 读取 part 的 bytes 内容缓存到内存
4. 通过检测后用 `aiohttp.FormData` 重新打包所有 part 转发

这是唯一能同时做检测和转发的方式，代价是文件内容需要在内存中缓冲一次。课设场景文件体积小，可接受。

### 2. urlencoded body 读取后重构

POST `application/x-www-form-urlencoded` 的处理：
1. `await request.post()` 读取表单（消费 body）
2. 对所有值做检测和 XSS 净化
3. 用 `urllib.parse.urlencode(净化后 dict)` 重新编码为 body bytes 转发

### 3. 频率限制基于请求次数，不依赖后端结果

代理层无法感知后端认证结果，对 `/login` 路径的每次 POST 请求都计数。`_rate_state` 字典在进程启动时初始化，作为应用级变量在请求间共享：

```python
# proxy.py 模块级
_rate_state: dict = {}

# handle_request 内
if request.path == config.get("login_path", "/login") and request.method == "POST":
    if check_rate_limit(ip, _rate_state, config["rate_limit"]):
        log_block("brute-force", ip)
        return web.Response(status=429)
    record_login_failure(ip, _rate_state, config["rate_limit"])
```

与 middleware.py 的差异：middleware.py 在认证成功时调用 `reset_rate_limit`，代理层无此能力。合法的登录失败也会被计数，这是代理层的固有局限，在报告局限性章节说明。

### 4. 检测顺序

频率限制 → SQL 注入 → 路径穿越 → 命令注入 → 文件扩展名 → XSS 净化

频率限制最先，避免对已锁定 IP 做无意义的检测计算。XSS 最后，因为它不拦截只净化，需要在所有拦截检测通过后才修改参数值。

### 5. 日志格式与 security.log 复用

复用现有 `security.log` 文件，日志格式与 middleware.py 保持一致：

```
YYYY-MM-DD HH:MM:SS | BLOCKED | type=<attack_type> | ip=<ip> | path=<path> | payload=<snippet>
YYYY-MM-DD HH:MM:SS | SANITIZED | type=xss | ip=<ip> | path=<path> | payload=<snippet>
```

## 测试策略

**单元测试（`tests/test_detector.py`）**：直接调用 `waf/detector.py` 中的函数，不启动任何服务。覆盖每个检测函数的正例和反例，以及频率限制的状态转换。

**集成验证（手动）**：启动漏洞版后端（5000）+ WAF 代理（8080），重放现有攻击脚本验证拦截效果，验证正常业务流程不受影响。

## 局限性说明（报告用）

- 频率限制计数合法登录失败，无法在认证成功时重置
- XSS 净化修改了请求参数，后端收到的值与原始值不同
- 正则检测可被编码绕过（Base64、Unicode 转义等）
- multipart 文件内容需全量缓冲到内存
- CSRF 防护无法在无状态代理层实现
