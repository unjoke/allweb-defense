# WAF 反向代理通防设计文档

**日期：** 2026-05-27  
**状态：** 待实现

---

## 背景与目标

当前通防中间件（`app/protected/middleware.py`）通过 Flask `before_request` 钩子绑定在留言系统的 protected app 上，与业务代码耦合，无法保护其他语言或框架编写的后端。

本设计将通防能力提取为一个**独立的反向代理进程**，语言无关，任何 HTTP 后端（PHP、Java、Go、Node.js 等）均可通过将流量指向代理端口来获得防护，无需修改后端代码。

---

## 架构

```
攻击者/客户端
      │
      ▼  :8080（可配置）
┌─────────────────────────────────┐
│         WAF 反向代理进程          │
│  waf/                           │
│  ├── proxy.py      # 主入口      │
│  ├── config.py     # 配置加载    │
│  ├── detector.py   # 检测逻辑    │
│  └── config.yaml   # 默认配置    │
└─────────────────────────────────┘
      │  转发合法请求
      ▼  http://127.0.0.1:5000（可配置）
┌─────────────────────────────────┐
│    任意后端（Flask/PHP/Java/Go）  │
└─────────────────────────────────┘
```

与现有项目的关系：
- `app/protected/middleware.py` 保留不动，作为"Flask 内嵌通防"演示
- 新增 `waf/` 目录作为"独立反向代理通防"演示
- `app/vulnerable/app.py`（端口 5000）直接作为 WAF 代理的后端目标，无需改动
- 课设报告可对比两种通防模式：绑定式 vs 代理式

---

## 模块设计

### `waf/detector.py`

从 `middleware.py` 提取所有纯检测函数，去除 Flask 依赖，只依赖标准库和 `re`：

- `detect_sql_injection(value: str) -> bool`
- `sanitize_xss(value: str) -> str`
- `detect_path_traversal(value: str) -> bool`
- `detect_cmd_injection(value: str) -> bool`
- `is_allowed_extension(filename: str) -> bool`
- `check_rate_limit(ip: str, state: dict, config: dict) -> bool`
- `record_login_failure(ip: str, state: dict, config: dict)`

所有函数无副作用，可独立单元测试，不依赖任何 Web 框架。

### `waf/config.py`

配置加载逻辑，命令行参数优先于 YAML 文件：

```python
def load_config(args) -> dict:
    # 1. 读取 config.yaml（若 --config 指定或默认路径存在）
    # 2. 命令行参数覆盖对应字段
    # 3. 返回合并后的配置字典
```

### `waf/config.yaml`（默认配置）

```yaml
listen_port: 8080
backend_url: "http://127.0.0.1:5000"
rules:
  sql_injection: true
  xss: true
  path_traversal: true
  cmd_injection: true
  rate_limit: true
  file_upload: true
  security_headers: true
rate_limit:
  max_failures: 10
  window: 60        # 秒
  lockout: 300      # 秒，5 分钟
log_path: "security.log"
```

> CSRF 在代理层默认关闭：代理无法感知后端的 session 状态，CSRF Token 的生成和校验需要与后端协同，超出通用代理的职责范围。

### `waf/proxy.py`

基于 `aiohttp` 的异步反向代理，请求处理流程：

```
收到请求
  │
  ├─ 1. 提取所有用户输入（GET 参数、POST 表单、上传文件名）
  │
  ├─ 2. 逐项跑 detector 检测
  │       SQL 注入 → 403
  │       路径穿越 → 403
  │       命令注入 → 403
  │       非法文件扩展名 → 400
  │       IP 频率限制 → 429
  │       XSS → 净化后继续（不拦截，修改参数值）
  │
  ├─ 3. 通过检测 → 用 aiohttp.ClientSession 转发给后端
  │       保留原始 headers、method、body
  │       替换 Host header 为后端地址
  │
  ├─ 4. 收到后端响应 → 注入安全响应头
  │       Content-Security-Policy: default-src 'self'
  │       X-Frame-Options: DENY
  │       X-Content-Type-Options: nosniff
  │       X-XSS-Protection: 1; mode=block
  │       Referrer-Policy: strict-origin-when-cross-origin
  │
  └─ 5. 返回响应给客户端，写 security.log（仅拦截事件）
```

### 启动方式

```bash
# 纯命令行
python -m waf.proxy --listen 8080 --backend http://127.0.0.1:5000

# 纯配置文件
python -m waf.proxy --config waf/config.yaml

# 混合（命令行覆盖配置文件中的对应字段）
python -m waf.proxy --config waf/config.yaml --listen 9090

# 关闭某项规则
python -m waf.proxy --listen 8080 --backend http://127.0.0.1:5000 --disable sql_injection
```

---

## 新增依赖

| 包 | 用途 | 版本 |
|----|------|------|
| `aiohttp` | 异步 HTTP 服务器 + 客户端转发 | `==3.9.5` |
| `pyyaml` | 读取 config.yaml | `==6.0.2` |

---

## 目录结构变更

```
allweb-defense/
├── app/                    # 不变
│   ├── vulnerable/
│   └── protected/
├── waf/                    # 新增
│   ├── __init__.py
│   ├── proxy.py
│   ├── config.py
│   ├── detector.py
│   └── config.yaml
├── tests/
│   ├── test_middleware.py  # 不变
│   └── test_detector.py    # 新增：针对 detector.py 的单元测试
└── requirements.txt        # 新增 aiohttp、pyyaml
```

---

## 演示场景（课设）

1. 启动漏洞版后端：`python -m app.vulnerable.app`（端口 5000）
2. 启动 WAF 代理：`python -m waf.proxy --listen 8080 --backend http://127.0.0.1:5000`
3. 所有攻击脚本改为打 8080 端口 → 全部被拦截
4. 直接打 5000 端口 → 全部成功（对比）
5. 展示 security.log，展示安全响应头

---

## 局限性（报告讨论点）

- 正则检测可被编码绕过（Base64、Unicode 转义等）
- XSS 净化在代理层修改了请求参数，后端收到的是净化后的值，可能影响业务逻辑
- CSRF 防护无法在无状态代理层实现，需后端配合
- 不支持 HTTPS 终止（课设范围内不需要）
- 内存中维护 rate_limit 状态，多进程部署时状态不共享
