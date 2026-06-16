# allweb-defense

Web 应用常见安全漏洞分析与防护课程项目。

本项目保留一个故意存在漏洞的 Flask 示例应用，并使用独立反向代理 WAF 展示检测、拦截、净化、日志和评估流程。项目不再维护单独的 `protected` 应用版本；具体修复建议集中整理在根目录的 `fix-summary.md` 中。

> 安全提示：项目包含故意保留漏洞的代码和攻击演示脚本，只能在本机或授权实验环境中运行。不要把漏洞应用、后端源站或测试脚本暴露到公网或不受控网段。

## 功能概览

- 漏洞版应用：演示 SQL 注入、XSS、CSRF、路径穿越、命令注入、越权和不安全文件上传。
- 独立 WAF：基于 `aiohttp` 的反向代理，对请求进行检测、拦截、净化和安全响应头注入。
- URL 粒度规则：可按路径启用不同检测项，降低误报并贴近真实业务接口。
- 攻击脚本：提供多类漏洞的本地复现脚本。
- 评估框架：批量运行 payload，输出 Markdown 报告和 matplotlib 图表。
- Dashboard：WAF 启动后默认在 `8081` 提供简单运行面板。

## 项目结构

```text
allweb-defense/
├── app/
│   ├── vulnerable/          # 漏洞版 Flask 应用，默认端口 5000
│   └── templates/           # Flask 应用和 WAF 错误页共用模板
├── attacks/                 # 攻击复现脚本
├── evaluation/              # payload 评估、报告和图表生成
├── tests/                   # 自动化测试
├── uploads/                 # 上传演示目录
├── waf/
│   ├── proxy.py             # 反向代理 WAF 主入口
│   ├── detector.py          # 检测、净化、归一化规则
│   ├── config.py            # YAML + CLI 配置加载
│   ├── config.yaml          # 默认 WAF 配置
│   ├── dashboard.py         # WAF Dashboard
│   ├── url_rules.py         # URL 粒度检测规则
│   └── url_rules.example.yaml
├── fix-summary.md           # 漏洞修复建议总结
├── init_db.py               # 初始化 SQLite 数据库
├── requirements.txt
└── README.md
```

## 快速开始

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python init_db.py
```

初始化后可使用以下测试账号：

| 用户名 | 密码 | 角色 |
|---|---|---|
| `admin` | `admin123` | 管理员 |
| `alice` | `alice123` | 普通用户 |
| `bob` | `bob123` | 普通用户 |

## 启动漏洞应用

```bash
python app/vulnerable/app.py
```

访问：

```text
http://127.0.0.1:5000
```

漏洞应用默认只绑定 `127.0.0.1:5000`，用于避免被同网段机器直接访问。不要改成 `0.0.0.0` 暴露运行。

## 启动 WAF

先启动漏洞应用，再启动 WAF：

```bash
python -m waf
```

WAF 入口：

```text
http://127.0.0.1:8080
```

Dashboard：

```text
http://127.0.0.1:8081
```

WAF 默认把请求转发到 `http://127.0.0.1:5000`。也可以临时覆盖监听端口和后端地址：

```bash
python -m waf --listen 8080 --backend http://127.0.0.1:5000
```

## 挂载其他项目

如果要把 WAF 接到别的 Web 项目上，通常只需要修改 `waf/config.yaml` 中的 `backend_url`，并根据实际登录路径调整 `login_path`。

例如后端项目运行在本机 `3000` 端口：

```yaml
listen_port: 8080
backend_url: "http://127.0.0.1:3000"
login_path: "/login"
```

字段含义：

| 字段 | 是否常改 | 说明 |
|---|---|---|
| `listen_port` | 视情况 | WAF 对外监听端口，默认 `8080`。多个项目同时运行时需要错开。 |
| `backend_url` | 通常需要 | WAF 转发到的真实后端地址。挂载新项目时主要改这里。 |
| `login_path` | 可能需要 | 登录失败限速规则作用的路径。若新项目登录接口不是 `/login`，需要修改。 |
| `rules` | 一般不改 | 全局防护开关，关闭后 URL 规则也不能重新开启该检测项。 |
| `rate_limit` | 按需 | 登录失败计数、窗口和锁定时间。 |
| `log_path` | 一般不改 | WAF 安全日志输出路径。 |

使用 WAF 时，应访问 WAF 入口，而不是直接访问后端端口。否则请求会绕过 WAF。

## WAF 配置

默认配置位于 `waf/config.yaml`：

```yaml
listen_port: 8080
backend_url: "http://127.0.0.1:5000"
login_path: "/login"
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
  window: 60
  lockout: 300
log_path: "security.log"
```

常用命令：

```bash
python -m waf --config waf/config.yaml
python -m waf --listen 8080
python -m waf --backend http://127.0.0.1:5000
python -m waf --disable sql_injection
python -m waf --url-rules waf/url_rules.example.yaml
```

## URL 粒度规则

主配置中添加：

```yaml
url_rules_file: "waf/url_rules.example.yaml"
```

规则文件格式：

```yaml
rules:
  - url: /search
    detect: [SQL, XSS]

  - url: /upload/*
    detect: [UPLOAD, PATH]

  - url: /api/*
    detect: [SQL, CMD]

  - url: /*
    detect: [SQL, XSS, PATH, CMD, UPLOAD]
```

支持的路径写法：

| 写法 | 含义 |
|---|---|
| `/login` | 精确匹配，只匹配 `/login` |
| `/api/*` | 前缀匹配，匹配 `/api/foo`、`/api/foo/bar`，不匹配 `/api` 或 `/apifoo` |
| `/*` | 兜底匹配所有路径 |

支持的检测 token：

| Token | 对应规则 |
|---|---|
| `SQL` | SQL 注入 |
| `XSS` | 跨站脚本，当前策略是净化后转发 |
| `PATH` | 路径穿越 |
| `CMD` | 命令注入 |
| `UPLOAD` | 文件上传扩展名和 magic bytes 校验 |

匹配策略是 first match wins，也就是从上到下第一个匹配到的规则生效。更具体的路径应放在前面，`/*` 应放在最后。未匹配任何 URL 规则的路径默认启用全部检测项，但仍受全局 `rules` 开关限制。

`rate_limit` 和 `security_headers` 目前不支持 URL 粒度配置，只由 `waf/config.yaml` 的全局开关控制。

## 覆盖的漏洞类型

| 类型 | 演示位置 | 建议修复方向 |
|---|---|---|
| SQL 注入 | 登录、搜索 | 参数化查询、输入约束、最小化错误回显 |
| XSS | 留言、搜索结果 | 输出编码、HTML 净化、CSP |
| CSRF | 修改密码、删除操作 | CSRF Token、SameSite Cookie |
| 路径穿越 | 文件下载 | 路径归一化、根目录限制 |
| 命令注入 | 管理员文件操作 | 避免 shell 拼接、参数列表调用 |
| 水平/垂直越权 | 留言和管理接口 | 资源归属校验、角色权限校验 |
| 不安全文件上传 | 头像上传 | 扩展名白名单、magic bytes 校验、隔离存储 |
| 暴力破解 | 登录接口 | IP 失败计数、窗口锁定 |

详细修复建议见 `fix-summary.md`。

## 攻击演示脚本

| 脚本 | 演示内容 |
|---|---|
| `attacks/sql_injection.py` | 登录绕过、UNION 数据泄露 |
| `attacks/xss_demo.py` | 存储型和反射型 XSS |
| `attacks/csrf_demo.html` | CSRF 请求伪造 |
| `attacks/path_traversal.py` | 路径穿越读取文件 |
| `attacks/cmd_injection.py` | 命令注入 |
| `attacks/privilege_escalation.py` | 水平/垂直越权 |
| `attacks/brute_force.py` | 登录暴力破解，默认目标为 WAF 入口 |

验证 WAF 效果时，应把目标地址指向 `http://127.0.0.1:8080`。

## 对抗性评估

先启动后端和 WAF：

```bash
python app/vulnerable/app.py
python -m waf
```

再运行评估：

```bash
python -m evaluation baseline --skip-rate-limit
python -m evaluation hardened --skip-rate-limit
python -m evaluation baseline --category benign
```

常用参数：

| 参数 | 说明 |
|---|---|
| `baseline` / `hardened` | 报告标签，用于区分评估轮次 |
| `--waf-url` | 指定 WAF 地址，默认 `http://127.0.0.1:8080` |
| `--category` | 只运行某一类 payload |
| `--skip-rate-limit` | 跳过限速类 payload，避免长时间锁定 |
| `--payloads-dir` | 指定 payload 目录 |
| `--results-dir` | 指定报告输出目录 |

输出默认位于 `evaluation/results/`。

说明：当前评估 runner 主要用 HTTP 状态码判断是否拦截，`400`、`403`、`429` 会被视为拦截。XSS 规则采用“净化后转发”策略，响应状态可能仍是 `200`，因此报告中的 XSS 指标需要结合响应体净化效果理解。

## 自动化测试

运行全部无需外部服务的测试：

```bash
python -m pytest tests/test_detector.py tests/test_waf_detector_hardened.py tests/test_url_rules.py tests/test_config_url_rules.py tests/test_proxy_url_rules.py tests/test_evaluation_*.py -v
```

漏洞应用手动冒烟测试需要先启动 `http://127.0.0.1:5000`：

```bash
python app/vulnerable/app.py
python -m pytest tests/test_all.py -v
```

## 源站绕过风险

WAF 有效的前提是后端源站不能被攻击者直接访问。如果真实后端监听在 `0.0.0.0` 并暴露端口，攻击者可以绕过 WAF 直接访问后端。

本地实验建议：

- 后端只监听 `127.0.0.1`。
- 对外只开放 WAF 入口端口。
- 不要把漏洞应用暴露到公网。
- 挂载外部项目时，确认访问流量确实经过 WAF。

在分布式部署中，还应考虑防火墙、内网访问控制、反代专用请求头、mTLS 或 HMAC 请求签名等机制。

## 技术栈

- Python 3.12
- Flask 3.1.2
- aiohttp 3.9.5
- PyYAML 6.0.2
- requests 2.32.5
- pytest 8.4.2
- matplotlib 3.9.2
