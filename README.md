# allweb-defense

Web 应用通用漏洞分析与防御课程设计项目。实现了一个留言板系统的漏洞版与防护版，并附带独立的反向代理 WAF，演示 10 类常见 Web 攻击及其防御方案。

## 项目结构

```
allweb-defense/
├── app/
│   ├── vulnerable/     # 漏洞版 Flask 应用（端口 5000）
│   └── protected/      # 防护版 Flask 应用（端口 5001）
├── shared/
│   └── templates/      # 两个应用共用的 HTML 模板
├── waf/                # 独立反向代理 WAF（端口 8080）
│   ├── proxy.py        # aiohttp 异步代理主入口
│   ├── detector.py     # 纯函数检测/净化库
│   ├── config.py       # 配置加载（YAML + CLI）
│   └── config.yaml     # 默认配置
├── attacks/            # 攻击演示脚本
├── tests/              # 自动化测试
├── init_db.py          # 数据库初始化
└── requirements.txt
```

## 快速开始

### 安装依赖

```bash
pip install -r requirements.txt
```

### 初始化数据库

```bash
python init_db.py
```

### 启动应用

**漏洞版**（用于演示攻击）：

```bash
python app/vulnerable/app.py
# 访问 http://127.0.0.1:5000
```

**防护版**（Flask 内嵌通防中间件）：

```bash
python app/protected/app.py
# 访问 http://127.0.0.1:5001
```

**WAF 反向代理**（代理式通防，保护漏洞版后端）：

```bash
# 先启动漏洞版后端
python app/vulnerable/app.py

# 再启动 WAF 代理
python -m waf
# 访问 http://127.0.0.1:8080（流量经 WAF 过滤后转发到 5000）
```

WAF 支持命令行参数覆盖配置：

```bash
python -m waf --listen 8080 --backend http://127.0.0.1:5000
```

## 防御能力对比

| 防御方式 | 实现位置 | 适用场景 |
|---------|---------|---------|
| 绑定式通防 | `app/protected/middleware.py` | 与 Flask 应用耦合，仅保护 Python/Flask 后端 |
| 代理式通防 | `waf/` | 独立进程，语言无关，可保护任意 HTTP 后端 |

## WAF 检测规则

| 规则 | 触发条件 | 响应 |
|------|---------|------|
| SQL 注入 | GET/POST 参数含 SQL 关键字 | 403 |
| 路径穿越 | 参数含 `../` 或其编码变体 | 403 |
| 命令注入 | 参数含 `;` `&&` `\|` `` ` `` `$(` | 403 |
| 非法文件扩展名 | 上传文件不在 `.jpg/.jpeg/.png/.gif` 白名单 | 400 |
| 频率限制 | 同一 IP 对 `/login` POST 超过阈值次数 | 429 |
| XSS 净化 | 参数含 `<script>` `javascript:` `on*=` | HTML 实体编码后转发，不拦截 |
| 安全响应头 | 所有响应 | 注入 CSP、X-Frame-Options 等 5 个安全头 |

所有拦截和净化事件写入 `security.log`。

## WAF 配置

编辑 `waf/config.yaml`：

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
  max_failures: 10   # 窗口内最大失败次数
  window: 60         # 时间窗口（秒）
  lockout: 300       # 锁定时长（秒）
log_path: "security.log"
```

禁用单项规则：

```bash
python -m waf --disable sql_injection
```

## 攻击演示脚本

脚本默认打漏洞版（端口 5000），可改端口验证防护效果。

| 脚本 | 演示攻击 |
|------|---------|
| `attacks/sql_injection.py` | 登录绕过、UNION 数据泄露 |
| `attacks/xss_demo.py` | 存储型 / 反射型 XSS |
| `attacks/csrf_demo.html` | 跨站请求伪造（在浏览器中打开） |
| `attacks/path_traversal.py` | 路径穿越读取任意文件 |
| `attacks/cmd_injection.py` | 命令注入执行系统命令 |
| `attacks/privilege_escalation.py` | 水平 / 垂直越权 |
| `attacks/brute_force.py` | 暴力破解登录（对比频率限制效果） |

## 运行测试

```bash
python -m pytest tests/test_detector.py -v
```

## 技术栈

- Python 3.12
- Flask 3.1.2（漏洞版 / 防护版应用）
- aiohttp 3.9.5（WAF 反向代理）
- PyYAML 6.0.2（WAF 配置）
- pytest 8.4.2（单元测试）
