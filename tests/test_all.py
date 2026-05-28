"""
Automated comparison test suite.
Tests 10 attack types against both the vulnerable app (port 5000)
and the protected app (port 5001).

Run:
    pytest tests/test_all.py -v
or for the formatted comparison table:
    python tests/test_all.py
"""
import re
import os
import sys
import time
import threading
import requests
import pytest

# ---------------------------------------------------------------------------
# App startup helpers
# ---------------------------------------------------------------------------

VULN_BASE = "http://127.0.0.1:5000"
PROT_BASE = "http://127.0.0.1:5001"

_vuln_proc = None
_prot_proc = None


def _start_app(module: str, port: int):
    import subprocess
    root = os.path.join(os.path.dirname(__file__), "..")
    env = os.environ.copy()
    env["PYTHONPATH"] = root
    proc = subprocess.Popen(
        [sys.executable, "-m", module],
        cwd=root,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Wait until the port is accepting connections
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            requests.get(f"http://127.0.0.1:{port}/login", timeout=1)
            return proc
        except Exception:
            time.sleep(0.2)
    proc.terminate()
    raise RuntimeError(f"App {module} did not start on port {port}")


def _is_up(base: str) -> bool:
    try:
        requests.get(f"{base}/login", timeout=2)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def _login(base: str, username: str, password: str) -> requests.Session:
    s = requests.Session()
    # For protected app we need a CSRF token first
    r = s.get(f"{base}/login")
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    data = {"username": username, "password": password}
    if csrf:
        data["csrf_token"] = csrf.group(1)
    s.post(f"{base}/login", data=data, allow_redirects=True)
    return s


def _get_csrf(session: requests.Session, base: str, path: str) -> str:
    r = session.get(f"{base}{path}")
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Individual attack functions — return True if attack SUCCEEDED
# ---------------------------------------------------------------------------

def attack_sql_login_bypass(base: str) -> bool:
    """SQL injection login bypass via OR '1'='1'."""
    s = requests.Session()
    r = s.post(
        f"{base}/login",
        data={"username": "admin' OR '1'='1' --", "password": "x"},
        allow_redirects=True,
    )
    return r.status_code == 200 and ("留言板" in r.text or "messages" in r.url)


def attack_sql_union(base: str) -> bool:
    """UNION SELECT to dump user hashes via /search."""
    s = _login(base, "alice", "alice123")
    # messages table: id, user_id, username, content, filepath, created_at (6 cols)
    # users table:    id, username, password, role, email, avatar (6 cols)
    payload = "' UNION SELECT id,username,password,role,email,avatar FROM users --"
    r = s.get(f"{base}/search", params={"q": payload})
    hashes = re.findall(r"\b[0-9a-f]{32}\b", r.text)
    return len(hashes) > 0


def attack_stored_xss(base: str) -> bool:
    """Post a <script> tag and verify it appears unescaped."""
    s = _login(base, "alice", "alice123")
    # Use a unique payload per run so we don't pick up old messages from the other app
    unique_marker = f"xss-stored-{int(time.time())}"
    payload = f'<script>alert("{unique_marker}")</script>'
    csrf = _get_csrf(s, base, "/messages")
    data = {"content": payload}
    if csrf:
        data["csrf_token"] = csrf
    s.post(f"{base}/messages", data=data, allow_redirects=True)
    r = s.get(f"{base}/messages")
    return payload in r.text


def attack_reflected_xss(base: str) -> bool:
    """Reflect a <script> tag via /search?q=."""
    s = _login(base, "alice", "alice123")
    payload = '<script>alert("rxss")</script>'
    r = s.get(f"{base}/search", params={"q": payload})
    return payload in r.text


def attack_csrf(base: str) -> bool:
    """Change password without a valid CSRF token."""
    s = _login(base, "alice", "alice123")
    # Deliberately omit csrf_token
    r = s.post(
        f"{base}/profile/password",
        data={"new_password": "hacked"},
        allow_redirects=True,
    )
    # Success means the server accepted the request (no 403)
    return r.status_code not in (403, 400)


def attack_path_traversal(base: str) -> bool:
    """Read init_db.py via ../init_db.py in /download (one level above messages/)."""
    s = _login(base, "alice", "alice123")
    r = s.get(f"{base}/download", params={"filename": "../init_db.py"})
    return r.status_code == 200 and len(r.content) > 0


def attack_horizontal_priv(base: str) -> bool:
    """Alice deletes bob's message (no ownership check)."""
    # Bob posts a message
    bob = _login(base, "bob", "bob123")
    csrf = _get_csrf(bob, base, "/messages")
    unique_content = f"bob-private-{time.time()}"
    data = {"content": unique_content}
    if csrf:
        data["csrf_token"] = csrf
    bob.post(f"{base}/messages", data=data, allow_redirects=True)

    # Find the ID of bob's just-posted message by matching content in the page.
    # msg_id hidden input is now admin-only; use the download link (always visible).
    r = bob.get(f"{base}/messages")
    bob_msg_id = None
    cards = re.split(r'<div class="msg-item">', r.text)
    for card in cards:
        if unique_content in card:
            m = re.search(r'/download\?filename=msg_(\d+)_\w+\.txt', card)
            if m:
                bob_msg_id = m.group(1)
                break

    if not bob_msg_id:
        return False

    # Alice tries to delete bob's message (vertical privilege escalation: no role check)
    alice = _login(base, "alice", "alice123")
    csrf2 = _get_csrf(alice, base, "/messages")
    del_data = {"msg_id": bob_msg_id}
    if csrf2:
        del_data["csrf_token"] = csrf2
    r2 = alice.post(f"{base}/messages/delete", data=del_data, allow_redirects=True)
    if r2.status_code == 403:
        return False

    # Check if bob's message is gone
    r3 = alice.get(f"{base}/messages")
    return unique_content not in r3.text


def attack_vertical_priv(base: str) -> bool:
    """Alice (role=user) accesses /admin/users."""
    s = _login(base, "alice", "alice123")
    r = s.get(f"{base}/admin/users")
    return r.status_code == 200 and ("admin" in r.text or "用户管理" in r.text)


def attack_unsafe_upload(base: str) -> bool:
    """Upload a .py file as avatar."""
    s = _login(base, "alice", "alice123")
    csrf = _get_csrf(s, base, "/profile")
    files = {"avatar": ("shell.py", b"print('pwned')", "text/plain")}
    data = {}
    if csrf:
        data["csrf_token"] = csrf
    r = s.post(f"{base}/profile/avatar", files=files, data=data, allow_redirects=True)
    return r.status_code not in (400, 403) and "shell.py" in r.text


def attack_cmd_injection(base: str) -> bool:
    """Admin deletes a file with shell metacharacters in filename."""
    s = _login(base, "admin", "admin123")
    csrf = _get_csrf(s, base, "/admin/messages")
    marker = os.path.join(
        os.path.dirname(__file__), "..", "cmd_injection_marker.txt"
    )
    marker = os.path.normpath(marker)
    payload = f"nonexistent; echo pwned > {marker}"
    data = {"filename": payload}
    if csrf:
        data["csrf_token"] = csrf
    s.post(f"{base}/admin/messages/delete", data=data, allow_redirects=True)
    time.sleep(0.3)
    exists = os.path.exists(marker)
    if exists:
        os.remove(marker)
    return exists


def attack_brute_force(base: str) -> bool:
    """Send 12 failed login attempts; success = no 429 received."""
    s = requests.Session()
    for _ in range(12):
        r = s.post(
            f"{base}/login",
            data={"username": "alice", "password": "wrongpassword"},
            allow_redirects=False,
        )
        if r.status_code == 429:
            return False  # rate-limited — attack blocked
    return True  # all 12 went through — no rate limiting


# ---------------------------------------------------------------------------
# Attack registry
# ---------------------------------------------------------------------------

ATTACKS = [
    ("SQL注入-登录绕过",   "SQL Injection (login bypass)",   attack_sql_login_bypass),
    ("SQL注入-UNION查询",  "SQL Injection (UNION dump)",     attack_sql_union),
    ("存储型XSS",          "Stored XSS",                     attack_stored_xss),
    ("反射型XSS",          "Reflected XSS",                  attack_reflected_xss),
    ("CSRF跨站请求伪造",   "CSRF",                           attack_csrf),
    ("路径穿越",           "Path Traversal",                 attack_path_traversal),
    ("水平越权",           "Horizontal Privilege Escalation",attack_horizontal_priv),
    ("垂直越权",           "Vertical Privilege Escalation",  attack_vertical_priv),
    ("不安全文件上传",     "Unsafe File Upload",             attack_unsafe_upload),
    ("命令注入",           "Command Injection",              attack_cmd_injection),
    ("暴力破解",           "Brute Force",                    attack_brute_force),
]


# ---------------------------------------------------------------------------
# pytest test cases — require both apps to be running
# ---------------------------------------------------------------------------

def _skip_if_down(base: str):
    if not _is_up(base):
        pytest.skip(f"App at {base} is not running")


class TestVulnerableApp:
    """Each attack should SUCCEED against the vulnerable app."""

    def test_sql_login_bypass(self):
        _skip_if_down(VULN_BASE)
        assert attack_sql_login_bypass(VULN_BASE), "SQL login bypass should succeed on vulnerable app"

    def test_sql_union(self):
        _skip_if_down(VULN_BASE)
        assert attack_sql_union(VULN_BASE), "UNION injection should leak hashes on vulnerable app"

    def test_stored_xss(self):
        _skip_if_down(VULN_BASE)
        assert attack_stored_xss(VULN_BASE), "Stored XSS payload should appear unescaped"

    def test_reflected_xss(self):
        _skip_if_down(VULN_BASE)
        assert attack_reflected_xss(VULN_BASE), "Reflected XSS payload should appear unescaped"

    def test_csrf(self):
        _skip_if_down(VULN_BASE)
        assert attack_csrf(VULN_BASE), "CSRF should succeed (no token check)"
        _reset_passwords()  # restore alice's password changed by CSRF attack

    def test_path_traversal(self):
        _skip_if_down(VULN_BASE)
        assert attack_path_traversal(VULN_BASE), "Path traversal should read files outside messages/"

    def test_horizontal_priv(self):
        _skip_if_down(VULN_BASE)
        assert attack_horizontal_priv(VULN_BASE), "Alice should be able to delete bob's message"

    def test_vertical_priv(self):
        _skip_if_down(VULN_BASE)
        assert attack_vertical_priv(VULN_BASE), "Non-admin should access /admin/users"

    def test_unsafe_upload(self):
        _skip_if_down(VULN_BASE)
        assert attack_unsafe_upload(VULN_BASE), "Uploading .py file should succeed"

    def test_cmd_injection(self):
        _skip_if_down(VULN_BASE)
        assert attack_cmd_injection(VULN_BASE), "Command injection should create marker file"

    def test_brute_force(self):
        _skip_if_down(VULN_BASE)
        assert attack_brute_force(VULN_BASE), "Brute force should not be rate-limited"


class TestProtectedApp:
    """Each attack should FAIL (be blocked) against the protected app."""

    def test_sql_login_bypass(self):
        _skip_if_down(PROT_BASE)
        assert not attack_sql_login_bypass(PROT_BASE), "SQL login bypass should be blocked"

    def test_sql_union(self):
        _skip_if_down(PROT_BASE)
        assert not attack_sql_union(PROT_BASE), "UNION injection should be blocked"

    def test_stored_xss(self):
        _skip_if_down(PROT_BASE)
        assert not attack_stored_xss(PROT_BASE), "Stored XSS payload should be escaped"

    def test_reflected_xss(self):
        _skip_if_down(PROT_BASE)
        assert not attack_reflected_xss(PROT_BASE), "Reflected XSS payload should be escaped"

    def test_csrf(self):
        _skip_if_down(PROT_BASE)
        assert not attack_csrf(PROT_BASE), "CSRF should be blocked (403)"

    def test_path_traversal(self):
        _skip_if_down(PROT_BASE)
        assert not attack_path_traversal(PROT_BASE), "Path traversal should be blocked"

    def test_horizontal_priv(self):
        _skip_if_down(PROT_BASE)
        assert not attack_horizontal_priv(PROT_BASE), "Alice should NOT be able to delete bob's message"

    def test_vertical_priv(self):
        _skip_if_down(PROT_BASE)
        assert not attack_vertical_priv(PROT_BASE), "Non-admin should be denied /admin/users"

    def test_unsafe_upload(self):
        _skip_if_down(PROT_BASE)
        assert not attack_unsafe_upload(PROT_BASE), "Uploading .py file should be blocked"

    def test_cmd_injection(self):
        _skip_if_down(PROT_BASE)
        assert not attack_cmd_injection(PROT_BASE), "Command injection should be blocked"

    def test_brute_force(self):
        _skip_if_down(PROT_BASE)
        assert not attack_brute_force(PROT_BASE), "Brute force should be rate-limited (429)"


# ---------------------------------------------------------------------------
# Standalone formatted comparison table
# ---------------------------------------------------------------------------

def _reset_passwords():
    """Restore test user passwords after CSRF attack changes them."""
    import sqlite3
    import hashlib
    db_path = os.path.join(os.path.dirname(__file__), "..", "app.db")
    db_path = os.path.normpath(db_path)
    if not os.path.exists(db_path):
        return
    def h(pw): return hashlib.md5(pw.encode()).hexdigest()
    db = sqlite3.connect(db_path)
    db.execute("UPDATE users SET password=? WHERE username=?", (h("alice123"), "alice"))
    db.execute("UPDATE users SET password=? WHERE username=?", (h("bob123"), "bob"))
    db.execute("UPDATE users SET password=? WHERE username=?", (h("admin123"), "admin"))
    db.commit()
    db.close()


def _run_all(base: str, label: str) -> list[bool]:
    results = []
    for cn, en, fn in ATTACKS:
        try:
            result = fn(base)
        except Exception as e:
            result = False
            print(f"  [ERROR] {en}: {e}")
        results.append(result)
        # Restore passwords after CSRF test (which changes alice's password)
        if fn is attack_csrf:
            _reset_passwords()
    return results


def print_table(vuln_results: list[bool], prot_results: list[bool]):
    col_attack = 24
    col_en     = 34
    col_vuln   = 12
    col_prot   = 12

    sep = "+" + "-"*(col_attack+2) + "+" + "-"*(col_en+2) + "+" + "-"*(col_vuln+2) + "+" + "-"*(col_prot+2) + "+"
    hdr = (
        f"| {'攻击类型':<{col_attack}} | {'Attack Type':<{col_en}} "
        f"| {'漏洞版(5000)':<{col_vuln}} | {'防护版(5001)':<{col_prot}} |"
    )

    print()
    print(sep)
    print(hdr)
    print(sep)

    for i, (cn, en, _) in enumerate(ATTACKS):
        v = "[+] 成功" if vuln_results[i] else "[-] 失败"
        p = "[!] 绕过" if prot_results[i] else "[x] 拦截"
        print(
            f"| {cn:<{col_attack}} | {en:<{col_en}} "
            f"| {v:<{col_vuln}} | {p:<{col_prot}} |"
        )

    print(sep)

    total = len(ATTACKS)
    vuln_ok  = sum(vuln_results)
    prot_blocked = total - sum(prot_results)
    prot_rate = prot_blocked / total * 100

    print(f"\n漏洞版攻击成功率: {vuln_ok}/{total} ({vuln_ok/total*100:.0f}%)")
    print(f"防护版拦截成功率: {prot_blocked}/{total} ({prot_rate:.0f}%)")
    print()


if __name__ == "__main__":
    # Ensure UTF-8 output on Windows
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print("=" * 80)
    print("Web 漏洞攻防对比测试")
    print("=" * 80)

    vuln_up = _is_up(VULN_BASE)
    prot_up = _is_up(PROT_BASE)

    if not vuln_up:
        print(f"[WARN] Vulnerable app not running at {VULN_BASE}")
    if not prot_up:
        print(f"[WARN] Protected app not running at {PROT_BASE}")

    if not vuln_up and not prot_up:
        print("Neither app is running. Start them first:")
        print("  python -m app.vulnerable.app   # port 5000")
        print("  python -m app.protected.app    # port 5001")
        sys.exit(1)

    print("\nRunning attacks against vulnerable app...")
    vuln_results = _run_all(VULN_BASE, "Vulnerable") if vuln_up else [False] * len(ATTACKS)

    print("Running attacks against protected app...")
    prot_results = _run_all(PROT_BASE, "Protected") if prot_up else [False] * len(ATTACKS)

    print_table(vuln_results, prot_results)
