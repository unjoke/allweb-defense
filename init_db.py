import sqlite3
import os
import hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")
MESSAGES_DIR = os.path.join(BASE_DIR, "messages")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def init_db(db_path=DB_PATH):
    os.makedirs(MESSAGES_DIR, exist_ok=True)
    os.makedirs(UPLOADS_DIR, exist_ok=True)

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            email TEXT,
            avatar TEXT
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            filepath TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Seed users
    users = [
        ("admin", hash_password("admin123"), "admin", "admin@example.com"),
        ("alice", hash_password("alice123"), "user", "alice@example.com"),
        ("bob", hash_password("bob123"), "user", "bob@example.com"),
    ]
    for username, pw, role, email in users:
        c.execute(
            "INSERT OR IGNORE INTO users (username, password, role, email) VALUES (?,?,?,?)",
            (username, pw, role, email),
        )

    # Seed messages with txt files
    conn.commit()
    c.execute("SELECT id FROM users WHERE username='alice'")
    row = c.fetchone()
    if row:
        alice_id = row[0]
        seed_messages = [
            (alice_id, "alice", "Hello everyone, this is Alice!"),
            (alice_id, "alice", "Flask is a great framework."),
        ]
        for uid, uname, content in seed_messages:
            c.execute(
                "SELECT id FROM messages WHERE username=? AND content=?",
                (uname, content),
            )
            if not c.fetchone():
                c.execute(
                    "INSERT INTO messages (user_id, username, content) VALUES (?,?,?)",
                    (uid, uname, content),
                )
                msg_id = c.lastrowid
                filepath = os.path.join(
                    MESSAGES_DIR, f"msg_{msg_id}_{uname}.txt"
                )
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)
                c.execute(
                    "UPDATE messages SET filepath=? WHERE id=?",
                    (filepath, msg_id),
                )

    conn.commit()
    conn.close()
    print(f"Database initialized at {db_path}")


if __name__ == "__main__":
    init_db()
