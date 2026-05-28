import re
import os
import time
import urllib.parse
import unicodedata
from html import escape

_INLINE_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def normalize(value: str) -> str:
    decoded = value
    for _ in range(3):
        nxt = urllib.parse.unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    normalized = unicodedata.normalize("NFKC", decoded)
    return _INLINE_COMMENT.sub("", normalized)


_SQL_PATTERN = re.compile(
    r"\b(union|select|insert|update|delete|drop|create|alter|exec|execute"
    r"|information_schema|sleep|benchmark|load_file|outfile)\b"
    r"|'[\s]*--"
    r"|--[\s]"
    r"|;\s*(drop|insert|update|delete|select)"
    r"|'\s*(or|and)\s+'?\d"
    r"|'\s*or\s*'"
    r"|char\s*\("
    r"|0x[0-9a-f]{6,}"
    r"|`\s*(union|select|insert|update|delete|drop)\s*`"
    r"|'\s*\|\|\s*'",
    re.IGNORECASE,
)

_XSS_TAGS = re.compile(
    r"<\s*(script|iframe|object|embed|form|input|button|link|meta|style|svg|math|img|div|span)"
    r"|javascript\s*:"
    r"|\bon\w+\s*=",
    re.IGNORECASE,
)

_PATH_TRAVERSAL = re.compile(r"\.\.[/\\]|\.\.%2[fF]|\.\.%5[cC]")

_CMD_CHARS = re.compile(r"[;&|`$]|\$\(")

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif"}


def detect_sql_injection(value: str) -> bool:
    return bool(_SQL_PATTERN.search(value))


def sanitize_xss(value: str) -> str:
    if not _XSS_TAGS.search(value):
        return value
    result = escape(value, quote=True)
    result = re.sub(r"javascript\s*:", "javascript&#58;", result, flags=re.IGNORECASE)
    result = re.sub(r"\bon(\w+)\s*=", r"data-blocked-\1=", result, flags=re.IGNORECASE)
    return result


def detect_path_traversal(value: str) -> bool:
    return bool(_PATH_TRAVERSAL.search(value))


def detect_cmd_injection(value: str) -> bool:
    return bool(_CMD_CHARS.search(value))


def is_allowed_extension(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_EXTENSIONS


def check_rate_limit(ip: str, state: dict) -> bool:
    now = time.time()
    entry = state.get(ip)
    if entry is None:
        return False
    return now < entry.get("locked_until", 0)


def record_login_failure(ip: str, state: dict, config: dict) -> None:
    now = time.time()
    entry = state.setdefault(ip, {"count": 0, "window_start": now, "locked_until": 0})
    if now - entry["window_start"] > config.get("window", 60):
        entry["count"] = 0
        entry["window_start"] = now
    entry["count"] += 1
    if entry["count"] > config.get("max_failures", 10):
        entry["locked_until"] = now + config.get("lockout", 300)
