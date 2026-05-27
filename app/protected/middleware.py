"""
Defense middleware for the protected Flask app.
Registered via before_request / after_request hooks.
"""
import re
import os
import time
import logging
from html import escape
from functools import wraps
from flask import request, session, abort, g

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif"}

# Routes that require admin role
ADMIN_ROUTES = re.compile(r"^/admin(/|$)")

# Login route for rate-limiting
LOGIN_ROUTE = "/login"

# Rate-limit state: { ip: {"count": int, "window_start": float, "locked_until": float} }
_rate_limit_state: dict = {}
RATE_LIMIT_MAX_FAILURES = 10
RATE_LIMIT_WINDOW = 60       # seconds
RATE_LIMIT_LOCKOUT = 300     # 5 minutes

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_log_path = os.path.join(os.path.dirname(__file__), "..", "..", "security.log")
_security_logger = logging.getLogger("security")
if not _security_logger.handlers:
    _handler = logging.FileHandler(_log_path, encoding="utf-8")
    _handler.setFormatter(
        logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    _security_logger.addHandler(_handler)
    _security_logger.setLevel(logging.WARNING)


def _log_block(attack_type: str, payload: str):
    ip = request.remote_addr or "unknown"
    path = request.path
    snippet = payload[:200]
    _security_logger.warning(
        "BLOCKED | type=%s | ip=%s | path=%s | payload=%s",
        attack_type, ip, path, snippet,
    )


# ---------------------------------------------------------------------------
# Detection / sanitization functions (pure, testable without Flask context)
# ---------------------------------------------------------------------------

# SQL injection: keyword patterns that appear in injection payloads
_SQL_PATTERN = re.compile(
    r"\b(union|select|insert|update|delete|drop|create|alter|exec|execute"
    r"|information_schema|sleep|benchmark|load_file|outfile)\b"
    r"|'[\s]*--"
    r"|--[\s]"
    r"|;\s*(drop|insert|update|delete|select)"
    r"|'\s*(or|and)\s+'?\d"
    r"|'\s*or\s*'",
    re.IGNORECASE,
)


def detect_sql_injection(value: str) -> bool:
    """Return True if value contains SQL injection patterns."""
    return bool(_SQL_PATTERN.search(value))


# XSS: dangerous HTML/JS patterns
_XSS_TAGS = re.compile(
    r"<\s*(script|iframe|object|embed|form|input|button|link|meta|style|svg|math|img|div|span)"
    r"|javascript\s*:"
    r"|\bon\w+\s*=",
    re.IGNORECASE,
)


def sanitize_xss(value: str) -> str:
    """HTML-encode value if it contains XSS patterns; return clean value unchanged."""
    if not _XSS_TAGS.search(value):
        return value
    # First HTML-escape all special chars, then additionally neutralize
    # dangerous keywords that survive escaping (javascript:, on*=)
    result = escape(value, quote=True)
    result = re.sub(r"javascript\s*:", "javascript&#58;", result, flags=re.IGNORECASE)
    result = re.sub(r"\bon(\w+)\s*=", r"data-blocked-\1=", result, flags=re.IGNORECASE)
    return result


# Path traversal
_PATH_TRAVERSAL = re.compile(r"\.\.[/\\]|\.\.%2[fF]|\.\.%5[cC]")


def detect_path_traversal(value: str) -> bool:
    """Return True if value contains path traversal sequences."""
    return bool(_PATH_TRAVERSAL.search(value))


# Command injection: shell metacharacters
_CMD_CHARS = re.compile(r"[;&|`$]|\$\(|>>?|<")


def detect_cmd_injection(value: str) -> bool:
    """Return True if value contains shell special characters."""
    return bool(_CMD_CHARS.search(value))


def is_allowed_extension(filename: str) -> bool:
    """Return True if filename has a whitelisted extension."""
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_EXTENSIONS


# ---------------------------------------------------------------------------
# CSRF helpers
# ---------------------------------------------------------------------------

import secrets


def generate_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf_token() -> bool:
    token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    return token is not None and token == session.get("csrf_token")


# ---------------------------------------------------------------------------
# Rate limiting helpers
# ---------------------------------------------------------------------------

def check_rate_limit(ip: str) -> bool:
    """Return True if the IP is currently locked out."""
    now = time.time()
    state = _rate_limit_state.get(ip)
    if state is None:
        return False
    if now < state.get("locked_until", 0):
        return True
    return False


def record_login_failure(ip: str):
    """Record a failed login attempt; lock out if threshold exceeded."""
    now = time.time()
    state = _rate_limit_state.setdefault(
        ip, {"count": 0, "window_start": now, "locked_until": 0}
    )
    if now - state["window_start"] > RATE_LIMIT_WINDOW:
        state["count"] = 0
        state["window_start"] = now
    state["count"] += 1
    if state["count"] > RATE_LIMIT_MAX_FAILURES:
        state["locked_until"] = now + RATE_LIMIT_LOCKOUT


def reset_rate_limit(ip: str):
    """Clear rate-limit state on successful login."""
    _rate_limit_state.pop(ip, None)


# ---------------------------------------------------------------------------
# Flask middleware registration
# ---------------------------------------------------------------------------

def register_middleware(app):
    """Attach before_request and after_request hooks to a Flask app."""

    @app.before_request
    def _before():
        ip = request.remote_addr or "unknown"

        # 1. Rate-limit check on login POST
        if request.path == LOGIN_ROUTE and request.method == "POST":
            if check_rate_limit(ip):
                _log_block("brute-force", f"ip={ip}")
                abort(429)

        # 2. CSRF validation for all state-changing POST requests
        #    Skip login and register (they don't need CSRF — no session yet)
        csrf_exempt = {LOGIN_ROUTE, "/register"}
        if request.method == "POST" and request.path not in csrf_exempt:
            if not validate_csrf_token():
                _log_block("csrf", request.form.get("csrf_token", ""))
                abort(403)

        # 3. Role-based access control for /admin/* routes
        if ADMIN_ROUTES.match(request.path):
            if session.get("role") != "admin":
                _log_block("vertical-privilege-escalation", request.path)
                abort(403)

        # 4. Scan all string parameters (GET + POST)
        all_values = list(request.args.values()) + list(request.form.values())
        for val in all_values:
            if not isinstance(val, str):
                continue

            if detect_sql_injection(val):
                _log_block("sql-injection", val)
                abort(403)

            if detect_path_traversal(val):
                _log_block("path-traversal", val)
                abort(403)

            if detect_cmd_injection(val):
                _log_block("cmd-injection", val)
                abort(403)

        # 5. File upload extension check
        for _field, file_storage in request.files.items():
            if file_storage and file_storage.filename:
                if not is_allowed_extension(file_storage.filename):
                    _log_block("unsafe-upload", file_storage.filename)
                    abort(400)

        # 6. XSS sanitization — mutate g so routes read sanitized values
        #    (routes should use g.safe_args / g.safe_form instead of request.args/form)
        g.safe_args = {k: sanitize_xss(v) for k, v in request.args.items()}
        g.safe_form = {k: sanitize_xss(v) for k, v in request.form.items()}

    @app.after_request
    def _after(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
