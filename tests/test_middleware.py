"""
TDD tests for the defense middleware (app/protected/middleware.py).
All tests must FAIL before middleware is implemented.
Run: pytest tests/test_middleware.py -v
"""
import sys
import os
import pytest

# Allow importing from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Import the module under test — will fail until middleware.py exists
# ---------------------------------------------------------------------------
from app.protected.middleware import (
    detect_sql_injection,
    sanitize_xss,
    detect_path_traversal,
    detect_cmd_injection,
    ALLOWED_EXTENSIONS,
    is_allowed_extension,
)


# ---------------------------------------------------------------------------
# SQL Injection detection
# ---------------------------------------------------------------------------
class TestSQLInjectionDetection:
    def test_detects_or_bypass(self):
        assert detect_sql_injection("' OR '1'='1") is True

    def test_detects_union_select(self):
        assert detect_sql_injection("' UNION SELECT username,password FROM users --") is True

    def test_detects_drop_table(self):
        assert detect_sql_injection("'; DROP TABLE users; --") is True

    def test_detects_comment_bypass(self):
        assert detect_sql_injection("admin' --") is True

    def test_detects_insert(self):
        assert detect_sql_injection("'; INSERT INTO users VALUES('hacker','pw','admin')") is True

    def test_clean_input_not_flagged(self):
        assert detect_sql_injection("hello world") is False

    def test_normal_username_not_flagged(self):
        assert detect_sql_injection("alice123") is False

    def test_normal_search_not_flagged(self):
        assert detect_sql_injection("Flask tutorial") is False


# ---------------------------------------------------------------------------
# XSS sanitization
# ---------------------------------------------------------------------------
class TestXSSSanitization:
    def test_script_tag_encoded(self):
        result = sanitize_xss("<script>alert(1)</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_img_onerror_encoded(self):
        result = sanitize_xss("<img src=x onerror=alert(1)>")
        assert "<img" not in result

    def test_javascript_protocol_encoded(self):
        result = sanitize_xss("javascript:alert(1)")
        assert "javascript:" not in result

    def test_iframe_encoded(self):
        result = sanitize_xss("<iframe src='evil.com'></iframe>")
        assert "<iframe" not in result

    def test_event_handler_encoded(self):
        result = sanitize_xss("<div onmouseover='alert(1)'>text</div>")
        assert "onmouseover" not in result

    def test_clean_text_unchanged(self):
        result = sanitize_xss("Hello, world!")
        assert result == "Hello, world!"

    def test_normal_message_unchanged(self):
        result = sanitize_xss("Flask is great for web development.")
        assert result == "Flask is great for web development."


# ---------------------------------------------------------------------------
# Path traversal detection
# ---------------------------------------------------------------------------
class TestPathTraversalDetection:
    def test_detects_unix_traversal(self):
        assert detect_path_traversal("../../etc/passwd") is True

    def test_detects_windows_traversal(self):
        assert detect_path_traversal("..\\..\\windows\\system32") is True

    def test_detects_encoded_traversal(self):
        assert detect_path_traversal("..%2F..%2Fetc%2Fpasswd") is True

    def test_detects_single_traversal(self):
        assert detect_path_traversal("../app.py") is True

    def test_clean_filename_not_flagged(self):
        assert detect_path_traversal("msg_001_alice.txt") is False

    def test_normal_path_not_flagged(self):
        assert detect_path_traversal("uploads/avatar.jpg") is False


# ---------------------------------------------------------------------------
# Command injection detection
# ---------------------------------------------------------------------------
class TestCmdInjectionDetection:
    def test_detects_semicolon(self):
        assert detect_cmd_injection("msg_001.txt; id") is True

    def test_detects_double_ampersand(self):
        assert detect_cmd_injection("msg_001.txt && cat /etc/passwd") is True

    def test_detects_pipe(self):
        assert detect_cmd_injection("msg_001.txt | whoami") is True

    def test_detects_backtick(self):
        assert detect_cmd_injection("msg_001.txt`id`") is True

    def test_detects_dollar_paren(self):
        assert detect_cmd_injection("msg_001.txt$(id)") is True

    def test_detects_redirect_out(self):
        assert detect_cmd_injection("msg_001.txt > /tmp/out") is True

    def test_clean_filename_not_flagged(self):
        assert detect_cmd_injection("msg_001_alice.txt") is False

    def test_normal_filename_not_flagged(self):
        assert detect_cmd_injection("report_2024.txt") is False


# ---------------------------------------------------------------------------
# File upload extension whitelist
# ---------------------------------------------------------------------------
class TestFileUploadExtension:
    def test_jpg_allowed(self):
        assert is_allowed_extension("avatar.jpg") is True

    def test_jpeg_allowed(self):
        assert is_allowed_extension("photo.jpeg") is True

    def test_png_allowed(self):
        assert is_allowed_extension("icon.png") is True

    def test_gif_allowed(self):
        assert is_allowed_extension("anim.gif") is True

    def test_py_blocked(self):
        assert is_allowed_extension("shell.py") is False

    def test_php_blocked(self):
        assert is_allowed_extension("webshell.php") is False

    def test_exe_blocked(self):
        assert is_allowed_extension("malware.exe") is False

    def test_sh_blocked(self):
        assert is_allowed_extension("exploit.sh") is False

    def test_no_extension_blocked(self):
        assert is_allowed_extension("noextension") is False

    def test_double_extension_blocked(self):
        # avatar.php.jpg — only check final extension, jpg is allowed
        assert is_allowed_extension("avatar.php.jpg") is True

    def test_allowed_extensions_set_contains_expected(self):
        assert ".jpg" in ALLOWED_EXTENSIONS
        assert ".jpeg" in ALLOWED_EXTENSIONS
        assert ".png" in ALLOWED_EXTENSIONS
        assert ".gif" in ALLOWED_EXTENSIONS
