import time
import waf.detector as d


def test_import_without_flask():
    import waf.detector


# --- detect_sql_injection ---

def test_sql_union_injection():
    assert d.detect_sql_injection("' UNION SELECT * FROM users--") is True

def test_sql_or_injection():
    assert d.detect_sql_injection("' OR '1'='1") is True

def test_sql_drop_injection():
    assert d.detect_sql_injection("'; DROP TABLE users; --") is True

def test_sql_clean_string():
    assert d.detect_sql_injection("hello world") is False

def test_sql_normal_username():
    assert d.detect_sql_injection("alice123") is False


# --- sanitize_xss ---

def test_xss_script_tag_sanitized():
    result = d.sanitize_xss("<script>alert(1)</script>")
    assert "<script>" not in result

def test_xss_javascript_protocol_sanitized():
    result = d.sanitize_xss("javascript:alert(1)")
    assert "javascript:" not in result

def test_xss_event_handler_sanitized():
    result = d.sanitize_xss('<img onerror="alert(1)">')
    assert "onerror=" not in result

def test_xss_clean_string_unchanged():
    assert d.sanitize_xss("hello world") == "hello world"

def test_xss_normal_message_unchanged():
    assert d.sanitize_xss("Good morning!") == "Good morning!"


# --- detect_path_traversal ---

def test_path_traversal_dotdot_slash():
    assert d.detect_path_traversal("../../etc/passwd") is True

def test_path_traversal_encoded():
    assert d.detect_path_traversal("..%2fetc%2fpasswd") is True

def test_path_traversal_clean():
    assert d.detect_path_traversal("messages/msg_1.txt") is False

def test_path_traversal_normal_filename():
    assert d.detect_path_traversal("avatar.jpg") is False


# --- detect_cmd_injection ---

def test_cmd_semicolon():
    assert d.detect_cmd_injection("msg_1.txt; id") is True

def test_cmd_ampersand():
    assert d.detect_cmd_injection("msg_1.txt && cat /etc/passwd") is True

def test_cmd_pipe():
    assert d.detect_cmd_injection("msg_1.txt | whoami") is True

def test_cmd_clean_filename():
    assert d.detect_cmd_injection("msg_1_alice.txt") is False

def test_cmd_normal_string():
    assert d.detect_cmd_injection("hello world") is False


# --- is_allowed_extension ---

def test_extension_jpg_allowed():
    assert d.is_allowed_extension("avatar.jpg") is True

def test_extension_jpeg_allowed():
    assert d.is_allowed_extension("photo.jpeg") is True

def test_extension_png_allowed():
    assert d.is_allowed_extension("image.PNG") is True  # case-insensitive

def test_extension_gif_allowed():
    assert d.is_allowed_extension("anim.gif") is True

def test_extension_py_blocked():
    assert d.is_allowed_extension("shell.py") is False

def test_extension_php_blocked():
    assert d.is_allowed_extension("backdoor.php") is False

def test_extension_no_ext_blocked():
    assert d.is_allowed_extension("noextension") is False


# --- rate limit ---

def test_rate_limit_not_locked_initially():
    state = {}
    config = {"max_failures": 3, "window": 60, "lockout": 300}
    assert d.check_rate_limit("1.2.3.4", state, config) is False

def test_rate_limit_locked_after_threshold():
    state = {}
    config = {"max_failures": 3, "window": 60, "lockout": 300}
    ip = "1.2.3.4"
    for _ in range(4):  # one more than max_failures
        d.record_login_failure(ip, state, config)
    assert d.check_rate_limit(ip, state, config) is True

def test_rate_limit_not_locked_below_threshold():
    state = {}
    config = {"max_failures": 3, "window": 60, "lockout": 300}
    ip = "1.2.3.4"
    for _ in range(3):  # exactly max_failures, not exceeded
        d.record_login_failure(ip, state, config)
    assert d.check_rate_limit(ip, state, config) is False

def test_rate_limit_independent_ips():
    state = {}
    config = {"max_failures": 3, "window": 60, "lockout": 300}
    for _ in range(4):
        d.record_login_failure("1.1.1.1", state, config)
    assert d.check_rate_limit("1.1.1.1", state, config) is True
    assert d.check_rate_limit("2.2.2.2", state, config) is False
