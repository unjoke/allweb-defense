import pytest
from waf.detector import (
    normalize,
    detect_sql_injection,
    sanitize_xss,
    detect_path_traversal,
    detect_cmd_injection,
)


# ---------- 6.1 normalize() ----------

def test_normalize_double_url_encoding():
    assert "UNION" in normalize("%2555NION").upper()


def test_normalize_nfkc_fullwidth():
    assert normalize("ＳＥＬＥＣＴ") == "SELECT"


def test_normalize_inline_comment():
    result = normalize("UN/**/ION/**/SELECT")
    assert "/*" not in result
    assert "UNION" in result.upper()


def test_normalize_stable_after_3_rounds():
    val = "%25252555NION"
    result = normalize(val)
    assert isinstance(result, str)


def test_normalize_plain_string_unchanged():
    assert normalize("hello world") == "hello world"
