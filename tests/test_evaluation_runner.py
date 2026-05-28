import pytest
from evaluation.runner import (
    Result,
    _build_request_kwargs,
    _build_file_content,
    ENDPOINTS,
)


def test_build_query_param_request():
    payload = {
        "id": "sqli-001",
        "payload": "' OR 1=1--",
        "category": "sql_injection",
        "inject_point": "query_param",
        "param_name": "q",
    }
    method, url_path, kwargs = _build_request_kwargs(payload)
    assert method == "GET"
    assert url_path == "/search"
    assert kwargs["params"] == {"q": "' OR 1=1--"}


def test_build_form_body_request():
    payload = {
        "id": "sqli-002",
        "payload": "admin' --",
        "category": "sql_injection",
        "inject_point": "form_body",
        "param_name": "username",
    }
    method, url_path, kwargs = _build_request_kwargs(payload)
    assert method == "POST"
    assert kwargs["data"]["username"] == "admin' --"


def test_build_path_request():
    payload = {
        "id": "pt-001",
        "payload": "../../etc/passwd",
        "category": "path_traversal",
        "inject_point": "path",
        "param_name": "filename",
    }
    method, url_path, kwargs = _build_request_kwargs(payload)
    assert method == "GET"
    assert kwargs["params"] == {"filename": "../../etc/passwd"}


def test_build_filename_request():
    payload = {
        "id": "up-001",
        "payload": "shell.php.jpg",
        "category": "file_upload",
        "inject_point": "filename",
        "param_name": "avatar",
        "file_content": "png-magic-padding",
    }
    method, url_path, kwargs = _build_request_kwargs(payload)
    assert method == "POST"
    assert "files" in kwargs
    field, file_tuple = next(iter(kwargs["files"].items()))
    assert field == "avatar"
    fname, content, ctype = file_tuple
    assert fname == "shell.php.jpg"
    assert content.startswith(b"\x89PNG")


def test_file_content_php_payload():
    data = _build_file_content("php-payload")
    assert b"<?php" in data


def test_file_content_jpg_magic():
    data = _build_file_content("jpg-magic-padding")
    assert data[:3] == b"\xff\xd8\xff"


def test_file_content_unknown_kind_raises():
    with pytest.raises(ValueError, match="unknown"):
        _build_file_content("not-a-real-kind")


def test_result_outcome_tp():
    r = Result(
        payload_id="x", category="sql_injection", expected="blocked",
        blocked=True, status_code=403, latency_ms=12.3, error=None,
    )
    assert r.outcome == "TP"


def test_result_outcome_fp():
    r = Result(
        payload_id="x", category="benign", expected="allowed",
        blocked=True, status_code=403, latency_ms=1.0, error=None,
    )
    assert r.outcome == "FP"


def test_result_outcome_fn():
    r = Result(
        payload_id="x", category="sql_injection", expected="blocked",
        blocked=False, status_code=200, latency_ms=1.0, error=None,
    )
    assert r.outcome == "FN"


def test_result_outcome_tn():
    r = Result(
        payload_id="x", category="benign", expected="allowed",
        blocked=False, status_code=200, latency_ms=1.0, error=None,
    )
    assert r.outcome == "TN"


def test_unknown_inject_point_raises():
    payload = {
        "id": "bad-001",
        "payload": "x",
        "category": "sql_injection",
        "inject_point": "not_a_real_point",
        "param_name": "q",
    }
    with pytest.raises(ValueError, match="inject_point"):
        _build_request_kwargs(payload)


def test_build_header_request_uses_default_q():
    payload = {
        "id": "rl-001",
        "payload": "1.2.3.4",
        "category": "rate_limit",
        "inject_point": "header",
        "param_name": "X-Forwarded-For",
    }
    method, url_path, kwargs = _build_request_kwargs(payload)
    assert method == "GET"
    assert url_path == "/search"
    assert kwargs["headers"] == {"X-Forwarded-For": "1.2.3.4"}
    assert kwargs["params"] == {"q": "test"}


def test_build_header_request_custom_base_params():
    payload = {
        "id": "rl-002",
        "payload": "1.2.3.4",
        "category": "rate_limit",
        "inject_point": "header",
        "param_name": "X-Forwarded-For",
        "base_params": {"q": "hello"},
    }
    method, url_path, kwargs = _build_request_kwargs(payload)
    assert kwargs["params"] == {"q": "hello"}
