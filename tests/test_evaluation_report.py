import pytest

from evaluation.report import _compute_metrics
from evaluation.runner import Result


def make_result(category, expected, blocked):
    return Result(
        payload_id="x", category=category, expected=expected,
        blocked=blocked, status_code=200, latency_ms=1.0, error=None,
    )


def test_metrics_basic():
    results = [
        make_result("sql_injection", "blocked", True),
        make_result("sql_injection", "blocked", True),
        make_result("sql_injection", "blocked", False),  # FN
        make_result("benign", "allowed", True),  # FP
        make_result("benign", "allowed", False),
        make_result("benign", "allowed", False),
    ]
    metrics = _compute_metrics(results)
    assert metrics["sql_injection"]["TP"] == 2
    assert metrics["sql_injection"]["FN"] == 1
    assert metrics["sql_injection"]["TPR"] == pytest.approx(2 / 3)
    assert metrics["benign"]["FP"] == 1
    assert metrics["benign"]["TN"] == 2
    assert metrics["benign"]["FPR"] == pytest.approx(1 / 3)


def test_metrics_handles_zero_division():
    results = []
    metrics = _compute_metrics(results)
    assert metrics == {}
