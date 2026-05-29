"""Loader + matcher tests for waf.url_rules. TDD-driven."""
import pytest

from waf.url_rules import (
    UrlRules,
    UrlRulesError,
    load_url_rules,
    is_rule_enabled,
    emit_global_mask_warnings,
)


def test_module_imports():
    """Smoke test: all public names are importable."""
    assert UrlRulesError is not None
    assert UrlRules is not None
    assert callable(load_url_rules)
    assert callable(is_rule_enabled)
    assert callable(emit_global_mask_warnings)


@pytest.fixture
def tmp_yaml(tmp_path):
    """Write a YAML body to a temp file and return the path."""
    def _write(body: str) -> str:
        p = tmp_path / "rules.yaml"
        p.write_text(body, encoding="utf-8")
        return str(p)
    return _write
