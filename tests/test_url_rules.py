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
