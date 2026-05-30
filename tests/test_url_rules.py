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


from waf.url_rules import _compile_url_pattern  # private but tested directly


class TestCompileUrlPattern:
    def test_exact_no_wildcard(self):
        kind, pattern = _compile_url_pattern("/login", entry_index=0)
        assert kind == "exact"
        assert pattern == "/login"

    def test_prefix_wildcard(self):
        kind, pattern = _compile_url_pattern("/api/*", entry_index=0)
        assert kind == "prefix"
        assert pattern == "/api"

    def test_prefix_wildcard_deep(self):
        kind, pattern = _compile_url_pattern("/foo/bar/*", entry_index=0)
        assert kind == "prefix"
        assert pattern == "/foo/bar"

    def test_catchall(self):
        kind, pattern = _compile_url_pattern("/*", entry_index=0)
        assert kind == "catchall"
        assert pattern == ""

    def test_url_must_start_with_slash(self):
        with pytest.raises(UrlRulesError, match=r"rules\[2\]: url must start with '/'"):
            _compile_url_pattern("api/foo", entry_index=2)

    def test_url_must_be_string(self):
        with pytest.raises(UrlRulesError, match=r"rules\[1\]: url must be a string"):
            _compile_url_pattern(123, entry_index=1)  # type: ignore[arg-type]

    def test_wildcard_only_at_end(self):
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: '\*' is only allowed at the end"):
            _compile_url_pattern("/api/*/admin", entry_index=0)

    def test_wildcard_must_follow_slash(self):
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: '\*' is only allowed at the end"):
            _compile_url_pattern("/api*", entry_index=0)
