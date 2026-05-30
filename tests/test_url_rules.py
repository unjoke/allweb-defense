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


class TestLoaderStrict:
    # V1: YAML parse error
    def test_v1_yaml_parse_error(self, tmp_yaml):
        path = tmp_yaml('rules:\n  - url: "/foo\n    detect: [SQL]\n')  # unclosed quote
        with pytest.raises(UrlRulesError, match=r"failed to parse YAML"):
            load_url_rules(path)

    # V2: top-level not a mapping
    def test_v2_top_level_not_mapping(self, tmp_yaml):
        path = tmp_yaml("- just\n- a\n- list\n")
        with pytest.raises(UrlRulesError, match=r"top-level must be a mapping"):
            load_url_rules(path)

    # V3: rules key missing or non-list
    def test_v3a_rules_key_missing(self, tmp_yaml):
        path = tmp_yaml("other_key: value\n")
        with pytest.raises(UrlRulesError, match=r"top-level must be a mapping with key 'rules'"):
            load_url_rules(path)

    def test_v3b_rules_not_list(self, tmp_yaml):
        path = tmp_yaml("rules: not_a_list\n")
        with pytest.raises(UrlRulesError, match=r"'rules' must be a list"):
            load_url_rules(path)

    # V4: entry missing url
    def test_v4a_missing_url(self, tmp_yaml):
        path = tmp_yaml("rules:\n  - detect: [SQL]\n")
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: missing required field 'url'"):
            load_url_rules(path)

    def test_v4b_missing_detect(self, tmp_yaml):
        path = tmp_yaml("rules:\n  - url: /foo\n")
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: missing required field 'detect'"):
            load_url_rules(path)

    # V5: unknown entry field
    def test_v5_unknown_field(self, tmp_yaml):
        path = tmp_yaml("rules:\n  - url: /foo\n    detect: [SQL]\n    method: POST\n")
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: unknown field 'method'"):
            load_url_rules(path)

    # V6: url not /-prefixed (covered by Task 3 unit test, but verify via loader path too)
    def test_v6_url_not_prefixed(self, tmp_yaml):
        path = tmp_yaml("rules:\n  - url: api/foo\n    detect: [SQL]\n")
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: url must start with '/'"):
            load_url_rules(path)

    # V7: wildcard not at end (covered by Task 3, but verify via loader path)
    def test_v7_wildcard_position(self, tmp_yaml):
        path = tmp_yaml("rules:\n  - url: /api/*/admin\n    detect: [SQL]\n")
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: '\*' is only allowed at the end"):
            load_url_rules(path)

    # V8: detect not a list
    def test_v8_detect_not_list(self, tmp_yaml):
        path = tmp_yaml("rules:\n  - url: /foo\n    detect: SQL\n")
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: detect must be a list"):
            load_url_rules(path)

    # V9: detect empty
    def test_v9_detect_empty(self, tmp_yaml):
        path = tmp_yaml("rules:\n  - url: /foo\n    detect: []\n")
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: detect must not be empty"):
            load_url_rules(path)

    # V10: unknown token + wrong case
    def test_v10a_unknown_token(self, tmp_yaml):
        path = tmp_yaml("rules:\n  - url: /foo\n    detect: [FOO]\n")
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: unknown token 'FOO'"):
            load_url_rules(path)

    def test_v10b_lowercase_token(self, tmp_yaml):
        path = tmp_yaml("rules:\n  - url: /foo\n    detect: [sql]\n")
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: unknown token 'sql'"):
            load_url_rules(path)

    def test_v10c_rate_token(self, tmp_yaml):
        path = tmp_yaml("rules:\n  - url: /foo\n    detect: [RATE]\n")
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: unknown token 'RATE'"):
            load_url_rules(path)

    def test_v10d_csrf_token(self, tmp_yaml):
        path = tmp_yaml("rules:\n  - url: /foo\n    detect: [CSRF]\n")
        with pytest.raises(UrlRulesError, match=r"rules\[0\]: unknown token 'CSRF'"):
            load_url_rules(path)

    # V11: duplicate url
    def test_v11_duplicate_url(self, tmp_yaml):
        path = tmp_yaml(
            "rules:\n"
            "  - url: /search\n    detect: [SQL]\n"
            "  - url: /search\n    detect: [XSS]\n"
        )
        with pytest.raises(UrlRulesError, match=r"rules\[1\]: duplicate url '/search' \(also at rules\[0\]\)"):
            load_url_rules(path)


class TestLoaderPositive:
    def test_minimal_valid_file(self, tmp_yaml):
        path = tmp_yaml(
            "rules:\n"
            "  - url: /search\n    detect: [SQL, XSS]\n"
            "  - url: /upload/*\n    detect: [UPLOAD, PATH]\n"
            "  - url: /*\n    detect: [SQL]\n"
        )
        url_rules = load_url_rules(path)
        assert len(url_rules.rules) == 3
        assert url_rules.rules[0].kind == "exact"
        assert url_rules.rules[0].pattern == "/search"
        assert url_rules.rules[0].detect_keys == frozenset({"sql_injection", "xss"})
        assert url_rules.rules[1].kind == "prefix"
        assert url_rules.rules[1].pattern == "/upload"
        assert url_rules.rules[2].kind == "catchall"

    def test_file_not_found(self, tmp_path):
        # FileNotFoundError must propagate (config layer turns it into sys.exit)
        with pytest.raises(FileNotFoundError):
            load_url_rules(str(tmp_path / "nope.yaml"))


class TestMatcher:
    @staticmethod
    def _build(yaml_body: str, tmp_yaml) -> UrlRules:
        return load_url_rules(tmp_yaml(yaml_body))

    # M1: exact hit
    def test_m1_exact_hit(self, tmp_yaml):
        ur = self._build("rules:\n  - url: /login\n    detect: [SQL]\n", tmp_yaml)
        assert ur.is_enabled("/login", "sql_injection") is True

    # M2: exact does NOT match trailing-slash variant
    def test_m2_exact_no_trailing_slash_match(self, tmp_yaml):
        ur = self._build("rules:\n  - url: /login\n    detect: [SQL]\n", tmp_yaml)
        # /login/ does not match /login: no rule matches → default-on
        assert ur.is_enabled("/login/", "sql_injection") is True
        # And other keys also default-on for the unmatched path
        assert ur.is_enabled("/login/", "xss") is True
        # On /login itself, only SQL is on; XSS is narrowed away
        assert ur.is_enabled("/login", "xss") is False

    # M3: prefix matches sub-paths
    def test_m3_prefix_sub_paths(self, tmp_yaml):
        ur = self._build("rules:\n  - url: /api/*\n    detect: [SQL]\n", tmp_yaml)
        assert ur.is_enabled("/api/foo", "sql_injection") is True
        assert ur.is_enabled("/api/foo/bar", "sql_injection") is True
        # XSS narrowed away on those paths
        assert ur.is_enabled("/api/foo", "xss") is False

    # M4: prefix requires segment boundary
    def test_m4_prefix_segment_boundary(self, tmp_yaml):
        ur = self._build("rules:\n  - url: /api/*\n    detect: [SQL]\n", tmp_yaml)
        # /apifoo does NOT match /api/* (no segment boundary)
        assert ur.is_enabled("/apifoo", "sql_injection") is True   # default-on, not narrowed
        assert ur.is_enabled("/apifoo", "xss") is True             # default-on
        # /api alone does NOT match /api/* either (spec)
        assert ur.is_enabled("/api", "xss") is True

    # M5: catchall
    def test_m5_catchall(self, tmp_yaml):
        ur = self._build("rules:\n  - url: /*\n    detect: [SQL]\n", tmp_yaml)
        assert ur.is_enabled("/", "sql_injection") is True
        assert ur.is_enabled("/anything", "sql_injection") is True
        assert ur.is_enabled("/deeply/nested/path", "sql_injection") is True
        # All other keys narrowed away by the catchall
        assert ur.is_enabled("/", "xss") is False
        assert ur.is_enabled("/anything", "path_traversal") is False

    # M6: first-match-wins
    def test_m6_first_match_wins(self, tmp_yaml):
        ur = self._build(
            "rules:\n"
            "  - url: /api/admin/*\n    detect: [SQL]\n"
            "  - url: /api/*\n    detect: [SQL, XSS]\n",
            tmp_yaml,
        )
        # /api/admin/users hits the first rule only — XSS NOT on
        assert ur.is_enabled("/api/admin/users", "sql_injection") is True
        assert ur.is_enabled("/api/admin/users", "xss") is False
        # /api/other hits the second rule — both SQL and XSS on
        assert ur.is_enabled("/api/other", "sql_injection") is True
        assert ur.is_enabled("/api/other", "xss") is True

    # M7: matcher receives already-decoded path (input is the caller's responsibility)
    def test_m7_decoded_path_input(self, tmp_yaml):
        ur = self._build("rules:\n  - url: /api/*\n    detect: [SQL]\n", tmp_yaml)
        # Caller (proxy) passes request.path (decoded) — we just verify the match works
        # on the decoded form. The encoded form would not have been written by the user.
        assert ur.is_enabled("/api/admin", "sql_injection") is True


class TestIsRuleEnabledHelper:
    @staticmethod
    def _ur(yaml_body: str, tmp_yaml) -> UrlRules:
        return load_url_rules(tmp_yaml(yaml_body))

    # E1: url_rules=None → always True (subject to global cap)
    def test_e1_none_always_true(self):
        cfg = {"rules": {"sql_injection": True}, "url_rules": None}
        assert is_rule_enabled(cfg, "/anywhere", "sql_injection") is True
        assert is_rule_enabled(cfg, "/anywhere", "xss") is True

    # E1b: url_rules=None but global off → False (global cap still applied)
    def test_e1b_none_global_off_false(self):
        cfg = {"rules": {"xss": False}, "url_rules": None}
        assert is_rule_enabled(cfg, "/anywhere", "xss") is False

    # E2: hit-with-key
    def test_e2_hit_with_key(self, tmp_yaml):
        ur = self._ur("rules:\n  - url: /search\n    detect: [SQL]\n", tmp_yaml)
        cfg = {"rules": {"sql_injection": True}, "url_rules": ur}
        assert is_rule_enabled(cfg, "/search", "sql_injection") is True

    # E3: hit-without-key
    def test_e3_hit_without_key(self, tmp_yaml):
        ur = self._ur("rules:\n  - url: /search\n    detect: [SQL]\n", tmp_yaml)
        cfg = {"rules": {"sql_injection": True, "xss": True}, "url_rules": ur}
        assert is_rule_enabled(cfg, "/search", "xss") is False

    # E4: global cap wins over url_rules
    def test_e4_global_cap_wins(self, tmp_yaml):
        ur = self._ur("rules:\n  - url: /search\n    detect: [XSS]\n", tmp_yaml)
        cfg = {"rules": {"xss": False}, "url_rules": ur}
        # Even though url_rules lists XSS, global cap is off → False
        assert is_rule_enabled(cfg, "/search", "xss") is False
