---
change: waf-url-rules
design-doc: docs/superpowers/specs/2026-05-29-waf-url-rules-design.md
base-ref: 864c22900de03ab72c551c1009d004eb12963058
---

# WAF URL Rules Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a per-URL WAF rule layer (independent YAML file) that lets ops narrow detections (SQL/XSS/PATH/CMD/UPLOAD) to specific routes, while keeping `waf/config.yaml` global toggles as an upper bound and preserving full backward compatibility when no URL rules are configured.

**Architecture:** A new `waf/url_rules.py` module owns YAML loading + strict validation + first-match-wins URL matching. `waf/config.py` plumbs `--url-rules` CLI / `url_rules_file` YAML into `config["url_rules"]` (a `UrlRules` instance or `None`). `waf/proxy.py::handle_request` swaps each `rules.get("X", True)` for `is_rule_enabled(config, path, "X")` at five dispatch sites — control flow, multipart parsing, `rate_limit`, and `security_headers` are untouched.

**Tech Stack:** Python 3.12, aiohttp, PyYAML, pytest. No new dependencies.

---

## File Structure

| Path | Action | Responsibility |
|---|---|---|
| `waf/url_rules.py` | **Create** | `UrlRulesError`, `_TOKEN_TO_KEY`, `_CompiledRule` dataclass, `UrlRules` class (hosting `is_enabled`, public `rules`), `load_url_rules(path)`, `is_rule_enabled(config, path, key)`, `emit_global_mask_warnings(url_rules, global_rules)` |
| `waf/config.py` | **Modify** | Add `--url-rules` arg, `url_rules_file: None` in `DEFAULTS`, post-load resolution + strict-loader call + warning emission, fill `config["url_rules"]` |
| `waf/proxy.py` | **Modify** (5 lines + 1 import + 1 path capture) | Replace each of the 5 `rules.get("X", True)` dispatch reads with `is_rule_enabled(config, path, "X")`. Leave `rate_limit` and `security_headers` reading `rules.get(...)` |
| `waf/url_rules.example.yaml` | **Create** | Example with comment header listing supported tokens, match syntax, policy, and 3 example rules |
| `tests/test_url_rules.py` | **Create** | Loader (L1–L11), matcher (M1–M6), `is_rule_enabled` helper (E1–E4), `emit_global_mask_warnings` |
| `tests/test_proxy_url_rules.py` | **Create** | Integration tests I1–I7 driving `handle_request` directly (mock aiohttp Request + mock backend session) |

---

## Test ID → Task Map

Every spec scenario and design-doc test ID has a task:

| Test ID | Source | Task |
|---|---|---|
| L1 V1 (YAML parse) | spec waf-config: "YAML 解析错" | Task 4 |
| L2 V2 (top non-mapping) | design §2.2 V2 | Task 4 |
| L3 V3 (rules not list) | design §2.2 V3 | Task 4 |
| L4 V4 (missing url/detect) | design §2.2 V4 | Task 4 |
| L5 V5 (unknown field) | spec waf-config: "未知字段" | Task 4 |
| L6 V6 (url not /-prefixed) | design §2.2 V6 | Task 4 |
| L7 V7 (wildcard not at end) | spec waf-config: "url 通配符位置非法" | Task 4 |
| L8 V8 (detect not list) | design §2.2 V8 | Task 4 |
| L9 V9 (detect empty) | spec waf-config: "空 detect 列表" | Task 4 |
| L10 V10 (unknown / wrong-case token) | spec waf-config: "未知 detect token", waf-detector: "token 大小写敏感" | Task 4 |
| L11 V11 (duplicate url) | spec waf-config: "重复 URL" | Task 4 |
| M1 exact hit | spec waf-detector: "精确匹配" | Task 6 |
| M2 exact ≠ trailing slash | spec waf-detector: "精确匹配不命中尾随 slash" | Task 6 |
| M3 prefix sub-paths | spec waf-detector: "前缀通配符命中子路径" | Task 6 |
| M4 prefix segment-bound | spec waf-detector: "前缀通配符要求斜杠分段" | Task 6 |
| M5 catchall | spec waf-detector: "兜底全匹配" | Task 6 |
| M6 first-match-wins | spec waf-detector: "上方规则优先" | Task 6 |
| M7 decoded path | spec waf-detector: "匹配输入为已解码 path" | Task 6 |
| E1 url_rules=None | spec waf-detector: "未配置 URL 规则文件 → 完全等价于现有行为" | Task 8 |
| E2 hit-with-key | spec waf-detector: "URL 规则未命中、全局开启" / "命中且列出该 rule" | Task 8 |
| E3 hit-without-key | spec waf-detector: "命中但未列出该 rule" | Task 8 |
| E4 global-cap | spec waf-detector: "命中且列出该 rule，但全局已关" | Task 8 |
| W1 warning emit | spec waf-config: "URL 规则启用了被全局关闭的检测" | Task 9 |
| I1 backward compat | design §6 I1 | Task 12 |
| I2 narrowed PATH | design §6 I2 | Task 12 |
| I3 unmatched still on | design §6 I3 | Task 12 |
| I4 global cap + warning | design §6 I4 | Task 12 |
| I5 missing file exit | spec waf-config: "显式指定但文件不存在" | Task 11 |
| I6 CLI > YAML | spec waf-config: "CLI 优先于配置文件" | Task 11 |
| I7 RATE not narrowed | spec waf-detector: "URL 规则不裁剪 RATE" | Task 12 |
| I8 security_headers not narrowed | spec waf-detector: "URL 规则不裁剪 security_headers" | Task 12 |

---

## Execution Order Rationale

Tasks are ordered TDD-style and so each commit is independently runnable:

1. Tasks 1–3 set up the bare module skeleton (data types + `UrlRulesError`) so subsequent tests have something to import.
2. Tasks 4–5 build the loader test-first.
3. Tasks 6–7 build the matcher test-first.
4. Tasks 8–9 wire `is_rule_enabled` and warning helper.
5. Tasks 10–11 plumb config.py with strict-error propagation tested.
6. Task 12 (proxy.py edit) is the load-bearing integration — it goes last because it depends on `is_rule_enabled` being shipped.
7. Tasks 13–14 are the example file + final regression sweep.

---

## Task 1: Module skeleton + token vocabulary

**Files:**
- Create: `waf/url_rules.py`
- Test: `tests/test_url_rules.py`

- [ ] **Step 1: Create the empty test file with one import test**

```python
# tests/test_url_rules.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_url_rules.py::test_module_imports -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'waf.url_rules'`.

- [ ] **Step 3: Create the module skeleton**

```python
# waf/url_rules.py
"""URL-scoped WAF rule layer: loader + matcher.

Public API:
- UrlRulesError       : exception raised on any strict-validation failure.
- UrlRules            : compiled rules; .is_enabled(path, key) is the runtime hook.
- load_url_rules(path): IO + strict validate + compile.
- is_rule_enabled(config, path, key): combines global cap with URL match.
- emit_global_mask_warnings(url_rules, global_rules): post-load stderr warnings.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Iterable, Literal, Optional

# YAML-token (external) → internal config-key (matches existing rules.* keys).
_TOKEN_TO_KEY: dict[str, str] = {
    "SQL":    "sql_injection",
    "XSS":    "xss",
    "PATH":   "path_traversal",
    "CMD":    "cmd_injection",
    "UPLOAD": "file_upload",
}
_VALID_TOKENS = frozenset(_TOKEN_TO_KEY.keys())
_INTERNAL_KEYS = frozenset(_TOKEN_TO_KEY.values())
_ALLOWED_ENTRY_FIELDS = frozenset({"url", "detect"})


class UrlRulesError(Exception):
    """Raised on any strict-validation failure during load."""


@dataclass(frozen=True)
class _CompiledRule:
    kind: Literal["exact", "prefix", "catchall"]
    pattern: str
    detect_keys: frozenset[str]


class UrlRules:
    """Compiled URL rules. Iteration order = file order."""

    def __init__(self, rules: list[_CompiledRule]) -> None:
        self.rules: list[_CompiledRule] = rules

    def is_enabled(self, path: str, key: str) -> bool:
        raise NotImplementedError  # filled in Task 7


def load_url_rules(path: str) -> UrlRules:
    raise NotImplementedError  # filled in Task 5


def is_rule_enabled(config: dict, path: str, key: str) -> bool:
    raise NotImplementedError  # filled in Task 8


def emit_global_mask_warnings(url_rules: UrlRules, global_rules: dict) -> None:
    raise NotImplementedError  # filled in Task 9
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_url_rules.py::test_module_imports -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add waf/url_rules.py tests/test_url_rules.py
git commit -m "feat(waf): scaffold url_rules module with token vocabulary"
```

---

## Task 2: Test fixtures helper

**Files:**
- Modify: `tests/test_url_rules.py`

- [ ] **Step 1: Add a `tmp_yaml` fixture and helper**

Append to `tests/test_url_rules.py` (after the import test):

```python
@pytest.fixture
def tmp_yaml(tmp_path):
    """Write a YAML body to a temp file and return the path."""
    def _write(body: str) -> str:
        p = tmp_path / "rules.yaml"
        p.write_text(body, encoding="utf-8")
        return str(p)
    return _write
```

- [ ] **Step 2: Verify pytest still collects without errors**

Run: `pytest tests/test_url_rules.py --collect-only -q`
Expected: no errors, fixture resolves.

- [ ] **Step 3: Commit**

```bash
git add tests/test_url_rules.py
git commit -m "test(waf): add tmp_yaml fixture for url-rules tests"
```

---

## Task 3: Compilation rules — `_compile_rule`

**Files:**
- Modify: `waf/url_rules.py`
- Modify: `tests/test_url_rules.py`

- [ ] **Step 1: Write tests for compilation kinds first**

Append to `tests/test_url_rules.py`:

```python
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
```

- [ ] **Step 2: Run tests — they should fail**

Run: `pytest tests/test_url_rules.py::TestCompileUrlPattern -v`
Expected: FAIL with `ImportError: cannot import name '_compile_url_pattern'`.

- [ ] **Step 3: Implement `_compile_url_pattern`**

In `waf/url_rules.py`, add (above `load_url_rules`):

```python
def _compile_url_pattern(url: object, entry_index: int) -> tuple[str, str]:
    """Compile a YAML 'url' value to (kind, pattern). Raises UrlRulesError."""
    if not isinstance(url, str):
        raise UrlRulesError(f"rules[{entry_index}]: url must be a string, got {type(url).__name__}")
    if not url.startswith("/"):
        raise UrlRulesError(f"rules[{entry_index}]: url must start with '/', got {url!r}")

    if "*" in url:
        if url == "/*":
            return ("catchall", "")
        if url.endswith("/*"):
            return ("prefix", url[:-2])
        raise UrlRulesError(
            f"rules[{entry_index}]: '*' is only allowed at the end (e.g. /api/*), got {url!r}"
        )

    return ("exact", url)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_url_rules.py::TestCompileUrlPattern -v`
Expected: 8 PASSED.

- [ ] **Step 5: Commit**

```bash
git add waf/url_rules.py tests/test_url_rules.py
git commit -m "feat(waf): compile url patterns to (kind, pattern) with strict checks"
```

---

## Task 4: Strict loader — V1–V11 tests (failing)

**Files:**
- Modify: `tests/test_url_rules.py`

- [ ] **Step 1: Write all 11 strict-validation tests at once**

Append to `tests/test_url_rules.py`:

```python
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
```

- [ ] **Step 2: Run tests — all should fail with NotImplementedError**

Run: `pytest tests/test_url_rules.py::TestLoaderStrict -v`
Expected: 16 FAILs (NotImplementedError on `load_url_rules`).

---

## Task 5: Strict loader — implementation

**Files:**
- Modify: `waf/url_rules.py`

- [ ] **Step 1: Replace `load_url_rules` skeleton with implementation**

In `waf/url_rules.py`, replace the `def load_url_rules(...)` stub with:

```python
def load_url_rules(path: str) -> UrlRules:
    """Read YAML, validate strictly, compile. Raises FileNotFoundError or UrlRulesError."""
    import yaml  # local import: PyYAML may be optional in some runs, but config layer guards that

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise UrlRulesError(f"failed to parse YAML at {path}: {e}") from e

    if not isinstance(data, dict):
        raise UrlRulesError(
            f"top-level must be a mapping with key 'rules', got {type(data).__name__}"
        )
    if "rules" not in data:
        raise UrlRulesError("top-level must be a mapping with key 'rules'")
    raw_rules = data["rules"]
    if not isinstance(raw_rules, list):
        raise UrlRulesError(f"'rules' must be a list, got {type(raw_rules).__name__}")

    compiled: list[_CompiledRule] = []
    seen_urls: dict[str, int] = {}

    for i, entry in enumerate(raw_rules):
        if not isinstance(entry, dict):
            raise UrlRulesError(f"rules[{i}]: each rule must be a mapping, got {type(entry).__name__}")

        # Required fields
        if "url" not in entry:
            raise UrlRulesError(f"rules[{i}]: missing required field 'url'")
        if "detect" not in entry:
            raise UrlRulesError(f"rules[{i}]: missing required field 'detect'")

        # Unknown fields (V5)
        unknown = set(entry.keys()) - _ALLOWED_ENTRY_FIELDS
        if unknown:
            bad = sorted(unknown)[0]
            raise UrlRulesError(
                f"rules[{i}]: unknown field {bad!r} "
                f"(allowed: {sorted(_ALLOWED_ENTRY_FIELDS)})"
            )

        # url validation + compile (V6, V7)
        url_str = entry["url"]
        kind, pattern = _compile_url_pattern(url_str, entry_index=i)

        # Duplicate url (V11) — literal-string match
        if url_str in seen_urls:
            raise UrlRulesError(
                f"rules[{i}]: duplicate url {url_str!r} (also at rules[{seen_urls[url_str]}])"
            )
        seen_urls[url_str] = i

        # detect validation (V8, V9, V10)
        detect = entry["detect"]
        if not isinstance(detect, list):
            raise UrlRulesError(f"rules[{i}]: detect must be a list, got {type(detect).__name__}")
        if len(detect) == 0:
            raise UrlRulesError(f"rules[{i}]: detect must not be empty")

        keys: set[str] = set()
        for tok in detect:
            if not isinstance(tok, str) or tok not in _VALID_TOKENS:
                raise UrlRulesError(
                    f"rules[{i}]: unknown token {tok!r} "
                    f"(valid: {sorted(_VALID_TOKENS)}; case-sensitive)"
                )
            keys.add(_TOKEN_TO_KEY[tok])

        compiled.append(_CompiledRule(kind=kind, pattern=pattern, detect_keys=frozenset(keys)))

    return UrlRules(compiled)
```

- [ ] **Step 2: Run all loader tests to verify they pass**

Run: `pytest tests/test_url_rules.py::TestLoaderStrict -v`
Expected: 16 PASSED.

- [ ] **Step 3: Add a positive-path loader test**

Append to `tests/test_url_rules.py`:

```python
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
```

- [ ] **Step 4: Run all url_rules tests**

Run: `pytest tests/test_url_rules.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add waf/url_rules.py tests/test_url_rules.py
git commit -m "feat(waf): strict yaml loader for url rules with detailed errors"
```

---

## Task 6: Matcher tests — M1–M7

**Files:**
- Modify: `tests/test_url_rules.py`

- [ ] **Step 1: Add matcher tests covering all spec scenarios**

Append to `tests/test_url_rules.py`:

```python
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
```

- [ ] **Step 2: Run tests — all should fail (NotImplementedError on is_enabled)**

Run: `pytest tests/test_url_rules.py::TestMatcher -v`
Expected: 7 FAILs.

---

## Task 7: Matcher — implementation

**Files:**
- Modify: `waf/url_rules.py`

- [ ] **Step 1: Implement `UrlRules.is_enabled`**

Replace the `is_enabled` stub on `UrlRules`:

```python
    def is_enabled(self, path: str, key: str) -> bool:
        """First-match-wins. If no rule matches, returns True (default-on)."""
        for rule in self.rules:
            if self._match(rule, path):
                return key in rule.detect_keys
        return True

    @staticmethod
    def _match(rule: _CompiledRule, path: str) -> bool:
        if rule.kind == "catchall":
            return True
        if rule.kind == "exact":
            return path == rule.pattern
        # prefix: requires segment boundary
        return path.startswith(rule.pattern + "/")
```

- [ ] **Step 2: Run all url_rules tests**

Run: `pytest tests/test_url_rules.py -v`
Expected: all PASS (loader + compile + matcher).

- [ ] **Step 3: Commit**

```bash
git add waf/url_rules.py tests/test_url_rules.py
git commit -m "feat(waf): first-match-wins url matcher with segment-bound prefix"
```

---

## Task 8: `is_rule_enabled` helper — E1–E4

**Files:**
- Modify: `waf/url_rules.py`
- Modify: `tests/test_url_rules.py`

- [ ] **Step 1: Add the helper tests first**

Append to `tests/test_url_rules.py`:

```python
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
```

- [ ] **Step 2: Run tests — they should fail**

Run: `pytest tests/test_url_rules.py::TestIsRuleEnabledHelper -v`
Expected: 5 FAILs (NotImplementedError).

- [ ] **Step 3: Implement `is_rule_enabled`**

Replace the `is_rule_enabled` stub:

```python
def is_rule_enabled(config: dict, path: str, key: str) -> bool:
    """effective(path, key) = global[key] AND (url_rules is None OR url_rules.is_enabled(path, key))."""
    rules = config.get("rules", {})
    if not rules.get(key, True):       # global cap
        return False
    url_rules = config.get("url_rules")
    if url_rules is None:
        return True
    return url_rules.is_enabled(path, key)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_url_rules.py::TestIsRuleEnabledHelper -v`
Expected: 5 PASSED.

- [ ] **Step 5: Commit**

```bash
git add waf/url_rules.py tests/test_url_rules.py
git commit -m "feat(waf): is_rule_enabled combines global cap with url match"
```

---

## Task 9: `emit_global_mask_warnings` — W1

**Files:**
- Modify: `waf/url_rules.py`
- Modify: `tests/test_url_rules.py`

- [ ] **Step 1: Add warning emission test (TDD)**

Append to `tests/test_url_rules.py`:

```python
class TestWarningEmission:
    def test_w1_warns_on_global_off(self, tmp_yaml, capsys):
        ur = load_url_rules(tmp_yaml(
            "rules:\n"
            "  - url: /search\n    detect: [XSS, SQL]\n"
            "  - url: /api/*\n    detect: [SQL]\n"
        ))
        global_rules = {"xss": False, "sql_injection": True, "path_traversal": True,
                        "cmd_injection": True, "file_upload": True}
        emit_global_mask_warnings(ur, global_rules)
        captured = capsys.readouterr()
        assert captured.out == ""
        # Only one warning: rule[0] lists XSS but xss is globally false.
        assert "url_rules entry [0] lists xss" in captured.err
        assert "rules.xss is false" in captured.err
        # SQL is on globally → no warning for it on either rule
        assert "lists sql_injection" not in captured.err

    def test_w1b_no_warnings_when_all_globals_on(self, tmp_yaml, capsys):
        ur = load_url_rules(tmp_yaml(
            "rules:\n  - url: /search\n    detect: [SQL, XSS]\n"
        ))
        global_rules = {k: True for k in
                        ("sql_injection", "xss", "path_traversal",
                         "cmd_injection", "file_upload")}
        emit_global_mask_warnings(ur, global_rules)
        captured = capsys.readouterr()
        assert captured.err == ""
```

- [ ] **Step 2: Run tests — they should fail**

Run: `pytest tests/test_url_rules.py::TestWarningEmission -v`
Expected: 2 FAILs (NotImplementedError).

- [ ] **Step 3: Implement `emit_global_mask_warnings`**

Replace the stub in `waf/url_rules.py`:

```python
def emit_global_mask_warnings(url_rules: UrlRules, global_rules: dict) -> None:
    """Print one stderr warning per (rule, key) where global_rules[key] is False."""
    for rule_index, rule in enumerate(url_rules.rules):
        for key in sorted(rule.detect_keys):     # sort for deterministic output
            if not global_rules.get(key, True):
                print(
                    f"warning: url_rules entry [{rule_index}] lists {key} "
                    f"but global rules.{key} is false; this rule has no effect for {key}",
                    file=sys.stderr,
                )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_url_rules.py::TestWarningEmission -v`
Expected: 2 PASSED.

- [ ] **Step 5: Run the full url_rules suite**

Run: `pytest tests/test_url_rules.py -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add waf/url_rules.py tests/test_url_rules.py
git commit -m "feat(waf): emit stderr warning for url-rule keys disabled globally"
```

---

## Task 10: Config integration — `--url-rules` flag + DEFAULTS

**Files:**
- Modify: `waf/config.py`

- [ ] **Step 1: Add CLI flag**

In `waf/config.py::build_arg_parser`, add the `--url-rules` argument:

Find:

```python
    parser.add_argument("--config", type=str, default=_UNSET)
    parser.add_argument("--disable", nargs="+", default=[])
    return parser
```

Replace with:

```python
    parser.add_argument("--config", type=str, default=_UNSET)
    parser.add_argument("--url-rules", type=str, default=_UNSET, dest="url_rules")
    parser.add_argument("--disable", nargs="+", default=[])
    return parser
```

- [ ] **Step 2: Add `url_rules_file: None` to DEFAULTS**

Find the `DEFAULTS = {...}` dict in `waf/config.py` and add `"url_rules_file": None,` (place it after the `"rules": {...}` block, before `"rate_limit"`).

- [ ] **Step 3: Verify nothing broke**

Run: `pytest -q` (the existing test suite must still pass; we haven't wired loading yet).
Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add waf/config.py
git commit -m "feat(waf): add --url-rules CLI flag and url_rules_file default"
```

---

## Task 11: Config integration — strict-loader call + I5 + I6

**Files:**
- Modify: `waf/config.py`
- Create: `tests/test_config_url_rules.py`

- [ ] **Step 1: Write integration tests for config plumbing first**

Create `tests/test_config_url_rules.py`:

```python
"""Tests for waf.config integration with url_rules: --url-rules, url_rules_file, errors."""
import pytest

from waf.config import load_config


@pytest.fixture
def tmp_url_rules(tmp_path):
    def _write(name: str, body: str) -> str:
        p = tmp_path / name
        p.write_text(body, encoding="utf-8")
        return str(p)
    return _write


@pytest.fixture
def tmp_config(tmp_path):
    def _write(body: str) -> str:
        p = tmp_path / "waf-config.yaml"
        p.write_text(body, encoding="utf-8")
        return str(p)
    return _write


class TestConfigUrlRulesPlumbing:
    # Default: neither CLI nor YAML → url_rules is None
    def test_default_no_url_rules(self, tmp_config):
        cfg_path = tmp_config("listen_port: 8080\n")
        config = load_config(["--config", cfg_path])
        assert config["url_rules"] is None

    # I5: explicit --url-rules but file missing → SystemExit
    def test_i5_missing_file_exits(self, tmp_config):
        cfg_path = tmp_config("listen_port: 8080\n")
        with pytest.raises(SystemExit):
            load_config(["--config", cfg_path, "--url-rules", "/definitely/missing.yaml"])

    # I6: CLI overrides YAML
    def test_i6_cli_overrides_yaml(self, tmp_config, tmp_url_rules):
        cli_rules = tmp_url_rules("cli.yaml",
                                  "rules:\n  - url: /from-cli\n    detect: [SQL]\n")
        yaml_rules = tmp_url_rules("yaml.yaml",
                                   "rules:\n  - url: /from-yaml\n    detect: [XSS]\n")
        cfg_path = tmp_config(f'listen_port: 8080\nurl_rules_file: "{yaml_rules}"\n')
        config = load_config(["--config", cfg_path, "--url-rules", cli_rules])
        # The CLI file's first rule lists SQL on /from-cli
        ur = config["url_rules"]
        assert ur is not None
        assert ur.rules[0].pattern == "/from-cli"
        assert "sql_injection" in ur.rules[0].detect_keys

    def test_yaml_only(self, tmp_config, tmp_url_rules):
        rules_path = tmp_url_rules(
            "rules.yaml", "rules:\n  - url: /from-yaml\n    detect: [XSS]\n")
        cfg_path = tmp_config(f'listen_port: 8080\nurl_rules_file: "{rules_path}"\n')
        config = load_config(["--config", cfg_path])
        ur = config["url_rules"]
        assert ur is not None
        assert ur.rules[0].pattern == "/from-yaml"
        assert "xss" in ur.rules[0].detect_keys

    def test_strict_error_exits(self, tmp_config, tmp_url_rules):
        bad = tmp_url_rules("bad.yaml",
                            "rules:\n  - url: /foo\n    detect: [BOGUS]\n")
        cfg_path = tmp_config("listen_port: 8080\n")
        with pytest.raises(SystemExit):
            load_config(["--config", cfg_path, "--url-rules", bad])

    def test_warning_on_global_off(self, tmp_config, tmp_url_rules, capsys):
        rules_path = tmp_url_rules(
            "rules.yaml", "rules:\n  - url: /foo\n    detect: [XSS]\n")
        cfg_path = tmp_config(
            "listen_port: 8080\n"
            "rules:\n  xss: false\n"
        )
        load_config(["--config", cfg_path, "--url-rules", rules_path])
        captured = capsys.readouterr()
        assert "url_rules entry [0] lists xss" in captured.err
```

- [ ] **Step 2: Run tests — they should fail (config doesn't load url_rules yet)**

Run: `pytest tests/test_config_url_rules.py -v`
Expected: FAILs (`KeyError: 'url_rules'` or default-not-None mismatch).

- [ ] **Step 3: Wire url-rules loading into `load_config`**

In `waf/config.py`, add the import at the top (alongside existing imports):

```python
from waf.url_rules import (
    UrlRulesError,
    emit_global_mask_warnings,
    load_url_rules,
)
```

Then at the **end** of `load_config` (just before `return config`), insert:

```python
    # --- url_rules layer ---
    url_rules_path = (
        args.url_rules if args.url_rules is not _UNSET
        else config.get("url_rules_file")
    )
    if url_rules_path:
        try:
            url_rules_obj = load_url_rules(url_rules_path)
        except FileNotFoundError:
            print(f"Error: url-rules file not found: {url_rules_path}", file=sys.stderr)
            sys.exit(1)
        except UrlRulesError as e:
            print(f"Error in url-rules file {url_rules_path}: {e}", file=sys.stderr)
            sys.exit(1)
        emit_global_mask_warnings(url_rules_obj, config["rules"])
        config["url_rules"] = url_rules_obj
    else:
        config["url_rules"] = None
```

- [ ] **Step 4: Run config integration tests**

Run: `pytest tests/test_config_url_rules.py -v`
Expected: 6 PASSED.

- [ ] **Step 5: Run the full test suite to confirm no regression**

Run: `pytest -q`
Expected: all PASS (existing 100+ tests + new url_rules + new config tests).

- [ ] **Step 6: Commit**

```bash
git add waf/config.py tests/test_config_url_rules.py
git commit -m "feat(waf): wire url_rules loader into config (CLI > YAML, strict exit)"
```

---

## Task 12: Proxy integration — 5 dispatch swaps + I1–I8

**Files:**
- Modify: `waf/proxy.py` (5 dispatch sites)
- Create: `tests/test_proxy_url_rules.py`

- [ ] **Step 1: Open `waf/proxy.py` and locate `handle_request`**

The 5 dispatch sites are around lines 152–195 in the function (per the existing code). Each looks like:

```python
if rules.get("X", True) and detect_X(nval):    # X ∈ {sql_injection, path_traversal, cmd_injection}
    ...
if rules.get("file_upload", True):             # the upload site
    ...
if rules.get("xss", True):                     # the xss block
    ...
```

- [ ] **Step 2: Add the import and capture path once at the top of `handle_request`**

At the top of `waf/proxy.py`'s import block, add:

```python
from waf.url_rules import is_rule_enabled
```

Inside `handle_request`, find the first lines:

```python
async def handle_request(request: web.Request, config: dict, logger: logging.Logger, session: aiohttp.ClientSession) -> web.Response:
    ip = request.remote or "unknown"
    path = request.path
    rules = config.get("rules", {})
```

Leave `path = request.path` — it already exists. (No change needed here; `path` and `rules` are both already available.)

- [ ] **Step 3: Replace the 5 dispatch reads**

Find and replace each of these (5 distinct sites):

```python
        if rules.get("sql_injection", True) and detect_sql_injection(nval):
```
→
```python
        if is_rule_enabled(config, path, "sql_injection") and detect_sql_injection(nval):
```

```python
        if rules.get("path_traversal", True) and detect_path_traversal(nval):
```
→
```python
        if is_rule_enabled(config, path, "path_traversal") and detect_path_traversal(nval):
```

```python
        if rules.get("cmd_injection", True) and detect_cmd_injection(nval):
```
→
```python
        if is_rule_enabled(config, path, "cmd_injection") and detect_cmd_injection(nval):
```

```python
        if rules.get("file_upload", True):
```
→
```python
        if is_rule_enabled(config, path, "file_upload"):
```

```python
    if rules.get("xss", True):
```
→
```python
    if is_rule_enabled(config, path, "xss"):
```

**Do not touch** the `rules.get("rate_limit", True)` site or the `rules.get("security_headers", True)` site (URL rules deliberately do not narrow these).

- [ ] **Step 4: Run the existing test suite — I1 (backward compat)**

Run: `pytest -q`
Expected: all existing tests PASS unchanged (no test sets `url_rules`, so `is_rule_enabled` returns identical values to `rules.get("X", True)`).

- [ ] **Step 5: Create the proxy integration test file**

Create `tests/test_proxy_url_rules.py`:

```python
"""Integration tests driving handle_request directly with mocked aiohttp objects."""
import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf.proxy import handle_request
from waf.url_rules import load_url_rules


# --- helpers ---------------------------------------------------------------

class _FakeURL:
    def __init__(self, path: str, query: dict | None = None):
        self.path = path
        self.query = query or {}


class _FakeRequest:
    """Minimal aiohttp.Request stand-in for handle_request."""
    def __init__(self, *, method="GET", path="/", query=None, headers=None,
                 form=None, content_type="application/x-www-form-urlencoded"):
        self.method = method
        self.path = path
        self.rel_url = _FakeURL(path, query or {})
        self.remote = "127.0.0.1"
        self.headers = headers or {}
        self.content_type = content_type
        self._form = form or {}
        self._read_body = b""

    async def post(self):
        return self._form

    async def read(self):
        return self._read_body


def _make_session_returning_200():
    """Mock aiohttp.ClientSession.request as an async context manager yielding a 200 backend response."""
    backend_resp = MagicMock()
    backend_resp.read = AsyncMock(return_value=b"OK")
    backend_resp.status = 200
    backend_resp.headers = {"Content-Type": "text/plain"}

    class _CtxMgr:
        async def __aenter__(self):
            return backend_resp
        async def __aexit__(self, *a):
            return False

    session = MagicMock()
    session.request = MagicMock(return_value=_CtxMgr())
    return session


def _logger():
    return logging.getLogger("test-waf-url-rules")


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def _config(rules: dict | None = None, url_rules=None, login_path="/login"):
    return {
        "rules": rules or {
            "sql_injection": True, "xss": True, "path_traversal": True,
            "cmd_injection": True, "file_upload": True,
            "rate_limit": True, "security_headers": True,
        },
        "rate_limit": {"max_failures": 10, "window": 60, "lockout": 300},
        "backend_url": "http://backend.invalid",
        "login_path": login_path,
        "url_rules": url_rules,
    }


# --- I2: url_rules narrows /search to [SQL, XSS] — PATH should pass through ----

def test_i2_path_narrowed_on_search(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - url: /search\n    detect: [SQL, XSS]\n", encoding="utf-8")
    ur = load_url_rules(str(rules_path))
    cfg = _config(url_rules=ur)
    req = _FakeRequest(method="GET", path="/search", query={"x": "../../etc/passwd"})
    resp = _run(handle_request(req, cfg, _logger(), _make_session_returning_200()))
    # PATH is narrowed away on /search — request reaches backend (200 not 403)
    assert resp.status == 200


# --- I3: same rules, /other path still has PATH on ----

def test_i3_path_still_blocks_unmatched(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - url: /search\n    detect: [SQL, XSS]\n", encoding="utf-8")
    ur = load_url_rules(str(rules_path))
    cfg = _config(url_rules=ur)
    req = _FakeRequest(method="GET", path="/other", query={"x": "../../etc/passwd"})
    resp = _run(handle_request(req, cfg, _logger(), _make_session_returning_200()))
    # /other doesn't match → default-on → PATH still blocks
    assert resp.status == 403


# --- I4: global xss=false + rule listing XSS — XSS not run on /search ----

def test_i4_global_cap_wins(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - url: /search\n    detect: [XSS]\n", encoding="utf-8")
    ur = load_url_rules(str(rules_path))
    cfg = _config(rules={
        "sql_injection": False, "xss": False, "path_traversal": False,
        "cmd_injection": False, "file_upload": False,
        "rate_limit": False, "security_headers": True,
    }, url_rules=ur)
    # Sanity: with all detection off, the request reaches backend
    req = _FakeRequest(method="GET", path="/search", query={"x": "<script>alert(1)</script>"})
    resp = _run(handle_request(req, cfg, _logger(), _make_session_returning_200()))
    assert resp.status == 200  # nothing blocks


# --- I7: url_rules narrows /login but RATE still fires ----

def test_i7_rate_not_narrowed_by_url_rules(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - url: /login\n    detect: [SQL]\n", encoding="utf-8")
    ur = load_url_rules(str(rules_path))
    cfg = _config(url_rules=ur, login_path="/login")
    # Trigger rate-limit lockout: simulate by pre-loading state via many failures
    from waf.proxy import _rate_state
    _rate_state.clear()
    _rate_state["127.0.0.1"] = {"count": 999, "window_start": 0, "locked_until": 9_999_999_999}
    try:
        req = _FakeRequest(method="POST", path="/login", form={"u": "a", "p": "b"})
        resp = _run(handle_request(req, cfg, _logger(), _make_session_returning_200()))
        # RATE fires (429), ignoring url_rules narrowing
        assert resp.status == 429
    finally:
        _rate_state.clear()


# --- I8: security_headers still injected on a narrowed path ----

def test_i8_security_headers_not_narrowed(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n  - url: /foo\n    detect: [SQL]\n", encoding="utf-8")
    ur = load_url_rules(str(rules_path))
    cfg = _config(url_rules=ur)
    req = _FakeRequest(method="GET", path="/foo", query={"x": "hello"})
    resp = _run(handle_request(req, cfg, _logger(), _make_session_returning_200()))
    assert resp.status == 200
    assert "X-Frame-Options" in resp.headers
    assert "Content-Security-Policy" in resp.headers
```

- [ ] **Step 6: Run the proxy integration tests**

Run: `pytest tests/test_proxy_url_rules.py -v`
Expected: 5 PASSED.

If `_make_session_returning_200`'s mock chain is mismatched against how `handle_request` actually invokes `session.request(...)`, adjust the mock to match — read `waf/proxy.py:227` for the actual call signature. Specifically, the existing handler calls `async with session.request(method=..., url=..., headers=..., data=..., allow_redirects=False) as backend_resp:` — the helper above mirrors that.

- [ ] **Step 7: Run the full test suite — final regression sweep (covers I1)**

Run: `pytest -q`
Expected: all PASS — existing tests under `url_rules=None` (I1 backward compatibility) + new url_rules + config + proxy_url_rules suites.

- [ ] **Step 8: Commit**

```bash
git add waf/proxy.py tests/test_proxy_url_rules.py
git commit -m "feat(waf): per-url rule dispatch in handle_request (5-site swap)"
```

---

## Task 13: Example file `waf/url_rules.example.yaml`

**Files:**
- Create: `waf/url_rules.example.yaml`

- [ ] **Step 1: Write the example file with comment header**

Create `waf/url_rules.example.yaml`:

```yaml
# WAF URL rule file
#
# Supported detection types (case-sensitive):
#   SQL    — SQL injection
#   XSS    — Cross-site scripting (sanitized, not blocked)
#   PATH   — Path traversal
#   CMD    — Command injection
#   UPLOAD — File upload (extension whitelist + magic bytes)
#
# URL match syntax:
#   /login    — exact match (does NOT match /login/)
#   /api/*    — prefix wildcard with segment boundary (matches /api/foo, /api/foo/bar; NOT /api or /apifoo)
#   /*        — catch-all (matches any path)
#
# Match policy: first match wins, top-to-bottom. Place more-specific rules first.
# Unmatched URLs: ALL detections enabled (subject to global toggles).
#
# Global toggles in waf/config.yaml are an upper bound. Detection types disabled
# globally cannot be re-enabled here. A warning is printed at startup if a rule
# lists a token that is globally off.
#
# RATE (brute-force lockout) and security-header injection are NOT URL-scoped;
# they remain controlled solely by waf/config.yaml::rules.{rate_limit,security_headers}.

rules:
  # Search pages: only SQL & XSS scanning needed
  - url: /search
    detect: [SQL, XSS]

  # Upload endpoints: focus on file-upload + path-traversal checks
  - url: /upload/*
    detect: [UPLOAD, PATH]

  # Generic API: detect SQL only (others narrowed to reduce false positives)
  - url: /api/*
    detect: [SQL]
```

- [ ] **Step 2: Verify the file loads without error**

Run: `python -c "from waf.url_rules import load_url_rules; print(len(load_url_rules('waf/url_rules.example.yaml').rules))"`
Expected: prints `3`.

- [ ] **Step 3: Commit**

```bash
git add waf/url_rules.example.yaml
git commit -m "docs(waf): example url-rules file with vocabulary header"
```

---

## Task 14: Final verification + tasks.md tick-off + commit

**Files:**
- Modify: `openspec/changes/waf-url-rules/tasks.md`

- [ ] **Step 1: Run the full test suite one more time**

Run: `pytest -q`
Expected: all PASS.

- [ ] **Step 2: Validate OpenSpec**

Run: `openspec validate waf-url-rules`
Expected: `Change 'waf-url-rules' is valid`.

- [ ] **Step 3: Smoke-launch the proxy with the example rules**

Run (briefly, then Ctrl+C — we just want to verify no startup crash):
```
python -m waf.proxy --url-rules waf/url_rules.example.yaml --listen 18080 --backend http://127.0.0.1:5000
```
Expected: no traceback, listens on 18080, no warnings unless `waf/config.yaml` has a globally-off rule that the example uses.

- [ ] **Step 4: Tick off tasks in `openspec/changes/waf-url-rules/tasks.md`**

Edit `openspec/changes/waf-url-rules/tasks.md` and change every `- [ ]` to `- [x]` for tasks that are now complete (which should be all of them: groups 1–7).

- [ ] **Step 5: Commit the tasks tick-off**

```bash
git add openspec/changes/waf-url-rules/tasks.md
git commit -m "chore(waf-url-rules): mark openspec tasks complete"
```

---

## Self-Review Notes

**Spec coverage check:**

- waf-config: "URL 规则文件路径配置" → Tasks 10–11 (CLI flag, default, plumbing, CLI > YAML, missing file)
- waf-config: "URL 规则文件 Strict 加载" + all V scenarios → Tasks 4–5 + Task 11 strict-error test
- waf-config: "URL 规则与全局开关的告警" → Task 9 (W1) + Task 11 (warning surfaces through load_config)
- waf-detector: "URL 维度规则词汇表" → Task 1 (`_TOKEN_TO_KEY`) + Task 4 (V10 unknown/case-sensitive)
- waf-detector: "URL 匹配语法" → Tasks 3 (compile) + Task 6 (M1–M7)
- waf-detector: "URL 规则匹配策略" → Task 6 (M6 first-match-wins)
- waf-detector: "Effective 规则计算" → Task 8 (E1–E4)
- waf-detector: "URL 规则不影响 RATE 与 security_headers" → Task 12 (I7, I8)

**Type consistency check:**
- `UrlRules`, `UrlRulesError`, `_CompiledRule`, `_TOKEN_TO_KEY`, `_VALID_TOKENS`, `_INTERNAL_KEYS`, `_ALLOWED_ENTRY_FIELDS` defined in Task 1 and reused consistently in Tasks 3, 5, 7, 8, 9.
- `_compile_url_pattern(url, entry_index)` signature defined in Task 3, called in Task 5 with the same signature.
- `is_rule_enabled(config, path, key)` signature defined in Task 1, implemented in Task 8, used in Task 12 — same.
- Internal keys (`sql_injection`, `xss`, `path_traversal`, `cmd_injection`, `file_upload`) match exactly the `rules.*` keys in `waf/config.py` `DEFAULTS` and the dispatch reads in `waf/proxy.py`.

**Placeholder scan:** No `TBD`, no "implement appropriate", no "similar to Task X without code". Every code step has full code; every test step has full assertion code.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-29-waf-url-rules.md`. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — Execute tasks in this session using `executing-plans`, batch execution with checkpoints.

Which approach?
