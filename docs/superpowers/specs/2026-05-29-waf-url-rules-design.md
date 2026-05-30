---
comet_change: waf-url-rules
role: technical-design
canonical_spec: openspec
---

# WAF URL Rules — Technical Design

> Canonical capability spec lives in OpenSpec (`openspec/changes/waf-url-rules/`). This document covers the **how**: implementation approach, internal contracts, boundary handling, testing strategy. Requirements are spec-side; this is engineering-side.

## 1. Architecture Overview

```
                   load_config(argv)
                         │
       parse CLI ──┐     │     ┌── read waf/config.yaml (global)
                   ▼     ▼     ▼
                 ┌─────────────────┐
                 │   waf/config.py │  resolves url-rules-file path
                 └────────┬────────┘  (CLI > YAML > none)
                          │ explicit path?
                          ▼
                 ┌─────────────────┐
                 │ waf/url_rules.py│  IO + Strict validate + compile
                 │  load_url_rules │
                 └────────┬────────┘
                          │ raise on any failure
                          ▼
              config["url_rules"] = UrlRules | None

                              │
                              ▼
                  ┌──────────────────────┐
                  │ waf/proxy.py         │  per request:
                  │  handle_request      │   path = request.path
                  │                      │   for rule in (sql,xss,...):
                  │                      │     if is_rule_enabled(
                  │                      │         config, path, rule):
                  │                      │       run detector
                  └──────────────────────┘
```

Three modules touch the change:

| Module | Role | Change scope |
|---|---|---|
| `waf/url_rules.py` (new) | Loader + matcher | Owns: file IO, strict validation, pattern compilation, runtime matching. Stateless after load. |
| `waf/config.py` (edit) | Config plumbing | Adds `--url-rules` flag, `url_rules_file` YAML key, calls loader, exits on error, fills `config["url_rules"]`. |
| `waf/proxy.py` (edit) | Per-request dispatch | 5-line surgical change: each `rules.get("X", True)` becomes `is_rule_enabled(config, path, "X")`. Control flow unchanged. |

## 2. Internal Contracts

### 2.1 `waf/url_rules.py` API

```python
from dataclasses import dataclass
from typing import Literal, Optional

# Public token vocabulary (case-sensitive).
_TOKEN_TO_KEY: dict[str, str] = {
    "SQL":    "sql_injection",
    "XSS":    "xss",
    "PATH":   "path_traversal",
    "CMD":    "cmd_injection",
    "UPLOAD": "file_upload",
}
_VALID_TOKENS = frozenset(_TOKEN_TO_KEY.keys())
_INTERNAL_KEYS = frozenset(_TOKEN_TO_KEY.values())


class UrlRulesError(Exception):
    """Raised on any strict-validation failure during load."""


@dataclass(frozen=True)
class _CompiledRule:
    kind: Literal["exact", "prefix", "catchall"]
    pattern: str                        # "" for catchall; bare prefix (no trailing /, no *) for prefix
    detect_keys: frozenset[str]         # internal keys (after token translation)


class UrlRules:
    def __init__(self, rules: list[_CompiledRule]) -> None: ...

    rules: list[_CompiledRule]              # public, read-only iteration order = file order

    def is_enabled(self, path: str, key: str) -> bool:
        """First-match-wins. If no rule matches, returns True (default-on)."""

    def detect_keys_for(self, path: str) -> Optional[frozenset[str]]:
        """For warning emission. Returns the matching rule's detect_keys, or None on no match."""


def load_url_rules(path: str) -> UrlRules:
    """Read YAML, validate strictly, compile. Raises FileNotFoundError or UrlRulesError."""


def emit_global_mask_warnings(url_rules: UrlRules, global_rules: dict) -> None:
    """Print one stderr warning per (rule, key) where global_rules[key] is False."""


def is_rule_enabled(config: dict, path: str, key: str) -> bool:
    """Module-level helper called by proxy.py. Combines global cap with URL match.

       effective = global[key] AND (url_rules is None OR url_rules.is_enabled(path, key))
    """
    rules = config.get("rules", {})
    if not rules.get(key, True):          # global mask
        return False
    url_rules = config.get("url_rules")
    if url_rules is None:                 # no url-rules layer → default-on
        return True
    return url_rules.is_enabled(path, key)
```

**Why a class plus a module-level helper.** `UrlRules` is a pure data structure tested in isolation (white-box); `is_rule_enabled` is the only function `proxy.py` calls and folds in the `None` case + the global cap, so the proxy doesn't have to remember the formula.

### 2.2 Strict-validation rule set (loader)

The loader raises `UrlRulesError(detail)` on any of these. Detail string carries entry index (or field name) plus offending value.

| # | Failure | Example error message |
|---|---|---|
| V1 | `yaml.safe_load` raises `YAMLError` | `failed to parse YAML at <path>: <line/col>` |
| V2 | top-level not a mapping | `top-level must be a mapping with key 'rules'` |
| V3 | missing/non-list `rules` | `top-level 'rules' must be a list, got <type>` |
| V4 | entry missing `url` or `detect` | `rules[<i>]: missing required field 'url'` |
| V5 | unknown entry field | `rules[<i>]: unknown field '<name>' (allowed: url, detect)` |
| V6 | `url` not str / not starts with `/` | `rules[<i>]: url must start with '/'` |
| V7 | `*` not at end | `rules[<i>]: '*' is only allowed at the end (e.g. /api/*)` |
| V8 | `detect` not a list | `rules[<i>]: detect must be a list` |
| V9 | `detect: []` | `rules[<i>]: detect must not be empty` |
| V10 | `detect` element not str / unknown / wrong case | `rules[<i>]: unknown token '<x>' (valid: SQL, XSS, PATH, CMD, UPLOAD; case-sensitive)` |
| V11 | duplicate `url` literal | `rules[<i>]: duplicate url '<x>' (also at rules[<j>])` |

**Implementation note.** The loader builds a `seen_urls: set[str]` to detect V11. It does NOT semantically dedupe (e.g. `/api/*` and `/api/*` matched by trailing-slash variants) — only literal string equality. This keeps "duplicate" deterministic and easy to explain.

### 2.3 Compilation: YAML rule → `_CompiledRule`

```
url string                    → kind         pattern          notes
─────────────────────────────────────────────────────────────────────
"/login"                     → exact        "/login"         strict equality
"/api/foo"                   → exact        "/api/foo"       no wildcards
"/api/*"                     → prefix       "/api"           strip trailing "/*"
"/foo/bar/*"                 → prefix       "/foo/bar"
"/*"                         → catchall     ""               special-case
```

Detection of kind:
- ends with `"/*"` and is exactly `"/*"` → `catchall`
- ends with `"/*"` and length > 2 → `prefix`, pattern = `url[:-2]`
- contains no `*` → `exact`, pattern = url
- contains `*` anywhere else → V7 violation

### 2.4 Match algorithm

```python
def is_enabled(self, path: str, key: str) -> bool:
    for rule in self._rules:                # file order
        if self._match(rule, path):
            return key in rule.detect_keys
    return True                             # no rule matched

def _match(rule, path: str) -> bool:
    if rule.kind == "catchall":
        return True
    if rule.kind == "exact":
        return path == rule.pattern
    # prefix
    return path.startswith(rule.pattern + "/")
```

**Edge cases the algorithm covers:**
- `/api/*` vs `/api` → `path.startswith("/api/")` → False, no match (per spec)
- `/api/*` vs `/apifoo` → False, no match (segment boundary preserved)
- `/api/*` vs `/api/` → True (one-char-after-slash counts)
- `/login` vs `/login/` → False, no match (Q2 decision: no normalization)
- `/*` vs `/` → True (catchall has empty pattern, always matches)

### 2.5 Mismatch-warning scan (post-load)

After successful load, `config.py` calls a helper exposed by `url_rules.py`:

```python
# in waf/url_rules.py
def emit_global_mask_warnings(url_rules: UrlRules, global_rules: dict) -> None:
    """Print one warning to stderr per (rule, key) where global_rules[key] is False."""
    for rule_index, rule in enumerate(url_rules.rules):    # rules is a public read-only sequence
        for key in rule.detect_keys:
            if not global_rules.get(key, True):
                print(f"warning: url_rules entry [{rule_index}] lists {key} "
                      f"but global rules.{key} is false; this rule has no effect for {key}",
                      file=sys.stderr)
```

`config.py` calls `emit_global_mask_warnings(url_rules, config["rules"])` immediately after a successful load. Informational only; never `sys.exit(1)`.

## 3. `waf/config.py` Integration

Three edits, all localized:

```python
# 1. parser
parser.add_argument("--url-rules", type=str, default=_UNSET)

# 2. DEFAULTS
DEFAULTS = {
    ...
    "url_rules_file": None,    # None means "no url-rules layer"
    ...
}

# 3. after deep-merge & --disable handling, before return:
url_rules_path = (
    args.url_rules if args.url_rules is not _UNSET
    else config.get("url_rules_file")
)

if url_rules_path:
    try:
        url_rules = load_url_rules(url_rules_path)
    except FileNotFoundError:
        print(f"Error: url-rules file not found: {url_rules_path}", file=sys.stderr)
        sys.exit(1)
    except UrlRulesError as e:
        print(f"Error in url-rules file {url_rules_path}: {e}", file=sys.stderr)
        sys.exit(1)
    emit_global_mask_warnings(url_rules, config["rules"])
    config["url_rules"] = url_rules
else:
    config["url_rules"] = None
```

**Why CLI > YAML works for free.** `_UNSET` sentinel means "user didn't pass `--url-rules`". When `--url-rules b.yaml` is passed and YAML has `url_rules_file: a.yaml`, we read `args.url_rules` first → `b.yaml`. When neither is set, we get `None` → no loading.

## 4. `waf/proxy.py` Integration

Five sites in `handle_request`. The diff is mechanical:

```diff
-    rules = config.get("rules", {})
+    # rules is still read for rate_limit/security_headers (URL rules don't affect them)
+    rules = config.get("rules", {})
+    path = request.path

     # 1. Rate limit (unchanged — URL rules do not narrow RATE)
     if rules.get("rate_limit", True) and request.method == "POST" and path == login_path:
         ...

     # 3. Detection
     for key, val in all_string_params.items():
         nval = normalize(val)
-        if rules.get("sql_injection", True) and detect_sql_injection(nval):
+        if is_rule_enabled(config, path, "sql_injection") and detect_sql_injection(nval):
             ...
-        if rules.get("path_traversal", True) and detect_path_traversal(nval):
+        if is_rule_enabled(config, path, "path_traversal") and detect_path_traversal(nval):
             ...
-        if rules.get("cmd_injection", True) and detect_cmd_injection(nval):
+        if is_rule_enabled(config, path, "cmd_injection") and detect_cmd_injection(nval):
             ...

     for field_name, filename in filenames:
-        if rules.get("file_upload", True):
+        if is_rule_enabled(config, path, "file_upload"):
             ...

-    if rules.get("xss", True):
+    if is_rule_enabled(config, path, "xss"):
         ...
```

`rate_limit` and `security_headers` keep `rules.get(...)`. URL-rule vocabulary only covers the five.

`path` is captured from `request.path` once at the top of the handler and reused — that's the input to the matcher per Q5. aiohttp's `request.path` already URL-decodes, so `/api%2Fadmin` arrives here as `/api/admin`.

## 5. Trade-offs & Boundary Conditions

| Concern | Decision | Why |
|---|---|---|
| Multiple matching rules | First match wins (file order) | nginx-style; zero implicit precedence to teach |
| `detect: []` | Strict error | URL rules are for narrowing, not for "skip WAF entirely" — that's what global toggles are for. Empty list is almost certainly a typo. |
| Trailing slash on URL | No normalization (`/login` ≠ `/login/`) | Preserves predictability; users wanting both forms write `/login/*` or two rules |
| Token case | Case-sensitive (`sql` invalid) | Avoids ambiguity; matches typed-config-key flavor |
| Rule on `/foo` lists `XSS`, global `xss=false` | Warning to stderr, do not exit | User intent is preserved (rule says "narrow"); global cap silently wins; warning surfaces the dead branch |
| `/*` catchall | Allowed but discouraged | Documented at top of example file; can accidentally narrow ALL paths |
| Unknown YAML field | Strict error | Forward-compat-shut-by-design; future spec change can open it |
| Config hot-reload | Out of scope | Spec non-goal; would require file watcher and atomic swap |
| Path source | `request.path` (already decoded) | aiohttp normalizes encoded `/`; rules apply to decoded form. Documented so users aren't surprised. |
| `rate_limit` / `security_headers` | Unaffected by URL rules | Spec'd explicitly. URL vocabulary deliberately excludes RATE/CSRF tokens. |

### Risks

1. **Rule ordering footgun.** `/api/* → [SQL]` placed above `/api/admin/* → [SQL,XSS]` makes the admin rule unreachable. → Mitigation: README warning + an example file that puts more-specific rules first.
2. **Silent narrowing via `/*`.** A `/* → [SQL]` at the bottom of the rules file silently disables XSS/PATH/CMD/UPLOAD on every path that doesn't match an earlier rule. → Mitigation: example file omits `/*`; README explicitly warns.
3. **Decoded-path surprise.** `/api%2Fadmin` matches `/api/*` rather than being treated as a separate path. → Mitigation: spec scenario + design-doc note explicitly call this out.
4. **Drift between vocabulary and implementation.** If a future change adds a sixth detection type to the proxy, `_TOKEN_TO_KEY` must be extended in lockstep. → Mitigation: integration test asserts every internal key in `_INTERNAL_KEYS` is referenced by `proxy.py`'s dispatch (a tiny grep-style assertion in test_proxy_url_rules.py).

## 6. Testing Strategy

Three files; total ~25 tests.

### `tests/test_url_rules.py` — loader + matcher (white-box)

| Group | IDs | Coverage |
|---|---|---|
| Loader-positive | L0 | minimal valid file → `UrlRules` with N rules |
| Loader-negative | L1–L11 | one test per V1–V11 (parse error, missing field, unknown field, bad url, bad wildcard, bad token incl. case, empty detect, duplicate url) |
| Matcher | M1–M6 | exact hit, exact miss-on-trailing-slash, prefix hit (sub + sub-of-sub), prefix miss (no slash, identical-no-slash), catchall hit, first-match-wins ordering |
| `is_rule_enabled` | E1–E4 | None config, hit-with-key, hit-without-key, no-match |

Each loader-negative test asserts the error message contains the entry index/field name (regex assert), so we catch silent-detail-drop regressions.

### `tests/test_proxy_url_rules.py` — handle_request (Q3 decision)

Use the same minimal `make_request(...)` / mock backend session pattern already used in existing proxy tests. No real aiohttp app.

| ID | Setup | Action | Assert |
|---|---|---|---|
| I1 | `url_rules=None` | run all existing proxy tests | unchanged behavior (re-uses regression suite via parametrize or import) |
| I2 | rule `/search → [XSS,SQL]` | GET `/search?x=../../etc/passwd` | 200 (PATH narrowed away), backend hit |
| I3 | same rule | GET `/other?x=../../etc/passwd` | 403 (PATH still on for unmatched paths) |
| I4 | global `xss=false` + rule `/search → [XSS]` | GET `/search?x=<script>` + capture stderr at startup | XSS not run (no sanitize log); startup stderr shows warning |
| I5 | `--url-rules /missing.yaml` | call `load_config([...])` | `SystemExit` with non-zero code |
| I6 | YAML `url_rules_file: a.yaml` + CLI `--url-rules b.yaml` | call `load_config` | `b.yaml` is the one loaded |
| I7 | rule `/login → [SQL]`, global `rate_limit=true` | flood POST `/login` past threshold | 429 fires (URL rules do NOT cancel RATE) |

### Coverage gates

- All loader scenarios in delta spec are 1:1 with a test ID.
- `pytest -q` from repo root must pass (existing 100+ tests + new ~25).

## 7. Open Questions

None — Q1–Q5 closed in brainstorming, captured as decisions above. Anything that emerges during implementation will be raised before coding around it.

## 8. Migration / Rollback

- Roll-out: deploy without setting `--url-rules` or `url_rules_file` → behavior identical to today. Then per-environment, ops copies `waf/url_rules.example.yaml` → `waf/url_rules.yaml` (or any path), tweaks, and adds the flag.
- Roll-back: drop the CLI flag / unset the YAML key. No data, no state, no migration.
- The change is additive and gated; risk is bounded to "did we silently break the dispatch when url_rules=None". Test I1 (regression-suite under `url_rules=None`) is the load-bearing test for that promise.

## 9. Implementation Divergence

Recorded post-build during the Comet verify phase. Items the as-built code drifts from §2 above, with rationale.

### 9.1 `UrlRules.detect_keys_for(path)` not implemented

§2.1 listed `detect_keys_for(path) -> Optional[frozenset[str]]` as a public method on `UrlRules`, intended to expose the matching rule's detect set for warning emission. As built, `emit_global_mask_warnings` iterates `url_rules.rules` directly (per-rule, per-key) rather than going through a path-based lookup — so the method had no caller and was omitted.

- **Reason**: the warning emitter doesn't take a `path`; it walks every rule once at load time. A `detect_keys_for(path)` would be needed by a per-request consumer, but none of the planned callers (proxy dispatch, warning emission) need it. Adding it as dead API would invite future confusion.
- **Impact**: none. The public surface is `UrlRulesError`, `UrlRules` (with `is_enabled`, `rules` attribute), `load_url_rules`, `is_rule_enabled`, `emit_global_mask_warnings` — all callers in the codebase use only these. Future code that needs path-keyed lookup can add the method then; the matcher loop is two lines.
- **Resolution**: design intent unchanged; this section records the API drop. Main spec (`openspec/specs/waf-detector/spec.md`) will reflect actual behavior at archive time.
