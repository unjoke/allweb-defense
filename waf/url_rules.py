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
        # prefix: requires segment boundary (so /api/* does NOT match /api or /apifoo)
        return path.startswith(rule.pattern + "/")


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


def load_url_rules(path: str) -> UrlRules:
    """Read YAML, validate strictly, compile. Raises FileNotFoundError or UrlRulesError."""
    import yaml  # local import: PyYAML is required; config layer guards optionality elsewhere

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
            raise UrlRulesError(
                f"rules[{i}]: each rule must be a mapping, got {type(entry).__name__}"
            )

        # Required fields (V4)
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

        # Duplicate url (V11) — literal-string match (only meaningful when url_str is a str;
        # earlier compile call would have raised V6 if not a str, so url_str is hashable here)
        if isinstance(url_str, str):
            if url_str in seen_urls:
                raise UrlRulesError(
                    f"rules[{i}]: duplicate url {url_str!r} (also at rules[{seen_urls[url_str]}])"
                )
            seen_urls[url_str] = i

        # detect validation (V8, V9, V10)
        detect = entry["detect"]
        if not isinstance(detect, list):
            raise UrlRulesError(
                f"rules[{i}]: detect must be a list, got {type(detect).__name__}"
            )
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


def is_rule_enabled(config: dict, path: str, key: str) -> bool:
    """effective(path, key) = global[key] AND (url_rules is None OR url_rules.is_enabled(path, key))."""
    rules = config.get("rules", {})
    if not rules.get(key, True):       # global cap
        return False
    url_rules = config.get("url_rules")
    if url_rules is None:
        return True
    return url_rules.is_enabled(path, key)


def emit_global_mask_warnings(url_rules: UrlRules, global_rules: dict) -> None:
    raise NotImplementedError  # filled in Task 9
