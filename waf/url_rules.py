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
