"""Load and validate WAF evaluation payload files (YAML)."""
from __future__ import annotations
from pathlib import Path
import yaml

REQUIRED_FIELDS = (
    "id", "payload", "category", "technique", "difficulty",
    "source", "expected", "inject_point", "param_name",
)
VALID_CATEGORIES = {
    "sql_injection", "xss", "path_traversal", "cmd_injection",
    "file_upload", "rate_limit", "benign",
}
VALID_DIFFICULTY = {"basic", "intermediate", "advanced"}
VALID_SOURCES = {"HackTricks", "PayloadsAllTheThings", "PortSwigger", "OWASP", "custom"}
VALID_EXPECTED = {"blocked", "allowed"}
VALID_INJECT_POINTS = {"query_param", "form_body", "path", "header", "filename"}


def validate(p: dict) -> None:
    if not isinstance(p, dict):
        raise ValueError(f"payload entry is not a dict: {p!r}")
    pid = p.get("id", "<no-id>")
    for field in REQUIRED_FIELDS:
        if field not in p:
            raise ValueError(f"payload {pid}: missing required field '{field}'")
    if p["category"] not in VALID_CATEGORIES:
        raise ValueError(f"payload {pid}: invalid category '{p['category']}'")
    if p["difficulty"] not in VALID_DIFFICULTY:
        raise ValueError(f"payload {pid}: invalid difficulty '{p['difficulty']}'")
    if p["source"] not in VALID_SOURCES:
        raise ValueError(f"payload {pid}: invalid source '{p['source']}'")
    if p["expected"] not in VALID_EXPECTED:
        raise ValueError(f"payload {pid}: invalid expected '{p['expected']}'")
    if p["inject_point"] not in VALID_INJECT_POINTS:
        raise ValueError(f"payload {pid}: invalid inject_point '{p['inject_point']}'")


def load(path: str) -> list[dict]:
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected top-level list")
    for p in data:
        validate(p)
    return data


def load_all(
    payloads_dir: str,
    *,
    category: str | None = None,
    skip_rate_limit: bool = False,
) -> list[dict]:
    out: list[dict] = []
    for f in sorted(Path(payloads_dir).glob("*.yaml")):
        loaded = load(str(f))
        out.extend(loaded)
    if category:
        out = [p for p in out if p["category"] == category]
    if skip_rate_limit:
        out = [p for p in out if p["category"] != "rate_limit"]
    return out
