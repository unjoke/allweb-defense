import pytest
from evaluation.payload_loader import load, load_all, validate, REQUIRED_FIELDS


def test_load_valid_yaml(tmp_path):
    f = tmp_path / "test.yaml"
    f.write_text(
        "- id: sqli-001\n"
        "  payload: \"' OR 1=1--\"\n"
        "  category: sql_injection\n"
        "  technique: tautology\n"
        "  difficulty: basic\n"
        "  source: OWASP\n"
        "  expected: blocked\n"
        "  inject_point: query_param\n"
        "  param_name: q\n",
        encoding="utf-8",
    )
    payloads = load(str(f))
    assert len(payloads) == 1
    assert payloads[0]["id"] == "sqli-001"


def test_missing_field_raises_with_id(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text(
        "- id: sqli-bad\n"
        "  payload: x\n"
        "  category: sql_injection\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="sqli-bad"):
        load(str(f))


def test_invalid_category_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text(
        "- id: x-001\n"
        "  payload: x\n"
        "  category: not_a_real_category\n"
        "  technique: t\n"
        "  difficulty: basic\n"
        "  source: OWASP\n"
        "  expected: blocked\n"
        "  inject_point: query_param\n"
        "  param_name: q\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="category"):
        load(str(f))


def test_required_fields_constant():
    assert "id" in REQUIRED_FIELDS
    assert "payload" in REQUIRED_FIELDS
    assert "category" in REQUIRED_FIELDS
    assert "inject_point" in REQUIRED_FIELDS
