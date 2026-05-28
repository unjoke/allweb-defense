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


def _valid_payload(pid="p-001", **overrides):
    base = {
        "id": pid,
        "payload": "x",
        "category": "sql_injection",
        "technique": "tautology",
        "difficulty": "basic",
        "source": "OWASP",
        "expected": "blocked",
        "inject_point": "query_param",
        "param_name": "q",
    }
    base.update(overrides)
    lines = [f"- id: {base['id']}"]
    for k, v in base.items():
        if k == "id":
            continue
        lines.append(f"  {k}: {v}")
    return "\n".join(lines) + "\n"


def test_validate_rejects_non_dict(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("- just a string\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not a dict"):
        load(str(f))


def test_invalid_difficulty_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text(_valid_payload(difficulty="impossible"), encoding="utf-8")
    with pytest.raises(ValueError, match="difficulty"):
        load(str(f))


def test_invalid_source_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text(_valid_payload(source="MadeUpSource"), encoding="utf-8")
    with pytest.raises(ValueError, match="source"):
        load(str(f))


def test_invalid_expected_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text(_valid_payload(expected="maybe"), encoding="utf-8")
    with pytest.raises(ValueError, match="expected"):
        load(str(f))


def test_invalid_inject_point_raises(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text(_valid_payload(inject_point="cookie"), encoding="utf-8")
    with pytest.raises(ValueError, match="inject_point"):
        load(str(f))


def test_load_all_aggregates_multiple_files(tmp_path):
    (tmp_path / "a.yaml").write_text(_valid_payload(pid="a-1"), encoding="utf-8")
    (tmp_path / "b.yaml").write_text(_valid_payload(pid="b-1"), encoding="utf-8")
    payloads = load_all(str(tmp_path))
    assert len(payloads) == 2
    ids = {p["id"] for p in payloads}
    assert ids == {"a-1", "b-1"}


def test_load_all_category_filter(tmp_path):
    (tmp_path / "a.yaml").write_text(_valid_payload(pid="sqli-1", category="sql_injection"), encoding="utf-8")
    (tmp_path / "b.yaml").write_text(_valid_payload(pid="xss-1", category="xss"), encoding="utf-8")
    payloads = load_all(str(tmp_path), category="xss")
    assert len(payloads) == 1
    assert payloads[0]["id"] == "xss-1"


def test_load_all_skip_rate_limit(tmp_path):
    (tmp_path / "a.yaml").write_text(_valid_payload(pid="rl-1", category="rate_limit"), encoding="utf-8")
    (tmp_path / "b.yaml").write_text(_valid_payload(pid="sqli-1", category="sql_injection"), encoding="utf-8")
    payloads = load_all(str(tmp_path), skip_rate_limit=True)
    ids = {p["id"] for p in payloads}
    assert ids == {"sqli-1"}


def test_load_all_sorted_file_order(tmp_path):
    (tmp_path / "c.yaml").write_text(_valid_payload(pid="c-1"), encoding="utf-8")
    (tmp_path / "a.yaml").write_text(_valid_payload(pid="a-1"), encoding="utf-8")
    (tmp_path / "b.yaml").write_text(_valid_payload(pid="b-1"), encoding="utf-8")
    payloads = load_all(str(tmp_path))
    assert [p["id"] for p in payloads] == ["a-1", "b-1", "c-1"]

