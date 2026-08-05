from sec_harness.schema import validate


def test_accepts_valid_flat_object():
    schema = {
        "type": "object",
        "required": ["id", "count"],
        "properties": {
            "id": {"type": "string"},
            "count": {"type": "integer"},
        },
    }
    assert validate({"id": "a", "count": 3}, schema) == []


def test_flags_missing_required_field():
    schema = {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}
    errors = validate({}, schema)
    assert any("id" in e and "required" in e for e in errors)


def test_flags_wrong_type():
    schema = {"type": "object", "properties": {"count": {"type": "integer"}}}
    errors = validate({"count": "not-a-number"}, schema)
    assert any("count" in e for e in errors)


def test_nullable_type_accepts_null_and_typed_value():
    schema = {"type": "object", "properties": {"score": {"type": ["integer", "null"]}}}
    assert validate({"score": None}, schema) == []
    assert validate({"score": 5}, schema) == []
    assert validate({"score": "x"}, schema) != []


def test_enum_rejects_value_outside_set():
    schema = {"type": "object", "properties": {"status": {"enum": ["raw", "confirmed"]}}}
    assert validate({"status": "raw"}, schema) == []
    errors = validate({"status": "bogus"}, schema)
    assert any("status" in e for e in errors)


def test_array_items_are_validated():
    schema = {
        "type": "object",
        "properties": {"tags": {"type": "array", "items": {"type": "string"}}},
    }
    assert validate({"tags": ["a", "b"]}, schema) == []
    errors = validate({"tags": ["a", 3]}, schema)
    assert any("tags[1]" in e for e in errors)


def test_unknown_keys_not_in_properties_are_ignored():
    schema = {"type": "object", "properties": {"id": {"type": "string"}}}
    assert validate({"id": "a", "extra": "ignored"}, schema) == []


def test_top_level_non_object_is_flagged():
    schema = {"type": "object", "properties": {}}
    errors = validate("not-a-dict", schema)
    assert errors and "object" in errors[0]
