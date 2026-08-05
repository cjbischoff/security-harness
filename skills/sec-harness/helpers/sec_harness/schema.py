"""Minimal JSON-Schema-subset validator (stdlib only).

Supports the subset this repo's ``references/*.schema.json`` files actually use:
``type`` (string or list-of-strings for nullable fields), ``enum``, ``required``,
``items`` (array element schema), ``properties`` (nested object schema). Not a
general-purpose JSON Schema implementation — extend only when a new schema file
needs a keyword this module doesn't yet support.
"""

from __future__ import annotations

_TYPE_MAP = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
    "null": type(None),
}


def validate(data, schema: dict) -> list[str]:
    """Validate ``data`` against ``schema``.

    Args:
        data: The parsed JSON value to check (usually a dict).
        schema: A JSON-Schema-subset dict (see module docstring for supported keywords).

    Returns:
        A list of human-readable error strings; empty when ``data`` is valid.
    """
    errors: list[str] = []
    _validate_value(data, schema, "$", errors)
    return errors


def _check_type(value, type_spec, path: str, errors: list[str]) -> bool:
    types = type_spec if isinstance(type_spec, list) else [type_spec]
    py_types = tuple(_TYPE_MAP[t] for t in types)
    if not isinstance(value, py_types):
        type_names = "|".join(types)
        errors.append(f"{path}: expected type {type_names}, got {type(value).__name__}")
        return False
    return True


def _validate_value(value, prop_schema: dict, path: str, errors: list[str]) -> None:
    if "type" in prop_schema and not _check_type(value, prop_schema["type"], path, errors):
        return
    if "enum" in prop_schema and value not in prop_schema["enum"]:
        errors.append(f"{path}: value {value!r} not in enum {prop_schema['enum']}")
    if isinstance(value, dict):
        _validate_object_fields(value, prop_schema, path, errors)
    if isinstance(value, list) and "items" in prop_schema:
        for i, item in enumerate(value):
            _validate_value(item, prop_schema["items"], f"{path}[{i}]", errors)


def _validate_object_fields(data: dict, schema: dict, path: str, errors: list[str]) -> None:
    for key in schema.get("required", []):
        if key not in data:
            errors.append(f"{path}.{key}: missing required field")
    properties = schema.get("properties", {})
    for key, prop_schema in properties.items():
        if key in data:
            _validate_value(data[key], prop_schema, f"{path}.{key}", errors)
