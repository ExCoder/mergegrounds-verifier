"""Draft 2020-12 JSON Schema validation with closed object schemas."""

from __future__ import annotations

import json
from functools import cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

SCHEMAS = {
    "subject": "subject-v1.schema.json",
    "policy": "policy-v1.schema.json",
    "evidence": "evidence-v1.schema.json",
    "waiver": "waiver-v1.schema.json",
    "decision": "decision-v1.schema.json",
}


@cache
def validator(kind: str) -> Draft202012Validator:
    try:
        name = SCHEMAS[kind]
    except KeyError as exc:
        raise ValueError(f"unknown schema kind: {kind}") from exc
    resource = files("mergegrounds_verifier.schemas").joinpath(name)
    schema = json.loads(resource.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validation_messages(kind: str, value: Any) -> list[str]:
    errors = sorted(
        validator(kind).iter_errors(value),
        key=lambda error: (tuple(str(part) for part in error.absolute_path), error.message),
    )
    messages: list[str] = []
    for error in errors:
        path = "/" + "/".join(str(part) for part in error.absolute_path)
        message = f"{path or '/'}: {error.message}"
        messages.append(message if len(message) <= 512 else message[:509] + "...")
    return messages
