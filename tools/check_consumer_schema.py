"""Independent consumer conformance: no ProtocolIA upstream Sales fixtures."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from protocolia import ContractError, validate

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "inventory.json"


def check() -> None:
    schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    structural = Draft202012Validator(schema)
    original = json.loads(CONTRACT.read_text(encoding="utf-8"))
    assert structural.is_valid(original), "independent consumer contract rejected"
    validate(original)
    malformed = copy.deepcopy(original)
    malformed["operations"]["addItem"]["path"] = "/inventory/{id}"
    assert not structural.is_valid(malformed), "v0.1 path parameters must remain forbidden"
    malformed = copy.deepcopy(original)
    malformed["models"]["Item"]["sku"]["required"] = "true"
    assert not structural.is_valid(malformed), "boolean type must be strict"
    malformed = copy.deepcopy(original)
    malformed["operations"]["addItem"]["capability"] = "public"
    assert structural.is_valid(malformed), "shape layer unexpectedly encodes policy"
    try:
        validate(malformed)
    except ContractError:
        pass
    else:
        raise AssertionError("semantic layer accepted public write")
    malformed = copy.deepcopy(original)
    malformed["models"]["Item"]["sku"]["type"] = "UndeclaredType"
    assert structural.is_valid(malformed), "shape unexpectedly resolves references"
    try:
        validate(malformed)
    except ContractError:
        pass
    else:
        raise AssertionError("semantic layer accepted unresolved model")
    print("INDEPENDENT P1 CONTRACT SCHEMA: 5 cases passed")


if __name__ == "__main__":
    check()
