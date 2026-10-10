"""Independent behavioral checks against a pinned, installed ProtocolIA wheel."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from protocolia import ContractError, compile_contract, validate, write_artifacts

CONTRACT = Path(__file__).resolve().parents[1] / "contracts" / "inventory.json"


class ConsumerTest(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_independent_contract_generates_three_apis_and_nested_models(self):
        artifacts = compile_contract(self.contract)
        spec = json.loads(artifacts["openapi.json"])
        self.assertEqual(len([v for p in spec["paths"].values() for v in p.values()]), 3)
        self.assertEqual(spec["components"]["schemas"]["InventoryPage"]["properties"]["items"]["items"]["$ref"], "#/components/schemas/Item")
        self.assertEqual(spec["paths"]["/inventory"]["post"]["security"], [{"bearerAuth": []}])
        self.assertEqual(spec["paths"]["/system/health"]["get"]["security"], [])

    def test_determinism_does_not_depend_on_source_key_order(self):
        a = compile_contract(self.contract)
        c = copy.deepcopy(self.contract)
        c["operations"] = dict(reversed(list(c["operations"].items())))
        b = compile_contract(c)
        self.assertEqual(a, b)
        self.assertEqual(json.loads(a["ir.json"])["execution_order"], ["health", "listItems", "addItem"])

    def test_fails_closed_on_unauthorized_public_mutation(self):
        c = copy.deepcopy(self.contract)
        c["operations"]["addItem"]["capability"] = "public"
        with self.assertRaises(ContractError):
            validate(c)

    def test_fails_closed_on_cycle_and_unrecognized_effect(self):
        c = copy.deepcopy(self.contract)
        c["operations"]["health"]["depends_on"] = ["addItem"]
        with self.assertRaises(ContractError):
            validate(c)
        c = copy.deepcopy(self.contract)
        c["operations"]["addItem"]["effects"].append("shell.execute")
        with self.assertRaises(ContractError):
            validate(c)

    def test_regeneration_protects_edits(self):
        with tempfile.TemporaryDirectory() as d:
            artifacts = compile_contract(self.contract)
            target = Path(d)
            write_artifacts(artifacts, target)
            manifest = json.loads((target / "manifest.json").read_text())
            for name, digest in manifest["artifacts"].items():
                self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(), digest)
            (target / "types.ts").write_text("modified by external consumer")
            with self.assertRaises(ContractError):
                write_artifacts(artifacts, target)


if __name__ == "__main__":
    unittest.main()
