"""Independent diff acceptance using consumer-owned inventory fixtures."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from protocolia import compare_contracts

ROOT = Path(__file__).resolve().parents[1]
baseline = json.loads((ROOT / "contracts" / "inventory.json").read_text(encoding="utf-8"))

optional = copy.deepcopy(baseline)
optional["models"]["Item"]["description"] = {"type": "string", "required": False}
report = compare_contracts(baseline, optional)
assert report["compatible"] and report["additive"] == 1, report

required = copy.deepcopy(baseline)
required["models"]["Item"]["minimum_stock"] = {"type": "integer", "required": True}
report = compare_contracts(baseline, required)
assert not report["compatible"] and report["breaking"] == 1, report

changed = copy.deepcopy(baseline)
changed["operations"]["listItems"]["capability"] = "inventory.admin"
report = compare_contracts(baseline, changed)
assert not report["compatible"], report

reordered = copy.deepcopy(baseline)
reordered["operations"]["addItem"]["effects"] = list(reversed(reordered["operations"]["addItem"]["effects"]))
assert compare_contracts(baseline, reordered)["compatible"]

with tempfile.TemporaryDirectory() as directory:
    before = Path(directory) / "old.json"
    after = Path(directory) / "new.json"
    before.write_text(json.dumps(baseline))
    after.write_text(json.dumps(required))
    cli = subprocess.run([sys.executable, "-m", "protocolia", "diff", str(before), str(after)],
                         capture_output=True, text=True, check=False)
    assert cli.returncode == 2 and json.loads(cli.stdout)["breaking"] > 0, (cli.returncode, cli.stdout, cli.stderr)

print("INDEPENDENT P1 COMPATIBILITY: five checks passed")
