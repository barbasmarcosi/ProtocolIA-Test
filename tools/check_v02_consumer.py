"""External consumer v0.2 fixture: strict executable validation and migration."""
import copy
import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from protocolia import ContractError, compare_contracts, migrate_contract, validate, validate_payload, validate_path_params

root=Path(__file__).resolve().parents[1]
contract=json.loads((root/'contracts/inventory-v0.2.json').read_text(encoding='utf-8'))
schema=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
artifacts=Path(sys.argv[2])
assert Draft202012Validator(schema).is_valid(contract)
validate(contract)
oas=json.loads((artifacts/'openapi.json').read_text())
assert oas['paths']['/inventory/{sku}']['get']['parameters'][0]['name']=='sku'
assert oas['paths']['/inventory/{sku}']['get']['parameters'][0]['required'] is True
assert validate_path_params(contract,'getItem',{'sku':'abc-12'})
assert not validate_path_params(contract,'getItem',{'unknown':'abc'})
item={'sku':'X-01','quantity':0}
assert validate_payload(contract,'Item',item)
for bad in [{'sku':'X-01','quantity':-1},{'sku':'X-01','quantity':True},{'sku':'bad space','quantity':0},{'sku':'X-01','quantity':0,'status':'unknown'}]:
    assert not validate_payload(contract,'Item',bad),bad
payload=json.loads((artifacts/'payload.schema.json').read_text())
payload['$ref']='#/$defs/Item'
external=Draft202012Validator(payload,format_checker=FormatChecker())
for tested in [item,{'sku':'x', 'quantity':0},{'sku':'abc','quantity':101000},{'sku':'X-01','quantity':0,'status':'reserved'}]:
    assert external.is_valid(tested)==validate_payload(contract,'Item',tested),tested
old=json.loads((root/'contracts/inventory.json').read_text())
migrated=migrate_contract(old)
assert migrated['version']=='0.2' and validate(migrated)
try: compare_contracts(old,migrated)
except ContractError:pass
else:raise AssertionError('implicit cross-version migration accepted')
print('P1 INDEPENDENT V0.2 CONSUMER: PASS')
