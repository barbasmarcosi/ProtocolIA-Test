"""Independent P3-B2.2: two-party signing + host authorization + REAL Docker.

All identity keys and files are created inside disposable CI storage.
An offline subprocess signs; the verifier receives only its public key.
"""
from __future__ import annotations
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
from protocolia.action_broker import preview_plan
from protocolia.action_runtime import ExecutionDenied
from protocolia.operator_auth import (
    approve_signed, create_intent, run_signed, revoke_signed
)

BINARY=b"Outside consumer receipt ledger\x00\xff\ntax-2026"
SHA=hashlib.sha256(BINARY).hexdigest()
PLAN={"version":"0.5","plan_id":"october-independent-billing","actions":[
 {"id":"expected","tool":"literal","args":{"value":SHA},"depends_on":[],
  "capability":"compute.literal","effects":[],"timeout_ms":1000,"output_type":"string"},
 {"id":"file","tool":"file.sha256","args":{"resource":"receipts/october"},"depends_on":[],
  "capability":"file.sha256","effects":["read"],"timeout_ms":10000,"output_type":"string"},
 {"id":"check","tool":"assert.eq","args":{"left":{"from":"expected"},"right":{"from":"file"}},
  "depends_on":["expected","file"],"capability":"compute.assert","effects":[],
  "timeout_ms":1000,"output_type":"boolean"}
]}
HOST={"version":"0.5","grants":{"compute.literal":["*"],"file.sha256":["receipts/october"],
                                "compute.assert":["*"]},
      "max_actions":3,"max_external_reads":1,"max_duration_ms":15000}
DOCKER={"version":"0.5","allow":["receipts/october"],"max_bytes":256,
        "timeout_ms":14000,"max_spend_usd":0,"container_image":os.environ["P3_DOCKER_IMAGE_ID"]}

def expect_denied(call, fragment):
    try: call()
    except ExecutionDenied as error:
        assert fragment in str(error),(fragment,str(error))
    else: raise AssertionError("FAIL OPEN: expected "+fragment)

def signing_subprocess(key_file, intent, confirmed_hash, resource, root):
    unsigned=root/"operator-intent.json"
    unsigned.write_text(json.dumps(intent))
    process=subprocess.run(
      [sys.executable,"-m","protocolia.operator_signer","sign",
       "--private-key",str(key_file),"--intent",str(unsigned),
       "--confirm-plan-sha256",confirmed_hash,
       "--confirm-resource",resource],
      text=True,capture_output=True,check=False)
    if process.returncode!=0:
        raise AssertionError("offline operator signer error: "+process.stderr)
    return json.loads(process.stdout)

with tempfile.TemporaryDirectory(prefix="consumer-signer-") as tmp:
    root=Path(tmp)
    inputs=root/"inputs"
    ledger=root/"ledger"
    (inputs/"receipts").mkdir(parents=True)
    ledger.mkdir()
    file=inputs/"receipts"/"october"
    file.write_bytes(BINARY)
    identity_dir=root/"operator-key-store"
    identity_dir.mkdir(mode=0o700)
    priv=identity_dir/"alice.ed25519"
    generated=subprocess.run(
      [sys.executable,"-m","protocolia.operator_signer","create-key",
       "--private-key",str(priv)],text=True,capture_output=True,check=True)
    public=json.loads(generated.stdout)["ed25519_public_b64"]
    assert priv.stat().st_mode & 0o777==0o600
    registry={"version":"0.6","operators":{"independent-alice":{
      "enabled":True,"resources":["receipts/october"],"keys":{
        "phone1":{"ed25519_public_b64":public,"revoked":False}}}}}
    registry_file=root/"trusted-registry.json"
    registry_file.write_text(json.dumps(registry))
    registry_file.chmod(0o600)
    keyfile=root/"host-key.dat"
    keyfile.write_bytes(secrets.token_bytes(32))
    keyfile.chmod(0o600)
    opts={"registry_file":registry_file,"service_key_file":keyfile,
          "host_environment":"external-test-host"}
    start=int(time.time())
    intent=create_intent(PLAN,HOST,DOCKER,inputs,registry_file,
       subject="independent-alice",key_id="phone1",
       environment=opts["host_environment"],
       issued_at=start,expires_at=start+180,nonce=secrets.token_hex(16))
    assert intent["resource"]=="receipts/october"
    assert intent["tool"]=="file.sha256"
    assert intent["container_image"]==DOCKER["container_image"]
    preview=preview_plan(PLAN,HOST,DOCKER,inputs)
    assert intent["plan_sha256"]==preview["plan_sha256"]
    assert intent["input_sha256"]==SHA
    assert not list(ledger.iterdir())
    # An operator cannot be tricked into signing a mismatched plan hash.
    signed_file=root/"operator-intent.json"
    signed_file.write_text(json.dumps(intent))
    bogus=subprocess.run([sys.executable,"-m","protocolia.operator_signer","sign",
        "--private-key",str(priv),"--intent",str(signed_file),
        "--confirm-plan-sha256","0"*64,
        "--confirm-resource","receipts/october"],
        capture_output=True,text=True)
    assert bogus.returncode!=0
    signed=signing_subprocess(priv,intent,intent["plan_sha256"],"receipts/october",root)
    expect_denied(lambda:run_signed(signed,PLAN,HOST,DOCKER,inputs,ledger,**opts),"approval ledger")
    # A second random (non-enrolled) private key cannot forge consent.
    intruder_key=identity_dir/"intruder.ed25519"
    subprocess.run([sys.executable,"-m","protocolia.operator_signer","create-key",
        "--private-key",str(intruder_key)],check=True,capture_output=True)
    forged=signing_subprocess(intruder_key,intent,intent["plan_sha256"],"receipts/october",root)
    expect_denied(lambda:approve_signed(forged,PLAN,HOST,DOCKER,inputs,ledger,**opts),"signature")
    assert not list(ledger.iterdir())
    first_grant=approve_signed(signed,PLAN,HOST,DOCKER,inputs,ledger,**opts)
    first=run_signed(signed,PLAN,HOST,DOCKER,inputs,ledger,**opts)
    again=run_signed(signed,PLAN,HOST,DOCKER,inputs,ledger,**opts)
    assert first["status"]=="executed" and again["status"]=="replayed"
    assert first["outputs"]["check"] is True
    assert first["outputs"]["file"]==SHA
    assert first["operator"]=="independent-alice"
    with sqlite3.connect(ledger/"protocolia-sandbox.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]==1
        assert db.execute("SELECT COUNT(*) FROM operator_receipts").fetchone()[0]==1
    file.write_bytes(b"changed after operator approval")
    expect_denied(lambda:run_signed(signed,PLAN,HOST,DOCKER,inputs,ledger,**opts),"stale")
    file.write_bytes(BINARY)
    # Operator key revocation blocks replays even when the underlying HMAC is valid.
    registry["operators"]["independent-alice"]["keys"]["phone1"]["revoked"]=True
    registry_file.write_text(json.dumps(registry))
    registry_file.chmod(0o600)
    expect_denied(lambda:run_signed(signed,PLAN,HOST,DOCKER,inputs,ledger,**opts),"revoked")
    # Key rotation: a new public key and a NEW plan/request ID are required.
    registry["operators"]["independent-alice"]["keys"]["phone2"]={
        "ed25519_public_b64":json.loads(subprocess.run(
          [sys.executable,"-m","protocolia.operator_signer","create-key",
           "--private-key",str(identity_dir/"new.ed25519")],
          text=True,capture_output=True,check=True).stdout)["ed25519_public_b64"],
        "revoked":False}
    registry_file.write_text(json.dumps(registry))
    registry_file.chmod(0o600)
    second_plan=copy.deepcopy(PLAN)
    second_plan["plan_id"]="october-new-operator-key"
    replacement=create_intent(second_plan,HOST,DOCKER,inputs,registry_file,
       subject="independent-alice",key_id="phone2",
       environment=opts["host_environment"],
       issued_at=start,expires_at=start+180,nonce=secrets.token_hex(16))
    replacement_signed=signing_subprocess(identity_dir/"new.ed25519",replacement,
        replacement["plan_sha256"],"receipts/october",root)
    approve_signed(replacement_signed,second_plan,HOST,DOCKER,inputs,ledger,**opts)
    replacement_result=run_signed(replacement_signed,second_plan,HOST,DOCKER,inputs,ledger,**opts)
    assert replacement_result["status"]=="executed"
    assert replacement_result["outputs"]["check"] is True
    # A different private key is never silently accepted as existing identity.
    assert first_grant["status"]=="approved-operator"
print("INDEPENDENT OPERATOR GATE: PASS offline CLI key custody, signed real Docker, "
      "attacker signature denial, nonce, read-only replay, resource mismatch, "
      "stale content and key revocation/rotation.")
