"""Independent P3 host Unix service, offline operator identity, real Docker, cost budget."""
from __future__ import annotations
import base64
from concurrent.futures import ThreadPoolExecutor
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

from protocolia.action_runtime import ExecutionDenied
from protocolia.operator_service import client, SOCK_NAME
from protocolia.operator_signer import generate_private_key
from protocolia.cost_ledger import CostLedger, sign_quote, sign_usage

DATA=b"Independent external receipt 2026-10-10\x00\xff"
HASH=hashlib.sha256(DATA).hexdigest()
PLAN={"version":"0.5","plan_id":"p3-consumer-signed-receipt","actions":[
    {"id":"expected","tool":"literal","args":{"value":HASH},"depends_on":[],
     "capability":"compute.literal","effects":[],"timeout_ms":1000,"output_type":"string"},
    {"id":"read","tool":"file.sha256","args":{"resource":"receipts/october"},
     "depends_on":[],"capability":"file.sha256","effects":["read"],
     "timeout_ms":10000,"output_type":"string"},
    {"id":"check","tool":"assert.eq","args":{"left":{"from":"read"},"right":{"from":"expected"}},
     "depends_on":["expected","read"],"capability":"compute.assert",
     "effects":[],"timeout_ms":1000,"output_type":"boolean"},
]}
HOST={"version":"0.5","grants":{"compute.literal":["*"],"compute.assert":["*"],
                                "file.sha256":["receipts/october"]},
      "max_actions":3,"max_external_reads":1,"max_duration_ms":15000}
DOCKER={"version":"0.5","allow":["receipts/october"],"max_bytes":256,
        "timeout_ms":11000,"max_spend_usd":0,
        "container_image":os.environ["P3_INDEPENDENT_DOCKER_ID"]}

def denied(callback,label):
    try:callback()
    except (ExecutionDenied,OSError):return
    raise AssertionError("FAIL OPEN: "+label)

with tempfile.TemporaryDirectory(prefix="p3-consumer-host-") as tmp:
    root=Path(tmp)
    inputroot=root/"inputs"
    (inputroot/"receipts").mkdir(parents=True)
    (inputroot/"receipts"/"october").write_bytes(DATA)
    ledger=root/"ledger"
    ledger.mkdir(mode=0o700)
    operator=root/"operator"
    operator.mkdir(mode=0o700)
    keyfile=operator/"key.ed25519"
    pub=generate_private_key(keyfile)
    registry={"version":"0.6","operators":{"auditor":{"enabled":True,
        "resources":["receipts/october"],"keys":{
            "key1":{"ed25519_public_b64":pub,"revoked":False}}}}}
    privates={
        "registry":json.dumps(registry).encode(),
        "service":secrets.token_bytes(32),
        "host":json.dumps(HOST).encode(),"docker":json.dumps(DOCKER).encode()}
    names={}
    for name,data in privates.items():
        path=root/("private-"+name)
        path.write_bytes(data)
        path.chmod(0o600)
        names[name]=path
    config={
        "version":"0.6","inputs":str(inputroot),"workspace":str(ledger),
        "registry_file":str(names["registry"]),"service_key_file":str(names["service"]),
        "host_policy_file":str(names["host"]),"docker_policy_file":str(names["docker"]),
        "environment":"independent-host","allowed_uids":[os.geteuid()]}
    conf=root/"host-config.json"
    conf.write_text(json.dumps(config))
    conf.chmod(0o600)
    daemon=subprocess.Popen([sys.executable,"-m","protocolia.operator_service",
                              "--config",str(conf)],
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    socketfile=ledger/SOCK_NAME
    try:
        for iteration in range(150):
            if socketfile.is_socket():break
            if daemon.poll() is not None:raise AssertionError(daemon.stderr.read())
            time.sleep(.05)
        else:raise AssertionError("independent Unix broker failed to start")
        assert client(socketfile,{"op":"preview","plan":PLAN})["status"]=="preview-only"
        intent=client(socketfile,{"op":"prepare","plan":PLAN,
                                  "subject":"auditor","key_id":"key1"})["intent"]
        assert intent["resource"]=="receipts/october" and intent["input_sha256"]==HASH
        assert not (ledger/"protocolia-sandbox.sqlite3").exists()
        intentfile=root/"reviewed-intent.json"
        intentfile.write_text(json.dumps(intent))
        signed=subprocess.run([
            sys.executable,"-m","protocolia.operator_signer","sign",
            "--private-key",str(keyfile),"--intent",str(intentfile),
            "--confirm-plan-sha256",intent["plan_sha256"],
            "--confirm-resource","receipts/october"],
            capture_output=True,text=True,check=True)
        envelope=json.loads(signed.stdout)
        forged={"intent":intent,"signature_b64":base64.b64encode(secrets.token_bytes(64)).decode()}
        denied(lambda:client(socketfile,{"op":"approve","plan":PLAN,"envelope":forged}),
               "forged signature must not mint a grant")
        denied(lambda:client(socketfile,{"op":"approve","plan":PLAN,"envelope":envelope,
                                        "service_key_file":"/tmp/injected"}),
               "agent cannot override signing key")
        approved=client(socketfile,{"op":"approve","plan":PLAN,"envelope":envelope})
        assert approved["status"]=="approved-operator"
        first=client(socketfile,{"op":"execute","plan":PLAN,"envelope":envelope},timeout=30)
        second=client(socketfile,{"op":"execute","plan":PLAN,"envelope":envelope},timeout=30)
        assert first["status"]=="executed" and second["status"]=="replayed"
        assert first["outputs"]["check"] is True
        assert first["outputs"]["read"]==HASH
        with sqlite3.connect(ledger/"protocolia-sandbox.sqlite3") as db:
            assert db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]==1
        new_plan=json.loads(json.dumps(PLAN))
        new_plan["actions"][0]["args"]["value"]="changed"
        denied(lambda:client(socketfile,{"op":"execute","plan":new_plan,"envelope":envelope}),
               "changed plan cannot reuse signed approval")
        (inputroot/"receipts"/"october").write_bytes(b"tampered")
        denied(lambda:client(socketfile,{"op":"execute","plan":PLAN,"envelope":envelope}),
               "changed resource not signed")
        (inputroot/"receipts"/"october").write_bytes(DATA)
        registry["operators"]["auditor"]["keys"]["key1"]["revoked"]=True
        names["registry"].write_text(json.dumps(registry))
        names["registry"].chmod(0o600)
        denied(lambda:client(socketfile,{"op":"execute","plan":PLAN,"envelope":envelope}),
               "revoked operator cannot replay")
        config["allowed_uids"]=[os.geteuid()+1]
        conf.write_text(json.dumps(config))
        conf.chmod(0o600)
        denied(lambda:client(socketfile,{"op":"preview","plan":PLAN}),
               "kernel peer UID denied by host allowlist")
    finally:
        daemon.terminate()
        try:daemon.communicate(timeout=8)
        except subprocess.TimeoutExpired:daemon.kill();daemon.communicate()

    # Separate cost fixture: quotes from trusted meter; model cannot mint proof.
    expense_root=root/"expense"
    expense_root.mkdir(mode=0o700)
    expense_key=root/"meter-secret"
    meter_key=secrets.token_bytes(32)
    expense_key.write_bytes(meter_key)
    expense_key.chmod(0o600)
    ledger=CostLedger(expense_root,expense_key,now=lambda:100.0)
    def quote(op,amount):
        value={"version":"0.1","op_id":op,"scope":"missioncost",
               "provider":"modeladapter","max_micro_usd":amount,"expires_at":300}
        return value,sign_quote(value,meter_key)
    def reserve(i):
        try:return ledger.reserve(*quote("operation"+str(i),3),budget_ceiling=10)["status"]
        except ExecutionDenied:return "denied"
    with ThreadPoolExecutor(max_workers=6) as pool:
        verdicts=list(pool.map(reserve,range(6)))
    assert verdicts.count("reserved")==3,verdicts
    assert ledger.totals("missioncost")["remaining_micro_usd"]==1
    winner=verdicts.index("reserved")
    winning_id="operation"+str(winner)
    ledger.started(winning_id)
    usage={"version":"0.1","op_id":winning_id,"provider":"modeladapter",
           "receipt_id":"vendorproof0","actual_micro_usd":2}
    assert ledger.settle(usage,sign_usage(usage,meter_key))["status"]=="settled"
    assert ledger.totals("missioncost")["remaining_micro_usd"]==2
    unknown,signature=quote("unknownprice",3)
    unknown["max_micro_usd"]=None
    denied(lambda:ledger.reserve(unknown,signature,budget_ceiling=10),
           "unknown cost cannot reserve")
    print("INDEPENDENT P3 HOST & BUDGET: PASS signed operator Unix daemon, real Docker, "
          "key revocation, malicious RPC and UID denial; atomic cost ceiling, "
          "signed vendor usage and unknown-cost denial")
