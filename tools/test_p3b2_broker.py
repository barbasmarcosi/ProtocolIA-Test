"""Independent consumer: typed DAG with host-granted read-only Docker, not upstream fixtures."""
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile

from protocolia.action_broker import (
    ExecutionDenied, approve_plan, preview_plan, run_plan, validate_broker_plan,
)
from protocolia.sandbox_adapter import revoke

CONTENT=b"Independent ProtocolIA-Test warehouse receipts.\x00\n"
EXPECTED=hashlib.sha256(CONTENT).hexdigest()
IMAGE=os.environ["P3B2_IMAGE_ID"]
SECRET=secrets.token_bytes(32)
PLAN={"version":"0.5","plan_id":"independent-receipt-audit","actions":[
    {"id":"expect","tool":"literal","args":{"value":EXPECTED},
     "depends_on":[],"capability":"compute.literal","effects":[],
     "timeout_ms":1000,"output_type":"string"},
    {"id":"hash","tool":"file.sha256","args":{"resource":"receipts/october"},
     "depends_on":[],"capability":"file.sha256","effects":["read"],
     "timeout_ms":10000,"output_type":"string"},
    {"id":"assert","tool":"assert.eq","args":{"left":{"from":"hash"},"right":{"from":"expect"}},
     "depends_on":["expect","hash"],"capability":"compute.assert","effects":[],
     "timeout_ms":1000,"output_type":"boolean"},
]}
HOST={"version":"0.5","grants":{"compute.literal":["*"],"file.sha256":["receipts/october"],"compute.assert":["*"]},
      "max_actions":3,"max_external_reads":1,"max_duration_ms":13000}
DOCKER={"version":"0.5","allow":["receipts/october"],"max_bytes":256,"timeout_ms":14000,
        "max_spend_usd":0,"container_image":IMAGE}
assert len(validate_broker_plan(PLAN)["actions"])==3

def denies(fn,fragment):
    try:fn()
    except ExecutionDenied as exc:
        assert fragment in str(exc),(fragment,str(exc))
    else:raise AssertionError("FAIL OPEN expected "+fragment)

with tempfile.TemporaryDirectory(prefix="consumer-p3b2-") as tmp:
    root=Path(tmp)
    inputs=root/"inputs"
    ledger=root/"ledger"
    (inputs/"receipts").mkdir(parents=True)
    ledger.mkdir()
    path=inputs/"receipts"/"october"
    path.write_bytes(CONTENT)
    identity={"subject":"consumer-host","environment":"isolated-github-runner",
              "secret":SECRET,"now":lambda:100.0}
    inspected=preview_plan(PLAN,HOST,DOCKER,inputs)
    assert inspected["external_snapshot"]["input_sha256"]==EXPECTED
    assert inspected["external_timeout_ms"]==10000
    assert not list(ledger.iterdir())
    denies(lambda:run_plan(PLAN,HOST,DOCKER,inputs,ledger,**identity),"approval ledger")
    permission=approve_plan(PLAN,HOST,DOCKER,inputs,ledger,**identity)

    def invoke(_):
        try:return run_plan(PLAN,HOST,DOCKER,inputs,ledger,**identity)["status"]
        except ExecutionDenied as exc:
            assert "quarantined" in str(exc),str(exc)
            return "running"
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes=list(pool.map(invoke,[0,1]))
    assert "executed" in outcomes,outcomes
    assert all(o in ("executed","replayed","running") for o in outcomes),outcomes
    repeated=run_plan(PLAN,HOST,DOCKER,inputs,ledger,**identity)
    assert repeated["status"]=="replayed" and repeated["outputs"]["assert"] is True
    assert repeated["outputs"]["hash"]==EXPECTED
    with sqlite3.connect(ledger/"protocolia-sandbox.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]==1

    mutate=copy.deepcopy(PLAN)
    mutate["actions"][0]["args"]["value"]="changed-expectation"
    assert preview_plan(mutate,HOST,DOCKER,inputs)["external_request"]["request_id"]!=permission["external_request_id"]
    denies(lambda:run_plan(mutate,HOST,DOCKER,inputs,ledger,**identity),"approval")

    scope=copy.deepcopy(HOST)
    scope["grants"]["file.sha256"]=[]
    denies(lambda:preview_plan(PLAN,scope,DOCKER,inputs),"resource denied")

    paid=copy.deepcopy(DOCKER)
    paid["max_spend_usd"]=None
    denies(lambda:preview_plan(PLAN,HOST,paid,inputs),"spending forbidden")

    evil=copy.deepcopy(PLAN)
    evil["actions"][1]["tool"]="shell.exec"
    denies(lambda:validate_broker_plan(evil),"forbidden broker tool")

    path.write_bytes(b"changed after approval")
    denies(lambda:run_plan(PLAN,HOST,DOCKER,inputs,ledger,**identity),"stale")
    path.write_bytes(CONTENT)
    denies(lambda:revoke(permission["external_request_id"],ledger,
                         secret=b"wrong-explicit-32byte-revoke-secret"),"revocation secret")
    assert run_plan(PLAN,HOST,DOCKER,inputs,ledger,**identity)["status"]=="replayed"
    revoke(permission["external_request_id"],ledger,secret=SECRET)
    denies(lambda:run_plan(PLAN,HOST,DOCKER,inputs,ledger,**identity),"revoked")
    print("INDEPENDENT BROKER + LIVE DOCKER: PASS authorization, typed DAG, SHA postcondition, "
          "two-client exactly-one container, stale plan/input, paid/shell denial, signer-key revocation.")
