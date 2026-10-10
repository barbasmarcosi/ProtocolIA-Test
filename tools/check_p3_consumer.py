"""Independent P3 consumer: strict CLI+library, replay, tamper and budgets."""
import copy
import json
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from protocolia.action_runtime import ExecutionDenied, validate_plan, execute, dry_run

ROOT=Path(__file__).resolve().parents[1]
SAMPLE=json.loads((ROOT/"plans/warehouse-audit.json").read_text())
POLICY=json.loads((ROOT/"plans/warehouse-policy.json").read_text())
assert len(validate_plan(SAMPLE)["actions"])==5
assert dry_run(SAMPLE,POLICY)["writes"]==1

with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)
    cmd=[sys.executable,"-m","protocolia","action-run",str(ROOT/"plans/warehouse-audit.json"),
         "--policy",str(ROOT/"plans/warehouse-policy.json"),"--out",tmp,"--environment","external-consumer-1"]
    preview=[sys.executable,"-m","protocolia","action-preview",str(ROOT/"plans/warehouse-audit.json"),
             "--policy",str(ROOT/"plans/warehouse-policy.json")]
    p=subprocess.run(preview,text=True,capture_output=True,check=True)
    assert json.loads(p.stdout)["writes"]==1
    assert not list(root.iterdir()),"dry run must not have side effects"
    first=subprocess.run(cmd,text=True,capture_output=True,check=True)
    result=json.loads(first.stdout)
    assert result["status"]=="executed" and result["outputs"]["compare"] is True,result
    second=subprocess.run(cmd,text=True,capture_output=True,check=True)
    repeated=json.loads(second.stdout)
    assert repeated["status"]=="replayed", repeated
    assert result["evidence_sha256"]==repeated["evidence_sha256"]
    with sqlite3.connect(root/"protocolia-action.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM executions").fetchone()[0]==1
        assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0]==5
        db.execute("UPDATE kv SET value='other' WHERE key='warehouse/sku1'")
    stale=subprocess.run(cmd,text=True,capture_output=True)
    assert stale.returncode!=0 and "stale external state" in stale.stderr,stale.stderr
    mismatch=subprocess.run(cmd[:-1]+["external-consumer-2"],text=True,capture_output=True)
    assert mismatch.returncode!=0 and "stale plan/policy/environment" in mismatch.stderr,mismatch.stderr

with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp)
    forbidden=copy.deepcopy(SAMPLE)
    forbidden["actions"][2]["args"]["key"]="../host/file"
    try:execute(forbidden,POLICY,root,environment="external-consumer-1")
    except ExecutionDenied:pass
    else:raise AssertionError("resource traversal not rejected")
    forbidden=copy.deepcopy(SAMPLE)
    forbidden["actions"][2]["capability"]="kv.read"
    try:dry_run(forbidden,POLICY)
    except ExecutionDenied:pass
    else:raise AssertionError("forged capability not rejected")
    forbidden=copy.deepcopy(SAMPLE)
    forbidden["actions"][2]["tool"]="shell.exec"
    try:dry_run(forbidden,POLICY)
    except ExecutionDenied:pass
    else:raise AssertionError("shell execution not rejected")
    privilege=copy.deepcopy(POLICY)
    privilege["grants"]["kv.write"]=[]
    try:execute(SAMPLE,privilege,root,environment="external-consumer-1")
    except ExecutionDenied:pass
    else:raise AssertionError("denied effects were executed")
    assert not list(root.iterdir()),"denial must happen before state creation"
    cancelled=lambda: True
    try:execute(SAMPLE,POLICY,root,environment="external-consumer-1",cancelled=cancelled)
    except ExecutionDenied:pass
    else:raise AssertionError("trusted cancel did not stop execution")
    assert not list(root.iterdir()),"cancel must happen before effects"
    budget=copy.deepcopy(POLICY)
    budget["max_writes"]=0
    try:dry_run(SAMPLE,budget)
    except ExecutionDenied:pass
    else:raise AssertionError("cost/write budget not enforced")
    assert not list(root.iterdir())
print("P3 INDEPENDENT CONSUMER: PASS authorized execution, 5-event ledger, exact replay, "
      "stale state/env denial, traversal, forged permission, forbidden shell, budget, cancellation and zero-effect denials")
