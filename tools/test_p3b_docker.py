"""External P3-B1 consumer: real Docker and consumer-owned binary snapshot."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
from protocolia.sandbox_adapter import ExecutionDenied, approve, preview, revoke, run

IMAGE=os.environ["P3_DOCKER_IMAGE_ID"]
SECRET=b"EXTERNAL-FIXTURE-operator-trusted-secret-32-bytes"
CONTENT=b"EXTERNAL inventory snapshot\n\x00binary\xff"
POLICY={"version":"0.5","allow":["documents/ledger"],"max_bytes":256,
        "timeout_ms":10000,"max_spend_usd":0,"container_image":IMAGE}
REQ={"version":"0.5","request_id":"external-document-a","tool":"file.sha256","resource":"documents/ledger"}

def denied(fn,part):
    try:fn()
    except ExecutionDenied as e:
        assert part in str(e),(part,str(e))
    else:raise AssertionError("FAIL OPEN: expected denial "+part)

with tempfile.TemporaryDirectory(prefix="external-p3b-") as folder:
    root=Path(folder)
    inputs=root/"inputs"
    workspace=root/"ledger"
    (inputs/"documents").mkdir(parents=True)
    workspace.mkdir()
    file=inputs/"documents"/"ledger"
    file.write_bytes(CONTENT)
    args=dict(subject="external-operator",environment="consumer-runner",secret=SECRET)
    assert preview(REQ,POLICY,inputs)["input_sha256"]==hashlib.sha256(CONTENT).hexdigest()
    assert not list(workspace.iterdir())
    denied(lambda:run(REQ,POLICY,inputs,workspace,**args),"approval")
    approve(REQ,POLICY,inputs,workspace,now=lambda:100.0,**args)
    first=run(REQ,POLICY,inputs,workspace,now=lambda:101.0,**args)
    second=run(REQ,POLICY,inputs,workspace,now=lambda:101.0,**args)
    assert first["status"]=="executed" and second["status"]=="replayed"
    assert first["result"]=={"sha256":hashlib.sha256(CONTENT).hexdigest(),"bytes":len(CONTENT)}
    with sqlite3.connect(workspace/"protocolia-sandbox.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]==1
        assert db.execute("SELECT status FROM attempts WHERE request_id=?", (REQ["request_id"],)).fetchone()[0]=="completed"
    file.write_bytes(b"changed")
    denied(lambda:run(REQ,POLICY,inputs,workspace,now=lambda:101,**args),"stale")
    file.write_bytes(CONTENT)
    denied(lambda:run(REQ,POLICY,inputs,workspace,now=lambda:5000,**args),"expired")
    revoke(REQ["request_id"],workspace,secret=SECRET)
    denied(lambda:run(REQ,POLICY,inputs,workspace,now=lambda:101,**args),"revoked")
    denied(lambda:run(REQ,POLICY,inputs,workspace,subject="bad-actor",
                      environment=args["environment"],secret=SECRET,now=lambda:101),"revoked")
    # Second approved request; two simultaneous clients must never start two containers.
    r2=dict(REQ,request_id="external-document-b")
    approve(r2,POLICY,inputs,workspace,now=lambda:100,**args)
    def consume(_):
        try:return run(r2,POLICY,inputs,workspace,now=lambda:101,**args)["status"]
        except ExecutionDenied as e:
            assert "quarantined" in str(e),str(e)
            return "running"
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses=list(pool.map(consume,[1,2]))
    assert "executed" in statuses,statuses
    assert all(s in {"executed","replayed","running"} for s in statuses),statuses
    assert run(r2,POLICY,inputs,workspace,now=lambda:101,**args)["status"]=="replayed"
    with sqlite3.connect(workspace/"protocolia-sandbox.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]==2
    # Host policy is neither model-editable nor an implicit grant for shell/network.
    other=dict(r2,request_id="external-forbidden",tool="shell")
    denied(lambda:preview(other,POLICY,inputs),"allowlisted")
    other=dict(r2,request_id="external-forbidden",resource="../etc/passwd")
    denied(lambda:preview(other,POLICY,inputs),"invalid")
    other_policy=dict(POLICY,max_spend_usd=None)
    denied(lambda:preview(r2,other_policy,inputs),"unknown or paid")
    file.unlink()
    file.symlink_to("/etc/passwd")
    denied(lambda:preview(r2,POLICY,inputs),"unsafe")
print("P3-B1 INDEPENDENT REAL DOCKER: approved binary read, hash, replay, revocation, TTL, "
      "concurrency, shell/paid/traversal/symlink denials: PASS")
