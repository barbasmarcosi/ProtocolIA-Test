"""Consumer-owned P4 CLI simulation; fake successful exit MUST be graded FAIL.

No Codex/Claude sessions, API credentials or generated-Java host execution.
Uses the REAL pinned downstream hidden-from-workspace judge on a closed port.
"""
from pathlib import Path
import json
import os
import socket
import sys
import tempfile
from unittest.mock import patch

from protocolia.p4_benchmark import create, lock, read, report, BenchmarkError
from protocolia.p4_local_runner import prepare, execute, FORBIDDEN_AUTH_ENV
from protocolia.p4_trial_finalize import finalize

upstream=Path(os.environ["P4_UPSTREAM"]).resolve()
fixtures=Path(os.environ["P4_FIXTURES"]).resolve()
study=read(upstream/"benchmarks/p4/studies/codex-pilot.json")
assert study["verification"]["commit"]=="77ec9150fed3b1ae4e80c87befc052e34702af8c"
assert study["tools"]["protocolia_commit"]
assert study["engines"]==["codex"]

with tempfile.TemporaryDirectory(prefix="p4-consumer-lab-") as tmp:
    base=Path(tmp)
    work=base/"work";work.mkdir()
    private=base/"private";private.mkdir(mode=0o700)
    results=base/"results";results.mkdir(mode=0o700)
    lock_file=private/"study.lock.json"
    frozen=lock(study)
    create(lock_file,frozen)
    assert len(frozen["assignments"])==36
    rid="codex-catalog-crud-r01-direct"
    prepared=prepare(lock_file,rid,fixtures,work,private)
    assert Path(prepared["workspace"]).is_dir()
    assert "TASK.json" in {p.name for p in Path(prepared["workspace"]).iterdir()}
    assert not (Path(prepared["workspace"])/"p4_verify.py").exists()

    fake=base/"fake-codex"
    fake.write_text(
        "#!"+sys.executable+"\n"
        "import sys\n"
        "if '--version' in sys.argv: print('codex-test-emulated-v1');sys.exit(0)\n"
        "assert sys.stdin.read()\n"
        "print('{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":22,"
        "\"output_tokens\":6,\"cached_input_tokens\":0}}')\n")
    fake.chmod(0o700)
    clean=os.environ.copy()
    for key in FORBIDDEN_AUTH_ENV:clean.pop(key,None)
    with patch.dict(os.environ,clean,clear=True),patch(
        "protocolia.p4_local_runner.shutil.which",return_value=str(fake)):
        run=execute(work,private,lock_file,rid,model="emulated-model-not-a-real-LLM",
                    timeout_seconds=10,allow_real_cli=True)
    assert run["exit_code"]==0 and not run["timed_out"]
    assert json.loads((private/rid/"run.json").read_text())["verifier_status"]=="NOT_RUN"

    # A closed port is a nonfunctional candidate. The trusted external HTTP
    # grader MUST produce a genuine failing verdict and 0 verified successes.
    listener=socket.socket()
    listener.bind(("127.0.0.1",0))
    port=listener.getsockname()[1]
    listener.close()
    outcome=finalize(lock_file,rid,work,private,results,fixtures,
                     base_url="http://127.0.0.1:"+str(port),
                     interventions=0,repairs=0)
    assert outcome["verified_success"] is False,outcome
    stored=read(results/(rid+".json"))
    assert stored["verified_success"] is False
    assert stored["usage"]["actual_subscription_usd"] is None
    assert stored["usage"]["observed_tokens"]["input_tokens"]==22
    with open(private/rid/"independent-verdict.json") as f:
        verdict=json.load(f)
    assert not verdict["tests_passed"] and not verdict["security_passed"]

    score=report(frozen,[stored])
    assert score["recorded"]==1 and score["scheduled"]==36 and not score["complete"]
    assert score["groups"]["codex:direct"]["verified_successes"]==0
    assert score["subscription_usd_per_success"] is None
    assert "no winner" in score["decision"].lower()

    try:
        prepare(lock_file,rid,fixtures,work,private)
    except BenchmarkError:pass
    else:raise AssertionError("reused trial ID unexpectedly allowed")

    tamper_id="codex-catalog-crud-r01-protocolia"
    prep=prepare(lock_file,tamper_id,fixtures,work,private)
    Path(prep["workspace"],"TASK.json").write_text('{"attacker":"overwrite"}')
    with patch.dict(os.environ,clean,clear=True),patch(
        "protocolia.p4_local_runner.shutil.which",return_value=str(fake)):
        try:
            execute(work,private,lock_file,tamper_id,
                    model="emulated-model-not-a-real-LLM",
                    timeout_seconds=10,allow_real_cli=True)
        except BenchmarkError as e:
            assert "frozen task or prompt" in str(e)
        else:raise AssertionError("tampered contract accepted")
print("INDEPENDENT P4 LOCAL CLI: PASS fake model exit != verified success, real external "
      "negative HTTP judge, immutable results and no USD claims; zero LLM sessions")
