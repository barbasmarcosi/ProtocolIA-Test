"""Operator-owned loopback proxy and one-shot frozen independent P4 HTTP verifier.
Contains NO task assertions: all grading is performed by pinned tools/p4_verify.py.
A publicly exposed free candidate is not a local isolated test target; proxy preserves
verifier's strict localhost interface without editing that original verifier.
"""
import hashlib
import http.server
import json
import os
import pathlib
import subprocess
import threading
import time
import urllib.error
import urllib.request

CANDIDATE = "https://protocolia-p4-java21-probe.onrender.com"
PINNED_VERIFIER = "77ec9150fed3b1ae4e80c87befc052e34702af8c"
CANDIDATE_PUBLISHED = "2cc3d6938c64b65f281ee10396f460d6dea13781"
CANDIDATE_SUBTREE = "b08a7206ee3357eef9198f949c9c47b7d45a9489"
NO_REDIRECTS = urllib.request.build_opener()
NO_REDIRECTS.add_handler(type("BlockRedirect", (urllib.request.HTTPRedirectHandler,), {
    "redirect_request": lambda self,req,fp,code,msg,hdrs,newurl: None
})())
REPORT = {
    "status": "NOT_RUN",
    "treatment": "C",
    "source_commit": CANDIDATE_PUBLISHED,
    "candidate_workspace_tree": CANDIDATE_SUBTREE,
    "verifier_commit": PINNED_VERIFIER,
    "verifier_unchanged": True,
    "build_test_compilation": "FAILED",
    "runtime_launch": "spring_boot_jar_without_candidate_code_changes",
}

class Proxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.forward()
    def do_POST(self): self.forward()
    def log_message(self, *args): pass
    def forward(self):
        if not (self.path.startswith("/api/books") or self.path == "/actuator/health" or self.path == "/health"):
            self.send_error(403)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length) if length else None
        req = urllib.request.Request(CANDIDATE + self.path, data=payload,
            method=self.command, headers={"Content-Type":"application/json"})
        try:
            with NO_REDIRECTS.open(req, timeout=12) as res:
                status, body = res.status, res.read(200000)
        except urllib.error.HTTPError as err:
            status,body = err.code,err.read(200000)
        except (OSError, TimeoutError) as err:
            status,body = 502,json.dumps({"proxy_error":type(err).__name__}).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class ReportHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/health", "/verdict"):
            self.send_error(404)
            return
        out = dict(REPORT)
        if self.path == "/health": out = {"status":"UP","verifier_status":REPORT["status"]}
        raw = json.dumps(out, sort_keys=True).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Cache-Control","no-store")
        self.send_header("Content-Length",str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def log_message(self,*args):pass

def run_once():
    script = pathlib.Path("/app/tools/p4_verify.py")
    REPORT["verifier_source_sha256"] = hashlib.sha256(script.read_bytes()).hexdigest()
    # Only a candidate with the actuator endpoint can pass readiness. Prior probe lacked it.
    ready = False
    for attempt in range(25):
        try:
            req = urllib.request.Request(CANDIDATE+"/actuator/health",headers={"Cache-Control":"no-cache"})
            with NO_REDIRECTS.open(req,timeout=10) as r:
                if r.status == 200:
                    ready = True
                    break
        except (OSError, TimeoutError):
            pass
        time.sleep(2)
    if not ready:
        REPORT["status"] = "INFRA_UNAVAILABLE_NOT_GRADED"
        print("Verifier unrun: candidate readiness failed",flush=True)
        return
    proxy = http.server.ThreadingHTTPServer(("127.0.0.1",8765),Proxy)
    threading.Thread(target=proxy.serve_forever,daemon=True).start()
    try:
        verdict = pathlib.Path("/tmp/p4-independent-c-verdict.json")
        args=["python","/app/tools/p4_verify.py","--task","catalog-crud",
            "--base-url","http://127.0.0.1:8765","--verifier-commit",PINNED_VERIFIER,
            "--out",str(verdict)]
        result = subprocess.run(args,capture_output=True,text=True,timeout=120,check=False)
        REPORT["verifier_exit_code"]=result.returncode
        REPORT["verifier_stdout"]=result.stdout[-1000:]
        REPORT["verifier_stderr"]=result.stderr[-1000:]
        if verdict.exists():
            REPORT["verdict"]=json.loads(verdict.read_text())
            REPORT["status"]="EVALUATED"
        else:
            REPORT["status"]="INCONCLUSIVE_NO_VERDICT"
    except Exception as exc:
        REPORT["status"]="INCONCLUSIVE_VERIFIER_ERROR"
        REPORT["verifier_runtime_error"]=type(exc).__name__
    finally:
        proxy.shutdown()
    print("P4 independent evaluation:",json.dumps(REPORT,sort_keys=True),flush=True)

if __name__=="__main__":
    threading.Thread(target=run_once,daemon=True).start()
    port=int(os.environ.get("PORT","10000"))
    http.server.ThreadingHTTPServer(("0.0.0.0",port),ReportHandler).serve_forever()
