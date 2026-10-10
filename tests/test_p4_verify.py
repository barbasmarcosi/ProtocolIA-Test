"""P4 independently held-out HTTP judge; fixtures never execute agents or paid calls."""
import json
from pathlib import Path
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from p4_verify import verify, TASKS

class Catalog(BaseHTTPRequestHandler):
    books={}
    def log_message(self,*args):pass
    def respond(self,code,value):
        data=json.dumps(value).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        if self.path!="/api/books":return self.respond(404,{})
        try:
            req=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))))
        except (ValueError,TypeError):
            return self.respond(400,{})
        if (type(req) is not dict or set(req)!={"isbn","title","stock"} or
            not isinstance(req["isbn"],str) or not req["isbn"].strip() or
            not isinstance(req["title"],str) or not req["title"].strip() or
            type(req["stock"]) is not int or req["stock"]<0):
            return self.respond(400,{})
        if req["isbn"] in self.books:return self.respond(409,{})
        self.books[req["isbn"]]=req.copy()
        self.respond(201,req)
    def do_GET(self):
        if not self.path.startswith("/api/books/"):return self.respond(404,{})
        key=self.path.removeprefix("/api/books/")
        if key not in self.books:return self.respond(404,{})
        self.respond(200,self.books[key])

class AlwaysOK(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_GET(self):self.reply()
    def do_POST(self):self.reply()
    def reply(self):
        body=b'{}'
        self.send_response(200)
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class HeldOutJudgeTests(unittest.TestCase):
    def serve(self,handler):
        server=ThreadingHTTPServer(("127.0.0.1",0),handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(lambda:(server.shutdown(),thread.join(3),server.server_close()))
        return "http://127.0.0.1:"+str(server.server_address[1])
    def test_independent_study_contains_four_distinct_task_strata(self):
        files=sorted((ROOT/"benchmarks/p4/tasks").glob("*.json"))
        self.assertEqual(len(files),4)
        seen=set()
        for path in files:
            task=json.loads(path.read_text())
            self.assertEqual(task["id"],path.stem)
            self.assertIn(task["id"],TASKS)
            self.assertGreaterEqual(len(task["requirements"]),4)
            self.assertNotIn(task["stratum"],seen)
            seen.add(task["stratum"])
    def test_real_positive_catalog_not_just_all_false(self):
        Catalog.books={}
        result=verify("catalog-crud",self.serve(Catalog),"test-verifier-commit")
        self.assertTrue(result["tests_passed"],result)
        self.assertTrue(result["security_passed"])
        self.assertEqual(len(result["evidence_sha256"]),64)
    def test_broken_backend_fails_every_task(self):
        base=self.serve(AlwaysOK)
        for task in TASKS:
            with self.subTest(task=task):
                result=verify(task,base,"test-verifier-commit")
                self.assertFalse(result["tests_passed"],result)
    def test_prod_urls_and_remote_hosts_rejected(self):
        for url in ("https://127.0.0.1:80","http://example.com",
                    "http://127.0.0.1:80/other","http://user:password@localhost:80"):
            with self.subTest(url=url),self.assertRaises(ValueError):
                verify("catalog-crud",url,"abc")

if __name__=="__main__":unittest.main()
