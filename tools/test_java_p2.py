"""Independent black-box test; uses only HTTP as a consumer."""
import base64
import json
import time
from uuid import uuid4
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError
from concurrent.futures import ThreadPoolExecutor

ROOT="http://localhost:8080"
ADMIN="Basic "+base64.b64encode(b"external-consumer:external-ephemeral-password-2026").decode()
VIEWER="Basic "+base64.b64encode(b"consumer-viewer:consumer-readonly-password-2026").decode()

def call(method,path,data=None,auth=ADMIN):
    headers={"Content-Type":"application/json"}
    if auth is not None:headers["Authorization"]=auth
    req=Request(ROOT+path,data=json.dumps(data).encode() if data is not None else None,headers=headers,method=method)
    try:
        with urlopen(req,timeout=20) as response:
            return response.status,json.loads(response.read())
    except HTTPError as e:
        return e.code,None

for _ in range(80):
    try:
        if call("GET","/health",auth=None)[0]==200:break
    except (URLError,OSError):pass
    time.sleep(1)
else:raise AssertionError("No generated Spring server became healthy")
assert call("GET","/health",auth=None)[0]==200
assert call("POST","/products",{"sku":"x","quantity":2},auth=None)[0]==401
assert call("POST","/products",{"sku":"x","quantity":2},auth=VIEWER)[0]==403
assert call("POST","/products",{"sku":"x","quantity":-1})[0]==400
assert call("POST","/products",{"sku":"x","quantity":2,"extraneous":"reject"})[0]==400
sku="ind-"+uuid4().hex[:12]
status,product=call("POST","/products",{"sku":sku,"quantity":1})
assert status==200,(status,product)
id=product["id"]
assert call("GET",f"/products/{id}/stock")[1]["stock"]==1
key1,key2=str(uuid4()),str(uuid4())
def purchase(k):return call("POST","/sales",{"product_id":id,"quantity":1,"idempotency_key":k})
with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(purchase,[key1,key2]))
assert sorted(x[0] for x in results)==[200,409],results
key=key1 if results[0][0]==200 else key2
successful=results[0][1] if results[0][0]==200 else results[1][1]
assert call("GET",f"/products/{id}/stock")[1]["stock"]==0
assert purchase(key)[1]["id"]==successful["id"]
assert call("POST","/sales",{"product_id":id,"quantity":0,"idempotency_key":str(uuid4())})[0]==400
print("INDEPENDENT CONSUMER P2: PASS HTTP, validation, auth, atomically bounded concurrent sales and idempotency")
