#!/usr/bin/env python3
"""End to end, through the mTLS proxy, against a real PostgreSQL and a real S3 store.

    python tests/e2e.py        (run by docker-compose.yml; reads E2E_URL, E2E_CERTS, E2E_S3_URL)

Each check prints PASS or FAIL with what it saw; exit 1 if any failed.
"""
import hashlib
import os
import ssl
import sys
import time

import boto3
import httpx

URL, CERTS = os.environ["E2E_URL"], os.environ["E2E_CERTS"]
failed = 0


def check(name, ok, seen=""):
    global failed
    failed += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({seen})" if seen else ""))


def as_(cn=None):
    ctx = ssl.create_default_context(cafile=f"{CERTS}/ca.pem")
    if cn:
        ctx.load_cert_chain(f"{CERTS}/{cn}.pem", f"{CERTS}/{cn}.key")
    return httpx.Client(base_url=URL, verify=ctx, timeout=10)


# The deployer creates the bucket; the service never does. The store may still be starting.
s3 = boto3.client("s3", endpoint_url=os.environ["E2E_S3_URL"],
                  aws_access_key_id=os.environ["MINIO_ACCESS_KEY"],
                  aws_secret_access_key=os.environ["MINIO_SECRET_KEY"], region_name="us-east-1")
for _ in range(60):
    try:
        if os.environ["MINIO_BUCKET"] not in [b["Name"] for b in s3.list_buckets().get("Buckets", [])]:
            s3.create_bucket(Bucket=os.environ["MINIO_BUCKET"])
        break
    except Exception:
        time.sleep(1)
else:
    sys.exit("FAIL  the S3 store never answered")

for _ in range(30):                       # the service and proxy start in parallel with this
    try:
        if as_().get("/health").status_code == 200:
            break
    except httpx.HTTPError:
        pass
    time.sleep(1)

demo, other, prod, op, anon = (as_("demo@dev"), as_("other@dev"), as_("demo@production"),
                               as_("infra-ops@dev"), as_())

r = anon.get("/v1/files")
check("no certificate is refused", r.status_code == 401, r.status_code)
r = anon.get("/v1/files", headers={"X-Client-Identity": "CN=demo@dev"})
check("a typed identity header without a certificate is cleared by the proxy", r.status_code == 401, r.status_code)

x = b"private bytes of demo@dev " + os.urandom(8)
r = demo.post("/v1/files", files={"file": ("x.txt", x, "text/plain")})
check("upload in your own context", r.status_code == 200, r.status_code)
up = r.json()
check("the sha1 is of the raw bytes", up.get("sha1") == hashlib.sha1(x).hexdigest())
r2 = demo.post("/v1/files", files={"file": ("x.txt", x, "text/plain")})
check("the same bytes again are the same blob", r2.json().get("uuid") == up["uuid"])
h = demo.get(f"/v1/files/{up['uuid']}/holds").json()
check("one player, one hold", h.get("live_holds") == 1, h.get("live_holds"))

r = demo.post("/v1/files", files={"file": ("x.txt", x)}, data={"environment": "staging"})
check("writing into another environment is refused", r.status_code == 403, r.status_code)

r = other.get(f"/v1/files/{up['uuid']}")
check("another application cannot read a non-production blob", r.status_code == 404, r.status_code)
r = other.get(f"/v1/files/by-sha1/{up['sha1']}")
check("nor find it by sha1", r.status_code == 404, r.status_code)

r = demo.get(f"/v1/files/by-sha1/{up['sha1']}/download")
check("download by sha1 returns the raw bytes", r.status_code == 200 and r.content == x, r.status_code)

y = b"published by production " + os.urandom(8)
py = prod.post("/v1/files", files={"file": ("y.txt", y)}).json()
r = other.get(f"/v1/files/{py['uuid']}/download")
check("production blobs are readable by every application", r.status_code == 200 and r.content == y, r.status_code)
r = other.post("/v1/files", files={"file": ("y.txt", y)})
h = other.get(f"/v1/files/{py['uuid']}/holds").json()
check("a second player holding the same bytes makes two holds", h.get("live_holds") == 2, h.get("live_holds"))

r = demo.post("/v1/gc")
check("gc is refused to an application", r.status_code == 403, r.status_code)
r = op.post("/v1/scopes/release", params={"system_id": "demo", "environment": "production"})
check("no identity can release a production scope", r.status_code == 403, r.status_code)

r = demo.delete(f"/v1/files/{up['uuid']}", params={"system_id": "demo", "environment": "dev"})
check("release your own hold", r.status_code == 200, r.status_code)
r = demo.get(f"/v1/files/{up['uuid']}/download")
check("with no hold left the blob reads as gone", r.status_code == 404, r.status_code)
r = op.post("/v1/gc")
g = r.json() if r.status_code == 200 else {}
check("the operator's gc collects it", r.status_code == 200 and up["sha1"] in g.get("sha1s", []), g.get("collected"))
key = f"{up['sha1'][:2]}/{up['sha1']}"
try:
    s3.head_object(Bucket=os.environ["MINIO_BUCKET"], Key=key)
    gone = False
except Exception:
    gone = True
check("and its object is removed from the store", gone)
check("a blob still held is not collected", py["sha1"] not in g.get("sha1s", []))

print(f"\n{'all passed' if not failed else f'{failed} failed'}")
sys.exit(1 if failed else 0)
