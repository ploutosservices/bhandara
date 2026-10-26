#!/usr/bin/env python3
"""tenant= in place of destination=: the tenant chooses the backend and is written nowhere.

    python3 -m unittest discover -s tests        (needs requirements.txt + requirements-test.txt)

Drives the real routes through FastAPI's TestClient. The database and S3 are fakes that RECORD
everything handed to them, and the tenant lookup is a real HTTP server on loopback serving the
lookup's shape — so "the tenant is never written" is checked against every SQL parameter, every S3
call and the access-log line, not against what the code says it does.
"""
import http.server
import json
import logging
import os
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

# A tenant key no other value in a request could contain, so finding it anywhere is a write.
T_DEFAULT = "zq7-default-tenant"      # a lookup row with no storage_destination -> default
T_SECOND = "zq7-second-tenant"        # a lookup row naming the "second" backend
FEED = {"title": "Tenants", "columns": [{"key": "_key"}],
        "rows": [{"_key": T_DEFAULT, "what": "x", "names": []},
                 {"_key": T_SECOND, "what": "y", "names": [], "storage_destination": "second"}]}


class _Feed(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(FEED).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


_srv = http.server.HTTPServer(("127.0.0.1", 0), _Feed)
threading.Thread(target=_srv.serve_forever, daemon=True).start()
LOOKUP = f"http://127.0.0.1:{_srv.server_port}/tenants"

os.environ.update({
    "STORAGE_DB_DSN": "dbname=none", "MINIO_ACCESS_KEY": "k", "MINIO_SECRET_KEY": "s",
    "MINIO_BUCKET": "default-bucket", "STORAGE_TENANT_LOOKUP_URL": LOOKUP,
    "STORAGE_BACKENDS_JSON": json.dumps({"second": {"endpoint_url": "http://127.0.0.1:1",
                                                   "access_key": "a", "secret_key": "b",
                                                   "bucket": "second-bucket"}}),
})

import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

RECORD = []          # every (sql, params) and every S3 call, in order


class _Cur:
    def __init__(self):
        self._row = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        RECORD.append(("sql", sql, params))
        s = " ".join(sql.split())
        if s.startswith("INSERT INTO content"):
            self._row = {"uuid": "c0ffee00-0000-0000-0000-000000000001"}
        elif s.startswith("SELECT * FROM files"):
            self._row = {"uuid": "h1", "sha1": params[0], "bucket": params[1]}
        elif "FROM content c" in s:
            self._row = {"content_uuid": "c1", "object_key": "ab/x", "compression": None,
                         "original_filename": "f", "content_type": "text/plain", "system_id": "demo"}
        else:
            self._row = None

    def fetchone(self):
        return self._row


class _Conn:
    def cursor(self):
        return _Cur()

    def commit(self):
        pass

    def close(self):
        pass


class _S3:
    def __init__(self, name):
        self.name = name

    def put_object(self, **kw):
        RECORD.append(("s3put", self.name, kw))

    def get_object(self, **kw):
        RECORD.append(("s3get", self.name, kw))

        class _B:
            def read(self):
                return b"bytes"
        return {"Body": _B()}


main.db = lambda: _Conn()
main._BACKENDS = {"default": (_S3("default"), "default-bucket"),
                  "second": (_S3("second"), "second-bucket")}
main._CLIENT_BY_BUCKET = {"default-bucket": main._BACKENDS["default"][0],
                          "second-bucket": main._BACKENDS["second"][0]}

ID = {"X-Client-Identity": "CN=demo@dev"}
SHA = "a" * 40
client = TestClient(main.app)


def _written():
    """Everything the service handed to the database or to S3, as one string."""
    return json.dumps(RECORD, default=str)


class TenantDestination(unittest.TestCase):
    def setUp(self):
        RECORD.clear()
        main.TENANT_LOOKUP_URL = LOOKUP

    def _upload(self, **form):
        return client.post("/v1/files", headers=ID, files={"file": ("f.txt", b"hello")},
                           data={"meta": json.dumps({"k": "v"}), **form})

    def test_upload_tenant_without_destination_lands_on_default(self):
        r = self._upload(tenant=T_DEFAULT)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["bucket"], "default-bucket")
        self.assertNotIn(T_DEFAULT, _written())
        self.assertNotIn(T_DEFAULT, r.text)

    def test_upload_tenant_with_destination_lands_on_it(self):
        r = self._upload(tenant=T_SECOND)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["bucket"], "second-bucket")
        self.assertIn(("s3put", "second"), [(e[0], e[1]) for e in RECORD if e[0] == "s3put"])
        self.assertNotIn(T_SECOND, _written())

    def test_destination_alone_is_unchanged(self):
        r = self._upload(destination="second")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["bucket"], "second-bucket")

    def test_both_given_is_422_and_nothing_written(self):
        r = self._upload(tenant=T_SECOND, destination="second")
        self.assertEqual(r.status_code, 422)
        self.assertIn("not both", r.text)
        self.assertEqual(RECORD, [])

    def test_unknown_tenant_is_refused_by_name(self):
        r = self._upload(tenant="no-such-tenant")
        self.assertEqual(r.status_code, 422)
        self.assertIn("unknown tenant 'no-such-tenant'", r.text)
        self.assertEqual(RECORD, [])

    def test_lookup_unreachable_refuses_never_defaults(self):
        main.TENANT_LOOKUP_URL = "http://127.0.0.1:1/tenants"
        r = self._upload(tenant=T_DEFAULT)
        self.assertEqual(r.status_code, 503)
        self.assertIn("refusing rather than guessing", r.text)
        self.assertEqual(RECORD, [])

    def test_lookup_unset_refuses_by_name(self):
        main.TENANT_LOOKUP_URL = ""
        r = self._upload(tenant=T_DEFAULT)
        self.assertEqual(r.status_code, 503)
        self.assertIn("STORAGE_TENANT_LOOKUP_URL", r.text)
        self.assertEqual(RECORD, [])

    def test_by_sha1_read_resolves_through_the_tenant(self):
        r = client.get(f"/v1/files/by-sha1/{SHA}", headers=ID, params={"tenant": T_SECOND})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["bucket"], "second-bucket")
        self.assertNotIn(T_SECOND, _written())

    def test_by_sha1_read_both_given_is_422(self):
        r = client.get(f"/v1/files/by-sha1/{SHA}", headers=ID,
                       params={"tenant": T_SECOND, "destination": "second"})
        self.assertEqual(r.status_code, 422)

    def test_by_sha1_download_resolves_through_the_tenant(self):
        r = client.get(f"/v1/files/by-sha1/{SHA}/download", headers=ID, params={"tenant": T_SECOND})
        self.assertEqual(r.status_code, 200, r.text)
        gets = [e for e in RECORD if e[0] == "s3get"]
        self.assertEqual(gets[0][1], "second")
        self.assertEqual(gets[0][2]["Bucket"], "second-bucket")
        self.assertNotIn(T_SECOND, _written())

    def test_access_log_line_carries_no_tenant(self):
        rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
                                ("127.0.0.1", "GET", f"/v1/files/by-sha1/{SHA}?tenant={T_SECOND}&x=1",
                                 "1.1", 200), None)
        main._RedactTokenFilter().filter(rec)
        self.assertNotIn(T_SECOND, rec.getMessage())
        self.assertIn("tenant=-&x=1", rec.getMessage())


if __name__ == "__main__":
    unittest.main()
