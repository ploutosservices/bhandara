import hashlib
import json
import logging
import os
import re
import urllib.request
import uuid as _uuid
from typing import Optional

import boto3
import psycopg2
import psycopg2.extras
import zstandard
from botocore.config import Config
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response

DB_DSN    = os.environ["STORAGE_DB_DSN"]
MINIO_URL = os.environ.get("MINIO_URL", "http://localhost:9000")
MINIO_KEY = os.environ["MINIO_ACCESS_KEY"]
MINIO_SEC = os.environ["MINIO_SECRET_KEY"]
BUCKET    = os.environ.get("MINIO_BUCKET", "storage")
# Named upload destinations beyond the default backend above. JSON object:
#   {"<name>": {"endpoint_url": ..., "access_key": ..., "secret_key": ..., "bucket": ...}}
# "default" is implicit (the MINIO_* backend) and may not be redefined. Absent or empty means one
# backend.
BACKENDS_JSON = os.environ.get("STORAGE_BACKENDS_JSON", "{}")
# The tenant lookup: a URL answering {"rows": [{"_key": <tenant>, "storage_destination": <name>}]},
# read LIVE on every call that sends `tenant=`, never copied. Unset = this service cannot take
# `tenant=` and says so; `destination=` works either way.
TENANT_LOOKUP_URL = os.environ.get("STORAGE_TENANT_LOOKUP_URL", "")
# The header a trusted mTLS proxy sets from the verified client certificate's subject. The proxy
# must SET it from a verified chain and CLEAR it on every request without one; see
# docs/identity-from-a-trusted-proxy.md.
IDENTITY_HEADER = os.environ.get("STORAGE_IDENTITY_HEADER", "X-Client-Identity")
# Every caller presents a client certificate and the service reads WHO from its CN; there are no
# tokens. A token map would let anyone holding a token act as its system; a certificate's CN states
# the claim and its private key proves it, and the service holds neither. Adding a caller means
# issuing it a certificate; the CN is its entitlement; gc and scope release take the operator
# identity below.
# Environments a scope release may NEVER touch — structural, not by convention.
PROTECTED_ENVIRONMENTS = {"production", "prod"}

log = logging.getLogger("uvicorn.error")


class _RedactTokenFilter(logging.Filter):
    """Keep ``token=`` and ``tenant=`` query values out of uvicorn access-log lines."""
    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str) and "token=" in args[2]:
            args = list(args)
            args[2] = re.sub(r"token=[^&\s]+", "token=REDACTED", args[2])
            record.args = tuple(args)
        # The service never records a tenant, and a by-sha1 GET carries one in the query string.
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str) and "tenant=" in args[2]:
            args = list(args)
            args[2] = re.sub(r"(?<![A-Za-z_])tenant=[^&\s]*", "tenant=-", args[2])
            record.args = tuple(args)
        return True


logging.getLogger("uvicorn.access").addFilter(_RedactTokenFilter())

app = FastAPI(title="Storage Service")


def _running_commit() -> str:
    """The commit THIS PROCESS loaded, read once at import.

    A deploy that moves the checkout and does not restart leaves the service running old code while
    `git rev-parse HEAD` reads green. The process is the only witness that cannot be wrong about
    what is running. Read without the git binary, and never fatal: an unreadable checkout answers
    "unknown", which is a finding rather than a crash.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    git = os.path.join(here, ".git")
    try:
        with open(os.path.join(git, "HEAD")) as f:
            head = f.read().strip()
        if not head.startswith("ref: "):
            return head
        ref = head[5:]
        loose = os.path.join(git, ref)
        if os.path.exists(loose):
            with open(loose) as f:
                return f.read().strip()
        with open(os.path.join(git, "packed-refs")) as f:      # a packed ref is still a ref
            for line in f:
                if line.rstrip().endswith(" " + ref):
                    return line.split()[0]
        return "unknown"
    except OSError:
        return "unknown"


RUNNING_COMMIT = _running_commit()


def _s3_client(endpoint_url: str, access_key: str, secret_key: str):
    return boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


s3 = _s3_client(MINIO_URL, MINIO_KEY, MINIO_SEC)  # default backend

# Backend registry. Upload resolves a *destination name* → (client, bucket); every other path
# resolves the blob's stored *bucket* → client. Bucket names must therefore be unique across
# backends — the bucket column is the blob's backend key in the DB (PK(sha1,bucket)), so two
# backends sharing a bucket name would be indistinguishable on read. Bad config refuses to start
# rather than mis-serve.
_BACKENDS: dict = {"default": (s3, BUCKET)}
_CLIENT_BY_BUCKET: dict = {BUCKET: s3}
for _name, _cfg in json.loads(BACKENDS_JSON).items():
    if _name == "default":
        raise RuntimeError("STORAGE_BACKENDS_JSON may not redefine 'default'")
    _bucket = _cfg["bucket"]
    if _bucket in _CLIENT_BY_BUCKET:
        raise RuntimeError(
            f"backend '{_name}': bucket '{_bucket}' is already served by another backend"
        )
    _client = _s3_client(_cfg["endpoint_url"], _cfg["access_key"], _cfg["secret_key"])
    _BACKENDS[_name] = (_client, _bucket)
    _CLIENT_BY_BUCKET[_bucket] = _client


def client_for_bucket(bucket: str):
    """S3 client serving ``bucket`` — the read-side inverse of the registry.

    Unknown bucket = a blob references a backend that was removed from config
    while its rows still exist; that is a config regression, surfaced loudly.
    """
    client = _CLIENT_BY_BUCKET.get(bucket)
    if client is None:
        raise HTTPException(
            status_code=500,
            detail=f"no configured backend serves bucket '{bucket}' — backend removed while blobs still reference it",
        )
    return client

_zstd = zstandard.ZstdCompressor(level=22)


def db():
    return psycopg2.connect(DB_DSN, cursor_factory=psycopg2.extras.RealDictCursor)


NO_CERTIFICATE = ("this service takes a client certificate, not a bearer token — present your "
                  "application's certificate and key to the service's mTLS proxy")


# ── Certificate identity ──────────────────────────────────────────────────────
#
# The mTLS proxy verifies a client certificate against the CA and hands the
# subject CN here in IDENTITY_HEADER, shaped ``application@environment``. The
# proxy SETS OR CLEARS the header on every proxied request, so it cannot arrive
# from a caller outside this box. A process already ON this box could forge it
# against the loopback listener — but such a process can read the service's
# configuration anyway, so the header widens nothing.
#
# THE MODEL, enforced here:
#     identity = (application, environment)
#     read     = production blobs (any application's) + your own (app, environment)
#     write    = your own (app, environment) only — no other target is expressible
#     wipe     = non-production only; your own scope (the operator: any non-prod scope)

# The proxy may hand the verified subject as an RFC2253 DN ("CN=app@env"); a bare
# "app@env" is accepted too so a proxy that extracts the CN needs no service change.
_IDENTITY_RE = re.compile(r"^(?:CN=)?([a-z][a-z0-9-]*)@([A-Za-z0-9._-]+)$")

# The operator's application name. Whoever holds a certificate with it, in any
# environment, may run gc and release any NON-PRODUCTION scope — and nothing else;
# releasing a production scope has no code path for ANY caller.
INFRA_OPERATOR_APP = os.environ.get("STORAGE_OPERATOR_APP", "infra-ops")


# Spellings of the same environment. Comparisons normalise through this table; a STORED
# environment is never rewritten, because it is part of the hold key and rewriting it would split a
# caller's old holds from its new ones.
_WORLDS = {"dev": "dev", "development": "dev", "local": "dev",
           "stage": "staging", "staging": "staging", "stg": "staging",
           "prod": "production", "production": "production"}


def _world(name: str) -> str:
    return _WORLDS.get((name or "").strip().lower(), (name or "").strip().lower())


def _world_aliases(name: str) -> list:
    """Every spelling that means the same world as ``name``, including ``name`` itself.

    Scope filters match every spelling, so a hold filed under `development` can be read and released
    by a caller whose certificate says `dev`, and the reverse.
    """
    w = _world(name)
    aliases = sorted({k for k, v in _WORLDS.items() if v == w} | {w, (name or "").strip()})
    return [a for a in aliases if a]



class Caller:
    """Who is asking, with the model's filters as SQL.

    ``read_where``/``own_where`` return ``(fragment, params)`` so every endpoint applies the model
    in its query rather than re-deriving it — a consumer that walks one rule by hand is silently
    partial.

    """

    def __init__(self, app="", env=""):
        self.kind = "identity"
        self.app = app
        self.env = env

    def read_where(self, col_sys="system_id", col_env="environment"):
        return (f"(({col_sys} = %s AND {col_env} = ANY(%s)) OR {col_env} = ANY(%s))",
                [self.app, _world_aliases(self.env), sorted(PROTECTED_ENVIRONMENTS)])

    def own_where(self, col_sys="system_id", col_env="environment"):
        return (f"({col_sys} = %s AND {col_env} = ANY(%s))", [self.app, _world_aliases(self.env)])


def caller_context(request: Request) -> Caller:
    """The certificate identity the mTLS proxy verified. There is no other way in.

    The proxy SETS this header from a verified chain and CLEARS it on every request that has none,
    so its presence is the proxy's statement and never the caller's. An absent header therefore
    means exactly one thing — no certificate was presented — and it is refused with the sentence
    that says what to bring.
    """
    ident = request.headers.get(IDENTITY_HEADER, "").strip()
    if not ident:
        raise HTTPException(status_code=401, detail=NO_CERTIFICATE)
    m = _IDENTITY_RE.match(ident)
    if not m:
        raise HTTPException(status_code=400,
                            detail=f"malformed client identity '{ident}' — expected application@environment")
    return Caller(app=m.group(1), env=m.group(2))


def sha1_of(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def _blob_for_handle(cur, handle: str):
    """Resolve a handle to its blob's ``(sha1, bucket)``.

    A handle is either the blob's ``content.uuid`` (the 1:1 handle returned by
    upload) or a legacy per-hold ``files.uuid`` (issued before reference
    counting). Both resolve to exactly one ``(sha1, bucket)`` — the specific
    backend copy the handle names. Returns ``(None, None)`` if unknown.

    Blobs are content-addressed **per backend**: the same bytes on two backends
    are two distinct ``content`` rows sharing a sha1, so a sha1 alone no longer
    identifies a blob — the bucket disambiguates.
    """
    cur.execute("SELECT sha1, bucket FROM content WHERE uuid = %s", (handle,))
    r = cur.fetchone()
    if r:
        return r["sha1"], r["bucket"]
    cur.execute("SELECT sha1, bucket FROM files WHERE uuid = %s", (handle,))
    r = cur.fetchone()
    return (r["sha1"], r["bucket"]) if r else (None, None)


def audit(cur, file_uuid, action: str, actor: str, detail: dict):
    cur.execute(
        "INSERT INTO audit_log (file_uuid, action, actor, detail) VALUES (%s, %s, %s, %s)",
        (str(file_uuid) if file_uuid else None, action, actor, json.dumps(detail)),
    )


def _require_environment(environment: str) -> str:
    """The environment a blob is filed under. Any non-empty name is accepted.

    There is no list of valid environments: they may be created and removed freely, and a fixed list
    would refuse the first new one. An empty name is refused, because ``environment`` is part of the
    hold key ``(sha1, bucket, system_id, environment)`` and an empty one makes a hold nobody can
    address or release.
    """
    name = (environment or "").strip()
    if not name:
        raise HTTPException(status_code=400,
                            detail="environment is required (any name; it is the section you are filing under)")
    return name


def _bucket_for_destination(destination: str) -> str:
    """The backend bucket the caller is addressing. The backend is the caller's
    responsibility: it names one via ``destination``, or gets the default
    backend when it names none. by-sha1 resolves ONLY on this backend, so a caller
    can never receive a blob that lives on a different backend. Unknown name → 422.
    """
    dest = destination or "default"
    if dest not in _BACKENDS:
        raise HTTPException(status_code=422, detail=f"unknown destination '{dest}'")
    return _BACKENDS[dest][1]


def _destination_for_tenant(tenant: str) -> str:
    """The destination the tenant lookup answers for ``tenant``.

    The tenant is used to CHOOSE and then dropped: the caller gets back only a destination name,
    and nothing here writes the tenant anywhere (a file may be shared among tenants). A row with no
    ``storage_destination`` means ``default``. Every failure REFUSES: a lookup that cannot be read
    must never quietly become the default backend, because a by-sha1 read on the wrong backend
    answers "absent" for a blob that is not.
    """
    if not TENANT_LOOKUP_URL:
        raise HTTPException(status_code=503, detail=(
            "tenant= needs the tenant lookup and STORAGE_TENANT_LOOKUP_URL is not set; "
            "send destination=<name> instead"))
    try:
        with urllib.request.urlopen(TENANT_LOOKUP_URL, timeout=5) as r:
            rows = json.load(r)["rows"]
    except Exception as e:  # unreachable, non-200, not the lookup's shape
        raise HTTPException(status_code=503, detail=(
            f"the tenant lookup could not be read ({type(e).__name__}); refusing rather than "
            "guessing the default destination"))
    row = next((r for r in rows if isinstance(r, dict) and r.get("_key") == tenant), None)
    if row is None:
        raise HTTPException(status_code=422, detail=f"unknown tenant '{tenant}': the tenant lookup has no such tenant")
    return row.get("storage_destination") or "default"


def _resolve_destination(destination: str, tenant: str) -> str:
    """``destination=`` or ``tenant=``, never both: both → 422."""
    if destination and tenant:
        raise HTTPException(status_code=422, detail="send destination or tenant, not both")
    return _destination_for_tenant(tenant) if tenant else destination


def _blob_download_response(conn, *, audit_key, bucket, object_key, compression,
                            original_filename, content_type, system_id, detail=None):
    """Fetch bytes for a resolved ``(bucket, object_key)``, decompress if needed,
    audit the download, and return them as an attachment. Shared by the uuid and
    by-sha1 download paths so byte-serving lives in exactly one place."""
    obj = client_for_bucket(bucket).get_object(Bucket=bucket, Key=object_key)
    data = obj["Body"].read()
    if compression == "zstd":
        data = zstandard.ZstdDecompressor().decompress(data)
    with conn.cursor() as cur:
        audit(cur, audit_key, "download", system_id or "system", detail or {})
    conn.commit()
    filename = original_filename or "download"
    ctype = content_type or "application/octet-stream"
    return Response(
        content=data,
        media_type=ctype,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/v1/files")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    # There is no system_id field: the certificate says who the caller is. An extra form field is
    # ignored. `environment` is optional and must match the certificate's environment.
    environment: str = Form(""),
    uploaded_by: str = Form(""),
    system_object_id: str = Form(""),
    meta: str = Form("{}"),
    destination: str = Form(""),
    # In place of destination: the tenant whose destination the lookup answers. Used to choose
    # the backend, then dropped — not on the hold, its meta, or any log row.
    tenant: str = Form(""),
):
    caller = caller_context(request)
    system_id = caller.app
    environment = environment or caller.env
    environment = _require_environment(environment)
    # Write only into your own context: a production certificate may not write into staging by
    # naming it in a form field.
    if _world(environment) != _world(caller.env):
        raise HTTPException(status_code=403,
                            detail=f"identity {caller.app}@{caller.env} writes only its own "
                                   f"context; refusing ({system_id}, {environment})")
    # Optional named backend. Omitted/empty = default backend; the app owns WHEN to send a name,
    # the service owns the name → backend mapping. After upload the uuid is the only handle — the
    # backend is resolved from the blob's stored bucket, never re-passed.
    destination = _resolve_destination(destination, tenant)
    if destination and destination not in _BACKENDS:
        raise HTTPException(status_code=422, detail=f"unknown destination '{destination}'")
    s3c, bucket = _BACKENDS[destination or "default"]

    data = await file.read()
    sha1 = sha1_of(data)
    content_type = file.content_type or "application/octet-stream"
    original_filename = file.filename or "upload"
    size = len(data)
    meta_dict = json.loads(meta) if meta else {}

    conn = db()
    try:
        with conn.cursor() as cur:
            # Blob is content-addressed PER BACKEND — one row per (sha1, bucket),
            # with a 1:1 uuid handle. Dedup must not cross backends: identical
            # bytes on a different backend are a distinct object that must be
            # written there, not aliased to this one.
            cur.execute("SELECT uuid FROM content WHERE sha1 = %s AND bucket = %s", (sha1, bucket))
            crow = cur.fetchone()
            if crow:
                content_uuid = str(crow["uuid"])
            else:
                compressed = _zstd.compress(data)
                object_key = f"{sha1[:2]}/{sha1}"
                s3c.put_object(
                    Bucket=bucket,
                    Key=object_key,
                    Body=compressed,
                    ContentType=content_type,
                    ContentEncoding="zstd",
                )
                cur.execute(
                    "INSERT INTO content (sha1, bucket, object_key, size_bytes, compression)"
                    " VALUES (%s, %s, %s, %s, %s) RETURNING uuid",
                    (sha1, bucket, object_key, size, "zstd"),
                )
                content_uuid = str(cur.fetchone()["uuid"])

            # One live hold per (sha1, bucket, system_id, environment). A repeat upload by the
            # same holder is a no-op and keeps the first upload's metadata. The reference count
            # is the number of live holds; GC collects the blob when there are none.
            hold_uuid = str(_uuid.uuid4())
            cur.execute(
                """INSERT INTO files
                   (uuid, sha1, bucket, system_id, system_object_id, environment,
                    uploaded_by, original_filename, content_type, size_bytes, meta)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (sha1, bucket, system_id, environment) WHERE deleted_at IS NULL
                   DO NOTHING""",
                (hold_uuid, sha1, bucket, system_id, system_object_id or None, environment,
                 uploaded_by or None, original_filename,
                 content_type, size, json.dumps(meta_dict)),
            )
            audit(cur, content_uuid, "upload", uploaded_by or system_id,
                  {"sha1": sha1, "filename": original_filename, "size": size,
                   "system_id": system_id, "environment": environment, "hold": hold_uuid})

        conn.commit()
        return {
            "uuid": content_uuid,   # blob handle, 1:1 with (sha1, bucket)
            "sha1": sha1,
            "size_bytes": size,
            "system_id": system_id,
            "system_object_id": system_object_id,
            "environment": environment,
            "bucket": bucket,
            "original_filename": original_filename,
            "content_type": content_type,
        }
    finally:
        conn.close()


@app.get("/v1/files/by-sha1/{sha1}")
def get_file_by_sha1(request: Request, sha1: str, system_id: str = "",
                     environment: str = "", destination: str = "", tenant: str = ""):
    """Metadata for a blob addressed by its content sha1, scoped to the caller.

    The content-addressed twin of ``GET /v1/files/{uuid}``: a caller that
    already holds the sha1 (e.g. a CMS whose static resources are named by sha1)
    can fetch without tracking a per-upload uuid. ``sha1`` is the sha1 of the RAW,
    uncompressed bytes — exactly what upload hashes (``sha1_of``). Confined to the
    caller's own holds on the addressed backend; 404 if the caller holds no such
    blob there.

    The backend is the caller's responsibility: ``destination`` names one, or the
    default backend is used. Optional ``system_id`` / ``environment`` narrow the
    caller's own scope.
    """
    caller = caller_context(request)
    # tenant= in place of destination; the release path is this read then DELETE /v1/files/{uuid},
    # which resolves its backend from the blob and takes neither.
    destination = _resolve_destination(destination, tenant)
    bucket = _bucket_for_destination(destination)
    conn = db()
    try:
        with conn.cursor() as cur:
            # READ = production + own. Naming a system/environment only NARROWS within that
            # readable set — it cannot widen it.
            rw, rp = caller.read_where()
            where = f"sha1 = %s AND bucket = %s AND {rw} AND deleted_at IS NULL"
            params = [sha1, bucket, *rp]
            if system_id:
                where += " AND system_id = %s"
                params.append(system_id)
            if environment:
                where += " AND environment = ANY(%s)"
                params.append(_world_aliases(environment))
            cur.execute(
                f"SELECT * FROM files WHERE {where} ORDER BY created_at DESC LIMIT 1",
                params,
            )
            row = cur.fetchone()
        if not row:
            # The same 404 whether the blob is absent or outside the caller's scope: a sha1 is
            # guessable, and a different answer would confirm someone else's content. The body
            # echoes only the caller's own parameters, to help with a search on the wrong backend.
            raise HTTPException(status_code=404, detail={
                "error": "no blob with that sha1 is visible to you here",
                "searched": {
                    "bucket": bucket,
                    "destination": destination or "(default)",
                    "system_id": system_id or "(any you may read)",
                    "environment": environment or "(any you may read)",
                },
                "note": "This answer is the same whether the blob does not exist or exists "
                        "outside your scope — deliberately, since a sha1 is guessable and the "
                        "difference would confirm another tenant's content. Check the four "
                        "values above before concluding the blob is absent.",
            })
        return dict(row)
    finally:
        conn.close()


@app.get("/v1/files/by-sha1/{sha1}/download")
def download_file_by_sha1(request: Request, sha1: str, system_id: str = "",
                          environment: str = "", destination: str = "", tenant: str = ""):
    """Proxied, decompressed bytes for a blob addressed by content sha1.

    Same bytes and same guards as ``GET /v1/files/{uuid}/download``: served only
    while the caller holds a live hold, scoped to the caller's systems, 404
    otherwise. ``sha1`` = sha1 of the RAW uncompressed bytes. The backend is the
    caller's responsibility (``destination``, else default); bytes are never
    served from a backend the caller did not address.
    """
    caller = caller_context(request)
    # tenant= in place of destination; the release path is this read then DELETE /v1/files/{uuid},
    # which resolves its backend from the blob and takes neither.
    destination = _resolve_destination(destination, tenant)
    bucket = _bucket_for_destination(destination)
    conn = db()
    try:
        with conn.cursor() as cur:
            rw, rp = caller.read_where(col_sys="f.system_id", col_env="f.environment")
            join_scope = f"AND {rw}"
            params = list(rp)
            if system_id:
                join_scope += " AND f.system_id = %s"
                params.append(system_id)
            if environment:
                join_scope += " AND f.environment = ANY(%s)"
                params.append(_world_aliases(environment))
            cur.execute(
                f"""SELECT c.uuid AS content_uuid, c.object_key, c.compression,
                           f.original_filename, f.content_type, f.system_id
                    FROM content c
                    JOIN files f ON f.sha1 = c.sha1 AND f.bucket = c.bucket
                                 AND f.deleted_at IS NULL {join_scope}
                    WHERE c.sha1 = %s AND c.bucket = %s
                    ORDER BY f.created_at DESC LIMIT 1""",
                params + [sha1, bucket],
            )
            row = cur.fetchone()
        if not row:
            # As the by-sha1 read: the same 404 whether absent or out of scope.
            raise HTTPException(status_code=404, detail={
                "error": "no blob with that sha1 is downloadable by you here",
                "searched": {"bucket": bucket, "destination": destination or "(default)",
                             "system_id": system_id or "(any you may read)",
                             "environment": environment or "(any you may read)"},
                "note": "Same answer whether absent or out of your scope — a sha1 is guessable "
                        "and the difference would confirm another tenant's content.",
            })
        return _blob_download_response(
            conn, audit_key=str(row["content_uuid"]), bucket=bucket,
            object_key=row["object_key"], compression=row["compression"],
            original_filename=row["original_filename"], content_type=row["content_type"],
            system_id=row["system_id"], detail={"sha1": sha1, "by": "sha1"},
        )
    finally:
        conn.close()


@app.get("/v1/files/{file_uuid}")
def get_file(request: Request, file_uuid: str):
    caller = caller_context(request)
    conn = db()
    try:
        with conn.cursor() as cur:
            sha1, bucket = _blob_for_handle(cur, file_uuid)
            if not sha1:
                raise HTTPException(status_code=404, detail="Not found")
            # Representative live hold for this blob's metadata, restricted to what the caller may
            # READ (production + its own context). Outside that set the blob reads as 404 —
            # existence is not disclosed.
            rw, rp = caller.read_where()
            cur.execute(
                f"SELECT * FROM files WHERE sha1 = %s AND bucket = %s"
                f" AND {rw} AND deleted_at IS NULL"
                f" ORDER BY created_at DESC LIMIT 1",
                (sha1, bucket, *rp),
            )
            row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Not found")
        return dict(row)
    finally:
        conn.close()


@app.get("/v1/files/{file_uuid}/download")
def download_file(request: Request, file_uuid: str):
    caller = caller_context(request)
    conn = db()
    try:
        with conn.cursor() as cur:
            sha1, bucket = _blob_for_handle(cur, file_uuid)
            if not sha1:
                raise HTTPException(status_code=404, detail="Not found")
            # Serve only what the caller may READ (production plus its own (application,
            # environment)), and only while a live hold exists. Zero holds (or none in the
            # readable set) reads as gone.
            rw, rp = caller.read_where(col_sys="f.system_id", col_env="f.environment")
            cur.execute(
                f"""SELECT c.bucket, c.object_key, c.compression,
                          f.original_filename, f.content_type, f.system_id
                   FROM content c
                   JOIN files f ON f.sha1 = c.sha1 AND f.bucket = c.bucket AND f.deleted_at IS NULL
                                AND {rw}
                   WHERE c.sha1 = %s AND c.bucket = %s
                   ORDER BY f.created_at DESC LIMIT 1""",
                (*rp, sha1, bucket),
            )
            row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Not found")
        return _blob_download_response(
            conn, audit_key=file_uuid, bucket=row["bucket"],
            object_key=row["object_key"], compression=row["compression"],
            original_filename=row["original_filename"], content_type=row["content_type"],
            system_id=row["system_id"],
        )
    finally:
        conn.close()


@app.get("/v1/files")
def list_files(
    request: Request,
    system_id: str = "",
    environment: str = "",
    limit: int = 100,
    offset: int = 0,
):
    caller = caller_context(request)
    conn = db()
    try:
        filters = ["deleted_at IS NULL"]
        params = []
        # A listing never crosses what the caller may READ: production + its own, and an explicit
        # system_id only narrows within that set — it cannot widen it.
        rw, rp = caller.read_where()
        filters.append(rw)
        params.extend(rp)
        if system_id:
            filters.append("system_id = %s")
            params.append(system_id)
        if environment:
            filters.append("environment = ANY(%s)")
            params.append(_world_aliases(environment))
        where = " AND ".join(filters)
        params += [limit, offset]

        with conn.cursor() as cur:
            cur.execute(
                f"""SELECT uuid, sha1, bucket, system_id, system_object_id, environment,
                           uploaded_by, original_filename,
                           content_type, size_bytes, created_at, meta
                    FROM files WHERE {where}
                    ORDER BY created_at DESC LIMIT %s OFFSET %s""",
                params,
            )
            rows = cur.fetchall()
        return {"files": [dict(r) for r in rows], "limit": limit, "offset": offset}
    finally:
        conn.close()


@app.delete("/v1/files/{file_uuid}")
def delete_file(request: Request, file_uuid: str, actor: str = "",
                system_id: str = "", environment: str = ""):
    """Release one hold on a blob.

    Two forms:
      * legacy per-hold handle (``files.uuid``) → releases exactly that hold.
      * blob handle (``content.uuid``) → releases ONE live hold for the caller's
        ``(system_id, environment)`` scope (both required). refcount decrements;
        the blob is GC'd only when its holds reach zero.
    """
    caller = caller_context(request)
    # RELEASE = YOUR OWN CONTEXT ONLY: an identity's holds live in exactly one (application,
    # environment), so naming any other scope is a caller bug and is refused by name; an unnamed
    # scope is filled with its own.
    if (system_id and system_id != caller.app) or (environment and _world(environment) != _world(caller.env)):
        raise HTTPException(status_code=403,
                            detail=f"identity {caller.app}@{caller.env} releases only its own "
                                   f"holds; refusing ({system_id or '-'}, {environment or '-'})")
    # The caller's OWN spelling survives — overwriting it with the CN's would make the release look
    # in the wrong place. own_where matches every alias anyway.
    system_id = caller.app
    environment = environment or caller.env
    own_frag, own_params = caller.own_where()
    conn = db()
    try:
        with conn.cursor() as cur:
            # (1) legacy/specific: the handle is a hold's own uuid. Only the caller's OWN holds are
            # releasable this way — a caller cannot release another scope's hold by naming its uuid.
            cur.execute(
                f"UPDATE files SET deleted_at = NOW()"
                f" WHERE uuid = %s AND {own_frag} AND deleted_at IS NULL RETURNING uuid",
                (file_uuid, *own_params),
            )
            row = cur.fetchone()
            if not row:
                # (2) blob handle: release one hold for the caller's scope on the
                # backend copy this handle names.
                cur.execute("SELECT sha1, bucket FROM content WHERE uuid = %s", (file_uuid,))
                c = cur.fetchone()
                if not c:
                    raise HTTPException(status_code=404, detail="Not found")
                if system_id and environment:
                    # precise: release one hold in the caller's own scope. system_id IS the CN by
                    # the time it reaches this line, so there is no other scope left to name.
                    cur.execute(
                        """UPDATE files SET deleted_at = NOW()
                           WHERE uuid = (
                               SELECT uuid FROM files
                               WHERE sha1 = %s AND bucket = %s AND system_id = %s
                                 AND environment = ANY(%s)
                                 AND deleted_at IS NULL
                               ORDER BY created_at ASC LIMIT 1)
                           RETURNING uuid""",
                        # Any spelling of the environment (see _world_aliases).
                        (c["sha1"], c["bucket"], system_id, _world_aliases(environment)),
                    )
                else:
                    # Unreachable: every caller's scope is filled from its certificate above. If it
                    # is ever reached, refuse rather than guess which hold to release.
                    raise HTTPException(
                        status_code=500,
                        detail="unscoped release reached a door where every caller carries its own "
                               "scope — refusing rather than guessing which hold to drop",
                    )
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="no live hold to release")
            # The actor is the certificate's identity; the caller's optional `actor` label is kept
            # beside it, never in its place.
            audit(cur, file_uuid, "delete", f"{caller.app}@{caller.env}",
                  {"released_hold": str(row["uuid"]),
                   **({"caller_label": actor} if actor else {})})
        conn.commit()
        return {"deleted": file_uuid, "released_hold": str(row["uuid"])}
    finally:
        conn.close()


@app.post("/v1/scopes/release")
def release_scope(request: Request, system_id: str = "", environment: str = "", actor: str = ""):
    """Release EVERY live hold for a ``(system_id, environment)`` scope — platform op.

    For when an application's non-production data is wiped and reloaded: every hold
    that ``(system_id, environment)`` owned is moot, because the rows that referenced
    those blobs are gone. Clearing the scope in one call lets a following
    ``POST /v1/gc`` reclaim every blob nobody else holds. Both ``system_id`` and
    ``environment`` are required, as query parameters, and are matched exactly.

    ``environment=production`` is refused unconditionally (see PROTECTED_ENVIRONMENTS)
    — a scope release is a wipe, and THE WIPE VERB DOES NOT EXIST for production:
    there is no caller or identity for which this path reaches a production scope.

    Who may wipe: an identity wipes its OWN non-production scope; the operator
    identity wipes ANY non-production scope.

    Does not collect blobs — call ``POST /v1/gc`` afterwards to reclaim object-store space.
    """
    caller = caller_context(request)
    if caller.app != INFRA_OPERATOR_APP and (system_id != caller.app
                                             or _world(environment) != _world(caller.env)):
        raise HTTPException(status_code=403,
                            detail=f"identity {caller.app}@{caller.env} may release only its own "
                                   f"scope; refusing ({system_id or '-'}, {environment or '-'})")
    if not system_id or not environment:
        raise HTTPException(status_code=400,
                            detail="system_id and environment are both required")
    # A non-operator caller may only name itself (above); an unknown name releases zero rows and the
    # count says so.
    if environment.strip().lower() in PROTECTED_ENVIRONMENTS:
        raise HTTPException(status_code=403,
                            detail=f"refusing scope release on protected environment '{environment}'")
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE files SET deleted_at = NOW()
                   WHERE system_id = %s AND environment = %s AND deleted_at IS NULL""",
                # EXACT, not aliased, and deliberately unlike every other environment comparison
                # in this file. Releasing a scope destroys holds; matching more spellings than the
                # operator named would destroy more than they asked for. Everywhere else a wider
                # match only ever shows a caller its own files or lets it release its own hold —
                # here it would reach further, so the narrow rule wins and the operator names the
                # spelling that is filed.
                (system_id, environment),
            )
            released = cur.rowcount
            # The actor is the certificate's identity, never a caller-supplied string.
            audit(cur, None, "scope_release", f"{caller.app}@{caller.env}",
                  {"system_id": system_id, "environment": environment, "released": released,
                   **({"caller_label": actor} if actor else {})})
        conn.commit()
        # The log line names both the scope asked for and the identity that asked.
        log.info("scope_release: %s/%s released %d hold(s) caller=%s@%s",
                 system_id, environment, released, caller.app, caller.env)
        return {"released": released, "system_id": system_id, "environment": environment}
    finally:
        conn.close()


@app.post("/v1/gc")
def garbage_collect(request: Request):
    """Physically collect content blobs that no active file references.

    A content row is collectable when no non-deleted files row references its
    sha1. Soft-deleted (tombstone) files rows still hold a FK to content
    (files_sha1_bucket_fkey), so they must be removed together with the content row in
    the same transaction, or the content DELETE raises a ForeignKeyViolation.

    Each blob is collected in its own transaction: a single failure is logged
    and skipped, it never aborts the whole run.

    Platform-gated: collection is GLOBAL — it reclaims zero-hold blobs of EVERY
    system, so an application must not be able to trigger it (parallels
    /v1/scopes/release). Run it on a schedule with the operator certificate.
    """
    caller = caller_context(request)
    if caller.app != INFRA_OPERATOR_APP:
        raise HTTPException(status_code=403,
                            detail=f"gc is a platform operation; identity {caller.app}@{caller.env} is not the platform")
    conn = db()
    collected = []
    errors = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT c.sha1, c.bucket, c.object_key
                   FROM content c
                   WHERE NOT EXISTS (
                       SELECT 1 FROM files f
                       WHERE f.sha1 = c.sha1 AND f.bucket = c.bucket AND f.deleted_at IS NULL
                   )"""
            )
            orphans = cur.fetchall()

        for row in orphans:
            sha1 = row["sha1"]
            bucket = row["bucket"]
            try:
                with conn.cursor() as cur:
                    # Re-check under the transaction: an upload may have dedup'd
                    # a live reference onto this blob since the scan above.
                    cur.execute(
                        "SELECT 1 FROM files WHERE sha1 = %s AND bucket = %s AND deleted_at IS NULL LIMIT 1",
                        (sha1, bucket),
                    )
                    if cur.fetchone():
                        conn.rollback()
                        continue
                    # Drop the tombstone references first so the content DELETE
                    # does not violate files_sha1_bucket_fkey.
                    cur.execute(
                        "DELETE FROM files WHERE sha1 = %s AND bucket = %s AND deleted_at IS NOT NULL",
                        (sha1, bucket),
                    )
                    cur.execute("DELETE FROM content WHERE sha1 = %s AND bucket = %s", (sha1, bucket))
                    audit(cur, None, "gc", "system",
                          {"sha1": sha1, "bucket": bucket, "object_key": row["object_key"]})
                conn.commit()
            except Exception as e:
                conn.rollback()
                log.exception("gc: failed to collect sha1=%s: %s", sha1, e)
                errors.append(sha1)
                continue

            # DB is consistent now; remove the object best-effort. A leaked
            # object is harmless — no content row will ever re-reference it.
            try:
                client_for_bucket(row["bucket"]).delete_object(Bucket=row["bucket"], Key=row["object_key"])
            except Exception as e:
                log.warning("gc: object delete failed for sha1=%s key=%s: %s",
                            sha1, row["object_key"], e)

            collected.append(sha1)

        return {"collected": len(collected), "sha1s": collected, "errors": errors}
    finally:
        conn.close()


@app.get("/v1/files/{file_uuid}/holds")
def get_holds(request: Request, file_uuid: str):
    """Reference count for a blob — is anyone still holding it, who, and how many.

    Accepts a blob handle (``content.uuid``) or a legacy per-hold handle
    (``files.uuid``); both resolve to the same blob. Read-only.
    """
    caller = caller_context(request)
    conn = db()
    try:
        with conn.cursor() as cur:
            sha1, bucket = _blob_for_handle(cur, file_uuid)
            if not sha1:
                raise HTTPException(status_code=404, detail="Not found")
            # Only a caller who can READ the blob (production + own) may read its refcount;
            # otherwise the blob reads as 404. A readable caller then sees the FULL by-scope
            # breakdown (its decision to release depends on whether anyone else still holds it).
            rw, rp = caller.read_where()
            cur.execute(
                f"SELECT 1 FROM files WHERE sha1 = %s AND bucket = %s"
                f" AND {rw} AND deleted_at IS NULL LIMIT 1",
                (sha1, bucket, *rp),
            )
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="Not found")
            cur.execute(
                """SELECT system_id, environment, count(*) AS holds
                   FROM files
                   WHERE sha1 = %s AND bucket = %s AND deleted_at IS NULL
                   GROUP BY system_id, environment
                   ORDER BY holds DESC, system_id, environment""",
                (sha1, bucket),
            )
            by_scope = [dict(r) for r in cur.fetchall()]
        live = sum(r["holds"] for r in by_scope)
        return {
            "uuid": file_uuid,
            "sha1": sha1,
            "live_holds": live,
            "held": live > 0,
            "by_scope": by_scope,
        }
    finally:
        conn.close()


@app.get("/health")
def health():
    # `commit` is what the PROCESS loaded, not what the checkout holds — a deployer compares
    # against this, so "deployed" cannot mean "the tree moved".
    return {"status": "ok", "commit": RUNNING_COMMIT}
