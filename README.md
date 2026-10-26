# bhandara

A file store for a group of applications that each run in several environments — production,
staging, development, and as many throwaway ones as you like — built around three things most
stores will not do:

- **Every environment reads production's files.** A staging or development copy of an application,
  loaded with a restore of production's data, can open every file that data points to, straight
  from production's store, without copying a byte. Writes stay in the caller's own environment, and
  nothing outside production can change or remove a production file.
- **A restore cleans up after itself.** When you wipe and reload a non-production environment, one
  call releases every file that environment was holding (`POST /v1/scopes/release`), and the next
  collection deletes whatever no one else still holds. No orphaned test uploads pile up. Production
  can never be released this way, by anyone.
- **The caller chooses the backend.** Whoever runs the service configures any number of
  S3-compatible backends; each upload names the one it goes to (`destination=`), or names its tenant
  and the service looks up that tenant's backend (`tenant=`). One tenant's files can live in its own
  bucket — or its own cloud — while the application code stays the same.

Underneath: identical bytes are stored once per backend however many applications hold them, a file
is deleted when nobody holds it any more, metadata lives in PostgreSQL, and every caller is
identified by a client certificate — there are no tokens.

This model suits whoever runs many environments of their own applications and trusts every one of
them with production's files. It is a poor fit where development must be kept away from production
data: see "Who may do what".

## Try it

    docker compose run --build --rm tests
    docker compose down -v

starts PostgreSQL, an S3 store (SeaweedFS), the service and nginx as the mTLS proxy with a throwaway
CA, then runs the unit tests and the end-to-end tests (`tests/e2e.py`) against it and exits with
their result. While it is up, the proxy answers on `https://127.0.0.1:8443`; the demo's certificates
are in the `certs` volume. The second line removes it all, certificates included.

## Words

- **identity** — `application@environment`, the subject CN of the caller's client certificate.
- **environment** — any non-empty name. `dev`, `development` and `local` are one environment;
  so are `stage`, `staging` and `stg`, and `prod` and `production`. The spelling a caller used is
  stored as it was sent.
- **blob** — one stored object: one row per `(sha1, bucket)`, with a `uuid` handle.
- **hold** — a claim on a blob by one `(application, environment)`. One live hold per blob per
  holder; the blob's reference count is its number of live holds.
- **scope** — all the holds of one `(application, environment)`.
- **backend** — an S3 bucket, named in configuration; `default` is the one set by `MINIO_*`.
- **operator** — the identity whose application is `STORAGE_OPERATOR_APP` (default `infra-ops`),
  in any environment.

## Who may do what

| | |
|---|---|
| read | every blob held in `production` (or `prod`), whoever holds it, plus your own scope |
| write | your own scope only |
| release a hold | your own holds only |
| release a whole scope | a non-production scope: your own, or any for the operator |
| collect (gc) | the operator only |

The first row is the point of the design, and it is also its boundary: a certificate for
`anything@dev` can list and download every production blob and its metadata, and see which scopes
hold a blob. Issue certificates only to applications you would trust with production's files, or
run a separate deployment per trust boundary.

## Blobs and holds

- The upload answers the blob's `uuid` and the `sha1` of the raw bytes; objects are stored
  zstd-compressed under `<sha1[:2]>/<sha1>`.
- Uploading bytes you already hold is a no-op: the response echoes your request, but the first
  upload's metadata (`system_object_id`, filename, content type, `meta`) is what is kept.
- Identical bytes are one blob per backend. **This makes the store a content oracle:** a caller who
  uploads known bytes gets the same `uuid` as an existing blob and can then read its `/holds`, which
  names every scope holding it. The by-sha1 reads answer a flat 404 for a blob outside your scope,
  but the upload path does not hide existence.
- An application counts its own internal references and releases its hold when the last one goes.
- `destination=<name>` chooses the backend at upload; later reads resolve it from the blob.
  `tenant=<key>` may be sent instead: the service fetches `STORAGE_TENANT_LOOKUP_URL` (a JSON
  `{"rows": [{"_key": "<tenant>", "storage_destination": "<backend>"}]}`, unauthenticated, on every
  such request, 5 s timeout) and uses that tenant's backend. Any caller may name any tenant; the
  tenant is written nowhere.
- Handles issued as a hold's own uuid (`files.uuid`) still resolve, as well as blob uuids.

## API

| | |
|---|---|
| `POST /v1/files` | upload: multipart `file`; optional `environment` (must be yours), `uploaded_by`, `system_object_id`, `meta` (JSON), `destination` or `tenant` |
| `GET /v1/files/{uuid}` | metadata of a blob you may read |
| `GET /v1/files/{uuid}/download` | its bytes |
| `GET /v1/files/{uuid}/holds` | `{live_holds, held, by_scope}` |
| `GET /v1/files/by-sha1/{sha1}` · `/download` | the same, by content; optional `destination` or `tenant`, `system_id`, `environment` |
| `GET /v1/files` | list what you may read: `system_id`, `environment`, `limit`, `offset` |
| `DELETE /v1/files/{uuid}` | release your hold; optional `actor` label for the audit log |
| `POST /v1/scopes/release?system_id=&environment=` | release every hold of a non-production scope (exact spelling); answers `{released}` |
| `POST /v1/gc` | collect blobs with no live hold, then their objects |
| `GET /health` | `{"status": "ok", "commit": ...}`; `commit` is `unknown` unless the service runs from a git checkout |

Errors: 401 no certificate, 400 malformed identity or missing parameter, 403 outside your scope or
a protected environment, 404 not found or not visible to you (indistinguishable on purpose), 422
unknown backend, unknown tenant, or both `destination` and `tenant`, 503 tenant lookup unset or
unreachable.

## Known limitations

- A handle that is not a uuid, or `meta` that is not JSON, answers 500 instead of 4xx.
- Two first uploads of the same bytes at the same moment: one answers 500.
- gc commits the database delete before removing the object; an upload of the same bytes in that
  window can lose its object, leaving a blob that answers 500 on download.
- Uploads and downloads are held whole in memory, and compression (zstd level 22) runs in the
  request; there is no size limit in the service — set one in the proxy.
- The audit log records the caller's `uploaded_by` label on upload, the blob's holder rather than
  the reader on download, and `system` for gc.
- `Content-Disposition` carries the stored filename unescaped.
- `limit` on `GET /v1/files` is not bounded.
- Dependencies are not pinned; tested with the versions `pip` installed on the day of the release.

## Running it

Python 3.12 (as the Dockerfile), PostgreSQL 13 or later, any S3-compatible store.

1. Create a database and a role that owns it, and load `schema.sql` into it as that role.
2. Create the bucket (and one per extra backend). The service never creates buckets.
3. Export the settings listed in `.env.example`; `STORAGE_DB_DSN`, `MINIO_ACCESS_KEY` and
   `MINIO_SECRET_KEY` are required.
4. `pip install -r requirements.txt`, then `uvicorn main:app --host 127.0.0.1 --port 8100`.
5. Put the mTLS proxy in front, as the only way in: `docs/identity-from-a-trusted-proxy.md`.
6. Run `POST /v1/gc` on a schedule with the operator's certificate.

The unit tests need no services: `pip install -r requirements.txt -r requirements-test.txt` and
`python -m unittest discover -s tests`. `docker build .` builds the service image.

## License

Apache-2.0; see `LICENSE` and `NOTICE`.
