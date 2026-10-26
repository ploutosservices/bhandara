-- The schema this service reads and writes, for a new database. Idempotent: a re-run is a no-op.
--
--   content    one row per blob per backend: (sha1, bucket), with a 1:1 uuid handle
--   files      holds: one live row per (sha1, bucket, system_id, environment) — one per "player";
--              the reference count is the number of live holds; deleted_at marks a released hold
--   audit_log  every upload, download, delete, scope release and collection, with its actor

CREATE TABLE IF NOT EXISTS content (
    sha1         text        NOT NULL,
    bucket       text        NOT NULL,
    uuid         uuid        NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    object_key   text        NOT NULL,
    size_bytes   bigint      NOT NULL,
    compression  text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT content_pkey PRIMARY KEY (sha1, bucket)
);

CREATE TABLE IF NOT EXISTS files (
    uuid               uuid        PRIMARY KEY,
    sha1               text        NOT NULL,
    bucket             text        NOT NULL,
    system_id          text        NOT NULL,
    system_object_id   text,
    environment        text        NOT NULL,
    uploaded_by        text,
    original_filename  text,
    content_type       text,
    size_bytes         bigint,
    meta               jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at         timestamptz NOT NULL DEFAULT now(),
    deleted_at         timestamptz,
    CONSTRAINT files_sha1_bucket_fkey FOREIGN KEY (sha1, bucket) REFERENCES content (sha1, bucket)
);

-- One live hold per player; a repeat upload is ON CONFLICT ... DO NOTHING against this index.
CREATE UNIQUE INDEX IF NOT EXISTS files_player_key
    ON files (sha1, bucket, system_id, environment) WHERE deleted_at IS NULL;
-- The listing order of GET /v1/files.
CREATE INDEX IF NOT EXISTS files_active_idx ON files (created_at) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS files_scope_idx ON files (system_id, environment) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS audit_log (
    id          bigserial   PRIMARY KEY,
    file_uuid   uuid,
    action      text        NOT NULL,
    actor       text        NOT NULL,
    detail      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);
