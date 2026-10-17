# Migrations

`001_complete_schema.sql` is the consolidated snapshot: it drops and recreates
every table and is the only file fresh databases load (Docker Compose init and
`make db-reset`). When a new migration ships, fold its schema into `001` as
well, so the snapshot stays complete and re-applying it can never leave stale
tables behind.

Migrations `002` and up are deltas for existing databases. After a numbered
delta migration has shipped on `main`, do not edit it; add a new numbered
migration with the required `ALTER TABLE` or data changes instead.

Apply `009_bulletin_jobs.sql` once to existing databases before deploying a
Babbel version that serves asynchronous bulletin jobs. It uses `CREATE TABLE
IF NOT EXISTS`, so it is a no-op on databases created from the current `001`
snapshot.

Deploy Knabbel UI PR 65 first, then deploy the Babbel app, and finally apply
`010_drop_unsupported_eleven_v3_settings.sql`, which removes `similarity_boost`,
`style`, and `speed` after the app no longer reads them.

Apply `011_oidc_identity.sql` once, before deploying the issuer/subject-based
OIDC login, to databases that lack the `oidc_*` columns; it fails on databases
created from the current `001` snapshot. Do not run alongside instances that
identify OIDC users by email alone.
`docs/CROSS_SUBDOMAIN_AUTH.md` describes how existing accounts are linked.

Stop Babbel, apply `012_drop_bulletin_job_target_date.sql`, then deploy; it
fails on databases created from the current `001` snapshot. Queued jobs
generate for the local day the worker runs them.

Apply `013_audit_events.sql` before deploying persistent audit history. Audit
history is retained indefinitely; there are no foreign keys to users or entities
and no cleanup job.

Apply `014_story_idempotency_key.sql` once, before deploying a Babbel version
that accepts `idempotency_key` on `POST /stories`; without the column every
story create fails, also without a key. It fails on databases created from the
current `001` snapshot, which already has the column.

Stop Babbel, apply `015_utc_datetime_columns.sql` once, then deploy the Babbel
version whose database session runs in UTC. Run it with the server's default
time zone (`docker exec -i babbel-mysql mysql ... < 015_utc_datetime_columns.sql`
does), because it reads the stored local times in that zone. It converts
`bulletins.file_purged_at` and the bulletin job `started_at`/`completed_at`
from local time to UTC; running it twice shifts them twice. Do not apply it to
databases created from the current `001` snapshot.
