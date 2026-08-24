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
