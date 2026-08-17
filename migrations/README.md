# Migrations

After a numbered migration has shipped on `main`, do not edit it; add a new numbered migration with the required `ALTER TABLE` or data changes instead.

Apply `009_bulletin_jobs.sql` once to existing databases before deploying a
Babbel version that serves asynchronous bulletin jobs. Fresh Docker Compose
databases load both the immutable `001` snapshot and migration `009`; `make
db-reset` does the same after dropping the job table.
