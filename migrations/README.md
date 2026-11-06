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

Skip `014_story_idempotency_key.sql`: no release used it, it fails on MariaDB,
and `017_drop_story_idempotency_key.sql` removes its column again. Apply `017`
only to databases that have `stories.idempotency_key`, from `014` or from an
earlier `001` snapshot, after deploying a Babbel version that no longer accepts
`idempotency_key`. It fails on databases without the column.

Stop Babbel, apply `015_utc_datetime_columns.sql` once, then deploy the Babbel
version whose database session runs in UTC. Run it with the server's default
time zone (`docker exec -i babbel-mysql mysql ... < 015_utc_datetime_columns.sql`
does), because it reads the stored local times in that zone. It converts
`bulletins.file_purged_at` and the bulletin job `started_at`/`completed_at`
from local time to UTC; running it twice shifts them twice. It also succeeds
on databases created from the current `001` snapshot, where those columns
already hold UTC, so do not apply it there: it would shift them again.

Stop Babbel, apply `016_clear_moved_jingles.sql` once, remove the files it
lists, then start Babbel. Apply it only after deploying a Babbel version that
refuses pair changes on a station-voice with a jingle and jingle uploads whose
pair changed. It clears `audio_file` on rows that store a jingle named after a
pair they no longer have; bulletins never played those files. Its first result
lists the files no station-voice owns afterwards: save it, because a second
run lists nothing, and remove those files from the processed audio directory
by hand before Babbel starts again, since a running Babbel can recreate the
pair and upload a jingle under the same name. Running it again changes
nothing.

Apply `018_story_external_id.sql` once, before deploying the Babbel version that
stores `external_id` and `external_url`; Babbel can keep running. It fails on
databases created from the current `001` snapshot, and on a second run. Set
`@wordpress_url` in the same session to the WordPress address (`wp option get
siteurl`), without a trailing slash, because the edit links are built from it.
If the value is missing, not http:// or https://, or ends in a slash, it stops
before changing anything, with an unknown column error that names this file:

    mysql --init-command="SET @wordpress_url='https://example.org'" ... < 018_story_external_id.sql

It copies `metadata.wordpress_id` to `external_id` and keeps `updated_at`. When
stories share a post, only the newest gets the ID, because the index is unique;
the others keep NULL. List those stories first and check that the newest is the
one to keep:

    SELECT MIN(JSON_VALUE(metadata, '$.wordpress_id')) AS post, GROUP_CONCAT(id ORDER BY id) AS stories,
           GROUP_CONCAT(deleted_at IS NOT NULL ORDER BY id) AS deleted
    FROM stories GROUP BY CAST(JSON_VALUE(metadata, '$.wordpress_id') AS BINARY)
    HAVING post IS NOT NULL AND COUNT(*) > 1;

Stories from a client that still sends only `metadata.wordpress_id` get no
`external_id`. Once all clients send it, run the `UPDATE` from `018` once more
for those stories, with `@wordpress_url` set as above: without it they get
the ID but no link, and a rerun does not add it. A post whose ID a story already
has is skipped: that story keeps the ID and its link, also when it is older or
soft-deleted.
