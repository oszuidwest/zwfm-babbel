# Migrations

`001_complete_schema.sql` is the consolidated snapshot: it drops and recreates
every table and is the only migration fresh databases load (Docker Compose init
and `make db-reset`). When a new migration ships, fold its schema into `001` as
well, so the snapshot stays complete and re-applying it can never leave stale
tables behind.

`001` creates no users. A production install creates its first admin by hand,
as `QUICKSTART.md` describes. `docker-compose.yml` and `make db-reset` also load
`tests/fixtures/dev-admin.sql`, which adds the `admin` / `admin` login that
development and the tests use.

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
stories share a post, only the one with the highest `id` gets the ID, because the
index is unique; the others keep NULL. List those stories first and check that
the one with the highest `id` is the one to keep. A story created after this
check can still become the highest `id`, so run the migration right after it, or
pause story writes if that matters:

    SELECT MIN(JSON_VALUE(metadata, '$.wordpress_id')) AS post, GROUP_CONCAT(id ORDER BY id) AS stories,
           GROUP_CONCAT(deleted_at IS NOT NULL ORDER BY id) AS deleted
    FROM stories GROUP BY CAST(JSON_VALUE(metadata, '$.wordpress_id') AS BINARY)
    HAVING post IS NOT NULL AND COUNT(*) > 1;

Stories from a client that still sends only `metadata.wordpress_id` get no
`external_id`. Once all clients send it, run the `UPDATE` from `018` once more
for those stories, with `@wordpress_url` set as above: without it they get
the ID but no link, and a rerun does not add it. A post whose ID a story already
has is skipped: that story keeps the ID and its link, also when it is older or
soft-deleted. A story that already has another ID keeps it, and the highest `id`
without an ID gets the post's ID.

Apply `019_utf8mb4_tables.sql` once, after `013`, and after `017` on a database
that has `stories.idempotency_key`, to a database with latin1 or utf8mb3 tables.
Deploy a Babbel version with the OIDC email check from #548 first: under this
collation an older version links a look-alike email to an existing account. Babbel
can keep running, and each table blocks writes while it converts. Text
those tables cannot hold, such as emoji, fails with a 500 until then. Other
databases do not need it, and it does not change a database created from the
current `001` snapshot. This query lists the tables it is for:

    SELECT TABLE_NAME FROM information_schema.TABLES
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_COLLATION NOT LIKE 'utf8mb4%';

The user needs the `ALTER` privilege on the database. Check first that these
queries return nothing. They list names that become equal, such as `strasse` and
`straße`. The migration stops on such a row, on MariaDB with error 1834 about a
foreign key instead of a duplicate. Rename the row and run the migration again,
which is safe after a stop:

    SELECT GROUP_CONCAT(name) FROM stations
    GROUP BY CONVERT(name USING utf8mb4) COLLATE utf8mb4_unicode_ci HAVING COUNT(*) > 1;
    SELECT GROUP_CONCAT(username) FROM users
    GROUP BY CONVERT(username USING utf8mb4) COLLATE utf8mb4_unicode_ci HAVING COUNT(*) > 1;

Names and text now compare and sort under `utf8mb4_unicode_ci`: `ä` equals `a`
and `ü` equals `u`, where `latin1_swedish_ci` kept `ä` apart and made `ü` equal
`y`. Search and sort results can change slightly.

Stop Babbel, apply `020_refuse_delete_with_dependents.sql` once with
`mysql ... < 020_refuse_delete_with_dependents.sql`, then start it again; the order
against a deploy does not matter. Do not use `source` or `--force`: they carry on
after an error and leave that key out, so check for errors. Each foreign key is
briefly
absent, and a delete in that moment would leave a row the new key rejects. It
makes the foreign keys from `stories` and `station_voices` to `voices` and
`stations` refuse a delete. A second run changes nothing. It uses the generated
names `stories_ibfk_1`, `station_voices_ibfk_1` (station) and
`station_voices_ibfk_2` (voice), and stops with an error if a database named them
differently. If it stops on an `ADD CONSTRAINT`, that key is gone. The error does
not name the row, so these queries list the rows that point at nothing. Fix those,
then run the file again from that `ADD CONSTRAINT`, before you start Babbel.

    SELECT s.id FROM stories s LEFT JOIN voices v ON v.id = s.voice_id
    WHERE s.voice_id IS NOT NULL AND v.id IS NULL;
    SELECT sv.id FROM station_voices sv LEFT JOIN stations st ON st.id = sv.station_id
    WHERE st.id IS NULL;
    SELECT sv.id FROM station_voices sv LEFT JOIN voices v ON v.id = sv.voice_id
    WHERE v.id IS NULL;

Before you start Babbel, this query must show all three keys with `RESTRICT`:

    SELECT CONSTRAINT_NAME, DELETE_RULE FROM information_schema.REFERENTIAL_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE() AND TABLE_NAME IN ('stories', 'station_voices');
