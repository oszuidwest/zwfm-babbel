-- Babbel's database session now runs in UTC, so DATETIME columns hold UTC.
-- Rows written before that hold local wall-clock time. Stop Babbel and run
-- this once, with the server's default time zone (the zone Babbel ran in),
-- so UNIX_TIMESTAMP reads the stored values as local time. Running it twice
-- shifts the values twice.
--
-- A local time in the repeated autumn hour converts to its first occurrence.
-- TIMESTAMP columns already store instants and are not touched; updated_at
-- is assigned explicitly so ON UPDATE CURRENT_TIMESTAMP does not fire. One
-- transaction keeps an interrupted run from converting only one table.
START TRANSACTION;

UPDATE bulletins
SET file_purged_at = DATE_ADD('1970-01-01', INTERVAL UNIX_TIMESTAMP(file_purged_at) SECOND)
WHERE file_purged_at IS NOT NULL;

UPDATE bulletin_jobs
SET started_at   = DATE_ADD('1970-01-01', INTERVAL UNIX_TIMESTAMP(started_at) SECOND),
    completed_at = DATE_ADD('1970-01-01', INTERVAL UNIX_TIMESTAMP(completed_at) SECOND),
    updated_at   = updated_at
WHERE started_at IS NOT NULL OR completed_at IS NOT NULL;

COMMIT;
