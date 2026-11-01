-- Removes the unreleased story create key added by 014; the index goes with the column.
ALTER TABLE stories DROP COLUMN idempotency_key;
