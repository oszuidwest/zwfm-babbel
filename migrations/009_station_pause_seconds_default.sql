-- Align the stations.pause_seconds column default with the API behavior:
-- the server inserts an explicit value on every create, and an omitted
-- pause_seconds in the request results in 0.
ALTER TABLE stations ALTER COLUMN pause_seconds SET DEFAULT 0;
