-- Add file_purged_at column to track when bulletin audio files are cleaned up
ALTER TABLE bulletins ADD COLUMN file_purged_at DATETIME NULL;
CREATE INDEX idx_bulletins_file_purged_at ON bulletins (file_purged_at);
