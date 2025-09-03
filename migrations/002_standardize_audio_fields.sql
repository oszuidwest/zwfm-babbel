-- Migration to standardize audio file field naming and storage
-- This migration renames audio file columns to use consistent 'audio_file' naming
-- and ensures only filenames (not full paths) are stored

-- Station-voices: Rename jingle_file to audio_file
ALTER TABLE station_voices CHANGE COLUMN jingle_file audio_file VARCHAR(255) NOT NULL;

-- Bulletins: Rename file_path to audio_file and extract just the filename
ALTER TABLE bulletins ADD COLUMN audio_file VARCHAR(255) NOT NULL DEFAULT '';

-- Update bulletins to store only filename (extract from file_path)
UPDATE bulletins SET audio_file = SUBSTRING_INDEX(file_path, '/', -1) WHERE file_path != '';

-- Drop old file_path column after data migration
ALTER TABLE bulletins DROP COLUMN file_path;

-- Stories already uses audio_file correctly, no changes needed