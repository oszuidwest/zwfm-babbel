-- Migration to standardize audio file field naming and storage
-- This migration handles EXISTING INSTALLATIONS that may have old column names
-- Uses conditional logic to safely handle both old and new schema installations

-- Station-voices: Rename jingle_file to audio_file (only if jingle_file exists)
SET @sql = IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS 
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'station_voices' AND COLUMN_NAME = 'jingle_file') > 0,
    'ALTER TABLE station_voices CHANGE COLUMN jingle_file audio_file VARCHAR(255) NOT NULL DEFAULT ''''',
    'SELECT ''station_voices.jingle_file already renamed or does not exist'' as message'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Bulletins: Rename file_path to audio_file (only if file_path exists)  
SET @sql = IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS 
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'bulletins' AND COLUMN_NAME = 'file_path') > 0,
    'ALTER TABLE bulletins CHANGE COLUMN file_path audio_file VARCHAR(255) NOT NULL DEFAULT ''''',
    'SELECT ''bulletins.file_path already renamed or does not exist'' as message'
);
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Clean up any existing path data to store filenames only
-- This handles cases where full paths like 'audio/processed/story_4.wav' were stored
UPDATE stories SET audio_file = SUBSTRING_INDEX(audio_file, '/', -1) WHERE audio_file LIKE '%/%';
UPDATE station_voices SET audio_file = SUBSTRING_INDEX(audio_file, '/', -1) WHERE audio_file LIKE '%/%';
UPDATE bulletins SET audio_file = SUBSTRING_INDEX(audio_file, '/', -1) WHERE audio_file LIKE '%/%';

-- Stories already uses audio_file correctly, no schema changes needed