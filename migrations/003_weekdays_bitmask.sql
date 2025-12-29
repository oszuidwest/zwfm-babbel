-- Migration: Convert weekday boolean columns to bitmask
-- This is a BREAKING CHANGE - API format changes from 7 booleans to 1 integer
-- This migration is idempotent - safe to run on fresh installs or existing databases

-- Check if old boolean columns exist (upgrade path) or if weekdays already exists (fresh install)
-- Uses MySQL prepared statements for conditional DDL

-- Only run if old 'sunday' column exists (indicates upgrade from old schema)
SET @has_old_schema = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'stories'
    AND COLUMN_NAME = 'sunday'
);

-- Step 1: Add new bitmask column (only if upgrading from old schema)
SET @add_weekdays = IF(@has_old_schema > 0,
    'ALTER TABLE stories ADD COLUMN weekdays TINYINT UNSIGNED NOT NULL DEFAULT 127 AFTER sunday',
    'SELECT ''weekdays column already exists (fresh install)'' as status'
);
PREPARE stmt FROM @add_weekdays;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Step 2: Migrate existing data - convert 7 booleans to bitmask (only if upgrading)
SET @migrate_data = IF(@has_old_schema > 0,
    'UPDATE stories SET weekdays =
        (CASE WHEN sunday = 1 THEN 1 ELSE 0 END) +
        (CASE WHEN monday = 1 THEN 2 ELSE 0 END) +
        (CASE WHEN tuesday = 1 THEN 4 ELSE 0 END) +
        (CASE WHEN wednesday = 1 THEN 8 ELSE 0 END) +
        (CASE WHEN thursday = 1 THEN 16 ELSE 0 END) +
        (CASE WHEN friday = 1 THEN 32 ELSE 0 END) +
        (CASE WHEN saturday = 1 THEN 64 ELSE 0 END)',
    'SELECT ''No data migration needed (fresh install)'' as status'
);
PREPARE stmt FROM @migrate_data;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Step 3: Drop old columns (only if they exist)
-- Each column dropped separately to avoid errors if some are already gone
SET @drop_monday = IF(@has_old_schema > 0,
    'ALTER TABLE stories DROP COLUMN monday',
    'SELECT ''monday column does not exist'' as status'
);
PREPARE stmt FROM @drop_monday;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_tuesday = IF(@has_old_schema > 0,
    'ALTER TABLE stories DROP COLUMN tuesday',
    'SELECT ''tuesday column does not exist'' as status'
);
PREPARE stmt FROM @drop_tuesday;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_wednesday = IF(@has_old_schema > 0,
    'ALTER TABLE stories DROP COLUMN wednesday',
    'SELECT ''wednesday column does not exist'' as status'
);
PREPARE stmt FROM @drop_wednesday;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_thursday = IF(@has_old_schema > 0,
    'ALTER TABLE stories DROP COLUMN thursday',
    'SELECT ''thursday column does not exist'' as status'
);
PREPARE stmt FROM @drop_thursday;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_friday = IF(@has_old_schema > 0,
    'ALTER TABLE stories DROP COLUMN friday',
    'SELECT ''friday column does not exist'' as status'
);
PREPARE stmt FROM @drop_friday;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_saturday = IF(@has_old_schema > 0,
    'ALTER TABLE stories DROP COLUMN saturday',
    'SELECT ''saturday column does not exist'' as status'
);
PREPARE stmt FROM @drop_saturday;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @drop_sunday = IF(@has_old_schema > 0,
    'ALTER TABLE stories DROP COLUMN sunday',
    'SELECT ''sunday column does not exist'' as status'
);
PREPARE stmt FROM @drop_sunday;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Step 4: Add index on weekdays column (only if it doesn't already exist)
SET @has_index = (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'stories'
    AND INDEX_NAME = 'idx_stories_weekdays'
);

SET @create_index = IF(@has_index = 0,
    'CREATE INDEX idx_stories_weekdays ON stories(weekdays)',
    'SELECT ''Index idx_stories_weekdays already exists'' as status'
);
PREPARE stmt FROM @create_index;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- Verification query (optional, run manually to verify migration):
-- SELECT id, title, weekdays,
--        BIN(weekdays) as binary_representation,
--        (weekdays & 1 > 0) as sunday,
--        (weekdays & 2 > 0) as monday,
--        (weekdays & 4 > 0) as tuesday,
--        (weekdays & 8 > 0) as wednesday,
--        (weekdays & 16 > 0) as thursday,
--        (weekdays & 32 > 0) as friday,
--        (weekdays & 64 > 0) as saturday
-- FROM stories LIMIT 10;
