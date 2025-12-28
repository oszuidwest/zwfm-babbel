-- Migration: Convert weekday boolean columns to bitmask
-- This is a BREAKING CHANGE - API format changes from 7 booleans to 1 integer

-- Step 1: Add new bitmask column with default value 127 (all days enabled)
ALTER TABLE stories ADD COLUMN weekdays TINYINT UNSIGNED NOT NULL DEFAULT 127 AFTER sunday;

-- Step 2: Migrate existing data - convert 7 booleans to bitmask
-- Bitmask values: Sunday=1, Monday=2, Tuesday=4, Wednesday=8, Thursday=16, Friday=32, Saturday=64
UPDATE stories SET weekdays =
    (CASE WHEN sunday = 1 THEN 1 ELSE 0 END) +
    (CASE WHEN monday = 1 THEN 2 ELSE 0 END) +
    (CASE WHEN tuesday = 1 THEN 4 ELSE 0 END) +
    (CASE WHEN wednesday = 1 THEN 8 ELSE 0 END) +
    (CASE WHEN thursday = 1 THEN 16 ELSE 0 END) +
    (CASE WHEN friday = 1 THEN 32 ELSE 0 END) +
    (CASE WHEN saturday = 1 THEN 64 ELSE 0 END);

-- Step 3: Drop old columns and their indexes
ALTER TABLE stories
    DROP COLUMN monday,
    DROP COLUMN tuesday,
    DROP COLUMN wednesday,
    DROP COLUMN thursday,
    DROP COLUMN friday,
    DROP COLUMN saturday,
    DROP COLUMN sunday;

-- Step 4: Add index on new column
CREATE INDEX idx_stories_weekdays ON stories(weekdays);

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
