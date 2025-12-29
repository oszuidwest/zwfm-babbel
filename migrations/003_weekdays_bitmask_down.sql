-- Rollback Migration: Convert weekdays bitmask back to boolean columns
-- Use this to revert the weekdays bitmask migration if needed

-- Step 1: Add back the individual weekday columns
ALTER TABLE stories
    ADD COLUMN sunday BOOLEAN NOT NULL DEFAULT 1 AFTER weekdays,
    ADD COLUMN monday BOOLEAN NOT NULL DEFAULT 1 AFTER sunday,
    ADD COLUMN tuesday BOOLEAN NOT NULL DEFAULT 1 AFTER monday,
    ADD COLUMN wednesday BOOLEAN NOT NULL DEFAULT 1 AFTER tuesday,
    ADD COLUMN thursday BOOLEAN NOT NULL DEFAULT 1 AFTER wednesday,
    ADD COLUMN friday BOOLEAN NOT NULL DEFAULT 1 AFTER thursday,
    ADD COLUMN saturday BOOLEAN NOT NULL DEFAULT 1 AFTER friday;

-- Step 2: Restore data from bitmask to individual columns
UPDATE stories SET
    sunday = (weekdays & 1 > 0),
    monday = (weekdays & 2 > 0),
    tuesday = (weekdays & 4 > 0),
    wednesday = (weekdays & 8 > 0),
    thursday = (weekdays & 16 > 0),
    friday = (weekdays & 32 > 0),
    saturday = (weekdays & 64 > 0);

-- Step 3: Drop the weekdays column and its index
DROP INDEX idx_stories_weekdays ON stories;
ALTER TABLE stories DROP COLUMN weekdays;

-- Step 4: Recreate indexes on individual columns (if they existed before)
CREATE INDEX idx_stories_monday ON stories(monday);
CREATE INDEX idx_stories_tuesday ON stories(tuesday);
CREATE INDEX idx_stories_wednesday ON stories(wednesday);
CREATE INDEX idx_stories_thursday ON stories(thursday);
CREATE INDEX idx_stories_friday ON stories(friday);
CREATE INDEX idx_stories_saturday ON stories(saturday);
CREATE INDEX idx_stories_sunday ON stories(sunday);
