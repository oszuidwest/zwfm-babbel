-- Add is_breaking column to stories for breaking news prioritization
-- Breaking stories are prioritized above fair rotation for selection in bulletins
ALTER TABLE stories ADD COLUMN is_breaking BOOLEAN NOT NULL DEFAULT FALSE AFTER weekdays;
CREATE INDEX idx_stories_is_breaking ON stories(is_breaking);
