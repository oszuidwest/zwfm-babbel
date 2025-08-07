-- Migration: Add story_stations junction table for station-specific story inclusion
-- This allows stories to be targeted to specific stations rather than being available to all

-- Create story_stations junction table
CREATE TABLE story_stations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    story_id INT NOT NULL,
    station_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (story_id) REFERENCES stories(id) ON DELETE CASCADE,
    FOREIGN KEY (station_id) REFERENCES stations(id) ON DELETE CASCADE,
    UNIQUE KEY unique_story_station (story_id, station_id),
    INDEX idx_story_stations_story_id (story_id),
    INDEX idx_story_stations_station_id (station_id)
);

-- Insert default data: Make all existing stories available to all stations
-- This ensures backwards compatibility - existing stories remain available everywhere
INSERT INTO story_stations (story_id, station_id)
SELECT s.id, st.id
FROM stories s
CROSS JOIN stations st
WHERE s.deleted_at IS NULL;