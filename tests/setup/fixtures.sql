-- Babbel Test Fixtures
-- This file contains test data for running tests

-- Create test users with known passwords
-- Password for all test users is 'testpass123' (bcrypt hashed)
INSERT INTO users (username, full_name, password_hash, role, created_at, updated_at) VALUES
('admin', 'Administrator', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin', NOW(), NOW()),
('editor_user', 'Test Editor', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'editor', NOW(), NOW()),
('viewer_user', 'Test Viewer', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'viewer', NOW(), NOW()),
('suspended_user', 'Suspended User', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'editor', NOW(), NOW());

-- Update suspended user
UPDATE users SET deleted_at = NOW() WHERE username = 'suspended_user';

-- Create test stations
INSERT INTO stations (name, max_stories_per_block, pause_seconds, created_at, updated_at) VALUES
('Test Station FM', 5, 2.0, NOW(), NOW()),
('Radio Test', 4, 1.5, NOW(), NOW()),
('Demo Station', 3, 2.5, NOW(), NOW());

-- Create test voices
INSERT INTO voices (name, created_at, updated_at) VALUES
('Test Voice Male', NOW(), NOW()),
('Test Voice Female', NOW(), NOW()),
('Demo Announcer', NOW(), NOW());

-- Create station-voice relationships (without jingles for now)
INSERT INTO station_voices (station_id, voice_id, jingle_file, mix_point, created_at, updated_at) VALUES
(1, 1, '', 0, NOW(), NOW()),
(1, 2, '', 0, NOW(), NOW()),
(2, 1, '', 0, NOW(), NOW()),
(2, 3, '', 0, NOW(), NOW()),
(3, 2, '', 0, NOW(), NOW()),
(3, 3, '', 0, NOW(), NOW());

-- Create test stories
INSERT INTO stories (title, text, voice_id, monday, tuesday, wednesday, thursday, friday, saturday, sunday, start_date, end_date, status, created_at, updated_at) VALUES
('Breaking News Test', 'This is a test breaking news story for automated testing.', 1, true, true, true, true, true, true, true, '2024-01-01', '2025-12-31', 'active', NOW(), NOW()),
('Weather Update Test', 'Test weather update for the automated test suite.', 2, true, true, true, true, true, false, false, '2024-01-01', '2025-12-31', 'active', NOW(), NOW()),
('Traffic Report Test', 'This is a test traffic report story.', 1, true, false, true, false, true, false, false, '2024-01-01', '2025-12-31', 'active', NOW(), NOW()),
('Sports Update Test', 'Test sports update for verification purposes.', 3, false, false, false, false, false, true, true, '2024-01-01', '2025-12-31', 'active', NOW(), NOW()),
('Archived Story Test', 'This story should be archived/deleted for testing.', 2, true, true, true, true, true, true, true, '2024-01-01', '2025-12-31', 'expired', NOW(), NOW()),
('Future Story Test', 'This story is scheduled for future dates.', 1, true, true, true, true, true, true, true, '2030-01-01', '2030-12-31', 'draft', NOW(), NOW());

-- Archive one story for soft-delete testing
UPDATE stories SET deleted_at = NOW() WHERE title = 'Archived Story Test';