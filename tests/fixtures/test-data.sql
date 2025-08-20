-- Babbel Test Fixtures
-- This file contains test data for running tests
-- Run this after the main schema to populate test data

-- Clear existing test data (optional, be careful in production!)
-- DELETE FROM bulletin_stories;
-- DELETE FROM bulletins;
-- DELETE FROM stories;
-- DELETE FROM station_voices;
-- DELETE FROM voices;
-- DELETE FROM stations;
-- DELETE FROM users WHERE username != 'admin';

-- Create test users with known passwords
-- Password for all test users is 'testpass123' (bcrypt hashed: $2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi)
INSERT IGNORE INTO users (username, full_name, password_hash, email, role, created_at, updated_at) VALUES
('editor_user', 'Test Editor', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'editor@test.local', 'editor', NOW(), NOW()),
('viewer_user', 'Test Viewer', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'viewer@test.local', 'viewer', NOW(), NOW()),
('suspended_user', 'Suspended User', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'suspended@test.local', 'editor', NOW(), NOW());

-- Mark suspended user as deleted
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
('Demo Announcer', NOW(), NOW()),
('Weekend Voice', NOW(), NOW()),
('Morning Voice', NOW(), NOW());

-- Create station-voice relationships (without jingles initially)
-- Get the actual IDs from the database
INSERT INTO station_voices (station_id, voice_id, jingle_file, mix_point, created_at, updated_at) 
SELECT s.id, v.id, '', 0, NOW(), NOW()
FROM stations s
CROSS JOIN voices v
WHERE s.name = 'Test Station FM' AND v.name IN ('Test Voice Male', 'Test Voice Female')
UNION ALL
SELECT s.id, v.id, '', 0, NOW(), NOW()
FROM stations s
CROSS JOIN voices v
WHERE s.name = 'Radio Test' AND v.name IN ('Test Voice Male', 'Demo Announcer')
UNION ALL
SELECT s.id, v.id, '', 0, NOW(), NOW()
FROM stations s
CROSS JOIN voices v
WHERE s.name = 'Demo Station' AND v.name IN ('Test Voice Female', 'Demo Announcer');

-- Create test stories with various configurations
INSERT INTO stories (title, text, voice_id, monday, tuesday, wednesday, thursday, friday, saturday, sunday, start_date, end_date, status, created_at, updated_at) 
SELECT 
    'Breaking News Test',
    'This is a test breaking news story for automated testing. It contains important information that should be broadcast across all days of the week.',
    v.id,
    true, true, true, true, true, true, true,
    '2024-01-01', '2025-12-31', 'active',
    NOW(), NOW()
FROM voices v WHERE v.name = 'Test Voice Male'
UNION ALL
SELECT 
    'Weather Update Test',
    'Test weather update for the automated test suite. Today will be partly cloudy with a chance of rain in the afternoon.',
    v.id,
    true, true, true, true, true, false, false,
    '2024-01-01', '2025-12-31', 'active',
    NOW(), NOW()
FROM voices v WHERE v.name = 'Test Voice Female'
UNION ALL
SELECT 
    'Traffic Report Test',
    'This is a test traffic report story. Heavy traffic on the main highway due to construction work.',
    v.id,
    true, false, true, false, true, false, false,
    '2024-01-01', '2025-12-31', 'active',
    NOW(), NOW()
FROM voices v WHERE v.name = 'Test Voice Male'
UNION ALL
SELECT 
    'Sports Update Test',
    'Test sports update for verification purposes. Local team wins championship game.',
    v.id,
    false, false, false, false, false, true, true,
    '2024-01-01', '2025-12-31', 'active',
    NOW(), NOW()
FROM voices v WHERE v.name = 'Demo Announcer'
UNION ALL
SELECT 
    'Morning News Test',
    'Good morning listeners, this is your morning news update test story.',
    v.id,
    true, true, true, true, true, false, false,
    '2024-01-01', '2025-12-31', 'active',
    NOW(), NOW()
FROM voices v WHERE v.name = 'Morning Voice'
UNION ALL
SELECT 
    'Weekend Special Test',
    'Special weekend programming test story for Saturday and Sunday broadcasts.',
    v.id,
    false, false, false, false, false, true, true,
    '2024-01-01', '2025-12-31', 'active',
    NOW(), NOW()
FROM voices v WHERE v.name = 'Weekend Voice'
UNION ALL
SELECT 
    'Archived Story Test',
    'This story should be archived/deleted for testing soft delete functionality.',
    v.id,
    true, true, true, true, true, true, true,
    '2024-01-01', '2025-12-31', 'expired',
    NOW(), NOW()
FROM voices v WHERE v.name = 'Test Voice Female'
UNION ALL
SELECT 
    'Future Story Test',
    'This story is scheduled for future dates and should not appear in current bulletins.',
    v.id,
    true, true, true, true, true, true, true,
    '2030-01-01', '2030-12-31', 'draft',
    NOW(), NOW()
FROM voices v WHERE v.name = 'Test Voice Male';

-- Mark one story as soft-deleted for testing
UPDATE stories SET deleted_at = NOW() WHERE title = 'Archived Story Test';

-- Create a few test bulletins for history testing
INSERT INTO bulletins (station_id, audio_file, created_at) 
SELECT s.id, CONCAT('test_bulletin_', s.id, '_', UNIX_TIMESTAMP(), '.wav'), NOW()
FROM stations s WHERE s.name = 'Test Station FM'
UNION ALL
SELECT s.id, CONCAT('test_bulletin_', s.id, '_', UNIX_TIMESTAMP(), '.wav'), DATE_SUB(NOW(), INTERVAL 1 DAY)
FROM stations s WHERE s.name = 'Test Station FM'
UNION ALL
SELECT s.id, CONCAT('test_bulletin_', s.id, '_', UNIX_TIMESTAMP(), '.wav'), DATE_SUB(NOW(), INTERVAL 2 DAY)
FROM stations s WHERE s.name = 'Radio Test';

-- Link some stories to bulletins for testing bulletin history
INSERT INTO bulletin_stories (bulletin_id, story_id, story_order)
SELECT b.id, s.id, 1
FROM bulletins b
CROSS JOIN stories s
WHERE s.title = 'Breaking News Test'
LIMIT 1;