-- Complete schema for Babbel news bulletin system (MySQL)
-- This file consolidates all migrations into a single schema

-- Drop existing tables (in reverse dependency order)
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS bulletin_stories;
DROP TABLE IF EXISTS bulletins;
DROP TABLE IF EXISTS stories;
DROP TABLE IF EXISTS station_voices;
DROP TABLE IF EXISTS voices;
DROP TABLE IF EXISTS stations;
DROP TABLE IF EXISTS users;
SET FOREIGN_KEY_CHECKS = 1;

-- Create stations table
CREATE TABLE stations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    max_stories_per_block INT DEFAULT 5,
    pause_seconds DECIMAL(4,2) DEFAULT 2.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create voices table
CREATE TABLE voices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    elevenlabs_voice_id VARCHAR(255) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create stories table
CREATE TABLE stories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    text TEXT NOT NULL,
    voice_id INT NULL,
    audio_file VARCHAR(500) DEFAULT '',
    duration_seconds DECIMAL(8,2) DEFAULT 0,
    status VARCHAR(50) DEFAULT 'draft',
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    weekdays TINYINT UNSIGNED NOT NULL DEFAULT 127,  -- Bitmask: Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64
    metadata JSON,
    deleted_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (voice_id) REFERENCES voices(id) ON DELETE SET NULL
);

-- Create bulletins table
CREATE TABLE bulletins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    station_id INT NOT NULL,
    filename VARCHAR(500) NOT NULL,
    audio_file VARCHAR(255) NOT NULL DEFAULT '',
    duration_seconds DECIMAL(8,2) DEFAULT 0,
    file_size BIGINT DEFAULT 0,
    story_count INT DEFAULT 0,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (station_id) REFERENCES stations(id),
    INDEX idx_station_created (station_id, created_at DESC)
);

-- Create bulletin_stories junction table
CREATE TABLE bulletin_stories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    bulletin_id INT NOT NULL,
    story_id INT NOT NULL,
    story_order INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (bulletin_id) REFERENCES bulletins(id) ON DELETE CASCADE,
    FOREIGN KEY (story_id) REFERENCES stories(id) ON DELETE CASCADE,
    UNIQUE KEY unique_bulletin_story (bulletin_id, story_id),
    INDEX idx_bulletin_stories_bulletin_id (bulletin_id),
    INDEX idx_bulletin_stories_story_id (story_id)
);

-- Create users table with complete schema
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    role VARCHAR(50) DEFAULT 'editor',
    suspended_at TIMESTAMP NULL,
    deleted_at TIMESTAMP NULL,
    last_login_at TIMESTAMP NULL,
    login_count INT DEFAULT 0,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create user_sessions table
CREATE TABLE user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    user_agent VARCHAR(500),
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_sessions_token (token_hash),
    INDEX idx_sessions_expires (expires_at)
);

-- Add indexes for performance
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_suspended_at ON users(suspended_at);
CREATE INDEX idx_stories_voice_id ON stories(voice_id);
CREATE INDEX idx_stories_status ON stories(status);
CREATE INDEX idx_stories_dates ON stories(start_date, end_date);
CREATE INDEX idx_stories_weekdays ON stories(weekdays);

-- Insert default admin user (password: admin)
-- Password hash is for 'admin' with bcrypt default cost
INSERT INTO users (username, full_name, password_hash, email, role, password_changed_at) VALUES 
('admin', 'System Administrator', '$2a$10$9JLNLD7JuNuTyhsgFQlXNevfypkWJ8XLBtZcbHyJf6XB8.1DAw5gy', 'admin@babbel.local', 'admin', CURRENT_TIMESTAMP);

-- Create station_voices junction table for station-specific jingles
CREATE TABLE station_voices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    station_id INT NOT NULL,
    voice_id INT NOT NULL,
    audio_file VARCHAR(255) NOT NULL DEFAULT '',
    mix_point DECIMAL(5,2) DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (station_id) REFERENCES stations(id) ON DELETE CASCADE,
    FOREIGN KEY (voice_id) REFERENCES voices(id) ON DELETE CASCADE,
    UNIQUE KEY unique_station_voice (station_id, voice_id)
);

-- Add indexes for performance
CREATE INDEX idx_station_voices_station_id ON station_voices(station_id);
CREATE INDEX idx_station_voices_voice_id ON station_voices(voice_id);

