ALTER TABLE tts_settings
    DROP CONSTRAINT chk_tts_settings_similarity,
    DROP CONSTRAINT chk_tts_settings_style,
    DROP CONSTRAINT chk_tts_settings_speed,
    DROP COLUMN similarity_boost,
    DROP COLUMN style,
    DROP COLUMN speed;
