ALTER TABLE tts_settings
    ADD COLUMN model VARCHAR(64) NOT NULL DEFAULT 'eleven_v3',
    ADD COLUMN use_speaker_boost BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN pronunciation_dictionary_id VARCHAR(255) NULL,
    ADD CONSTRAINT chk_tts_settings_model CHECK (model IN (
        'eleven_v3',
        'eleven_multilingual_v2',
        'eleven_flash_v2_5'
    ));
