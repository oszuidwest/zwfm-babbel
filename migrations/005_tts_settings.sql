CREATE TABLE IF NOT EXISTS tts_settings (
    id                       INT             NOT NULL,
    model                    VARCHAR(64)     NOT NULL,
    stability                DECIMAL(3,2)    NOT NULL,
    similarity_boost         DECIMAL(3,2)    NOT NULL,
    style                    DECIMAL(3,2)    NOT NULL,
    use_speaker_boost        BOOLEAN         NOT NULL,
    speed                    DECIMAL(3,2)    NOT NULL,
    apply_text_normalization VARCHAR(8)      NOT NULL,
    seed                     BIGINT UNSIGNED NULL,
    tts_style_prefix         VARCHAR(500)    NOT NULL,
    updated_at               TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
                                             ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT chk_tts_settings_singleton          CHECK (id = 1),
    CONSTRAINT chk_tts_settings_stability          CHECK (stability        >= 0    AND stability        <= 1),
    CONSTRAINT chk_tts_settings_similarity         CHECK (similarity_boost >= 0    AND similarity_boost <= 1),
    CONSTRAINT chk_tts_settings_style              CHECK (style            >= 0    AND style            <= 1),
    CONSTRAINT chk_tts_settings_speed              CHECK (speed            >= 0.7  AND speed            <= 1.2),
    CONSTRAINT chk_tts_settings_text_normalization CHECK (apply_text_normalization IN ('auto', 'on', 'off')),
    CONSTRAINT chk_tts_settings_model              CHECK (model IN (
        'eleven_v3',
        'eleven_multilingual_v2',
        'eleven_flash_v2_5'
    ))
);

INSERT INTO tts_settings (
    id, model, stability, similarity_boost, style, use_speaker_boost,
    speed, apply_text_normalization, seed, tts_style_prefix
) VALUES (
    1, 'eleven_v3', 0.80, 0.80, 0.25, TRUE,
    1.00, 'auto', NULL, '[professional][news anchor][engaging]'
)
ON DUPLICATE KEY UPDATE id = id;
