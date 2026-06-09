ALTER TABLE tts_settings DROP CONSTRAINT chk_tts_settings_model;
ALTER TABLE tts_settings DROP COLUMN model;
ALTER TABLE tts_settings DROP COLUMN pronunciation_dictionary_id;
ALTER TABLE tts_settings DROP COLUMN use_speaker_boost;
