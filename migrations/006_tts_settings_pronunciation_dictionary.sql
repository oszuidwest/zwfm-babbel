ALTER TABLE tts_settings
  ADD COLUMN pronunciation_dictionary_id VARCHAR(255) NULL
  COMMENT 'ElevenLabs ID of the lazily-created "Babbel" dictionary. NULL = no rules yet.';
