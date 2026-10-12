ALTER TABLE stories
    ADD COLUMN idempotency_key VARCHAR(100) NULL AFTER metadata,
    ADD UNIQUE KEY idx_stories_idempotency_key (idempotency_key);
