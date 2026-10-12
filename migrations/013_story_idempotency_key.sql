ALTER TABLE stories
    ADD COLUMN idempotency_key VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_bin NULL AFTER metadata,
    ADD UNIQUE KEY idx_stories_idempotency_key (idempotency_key);
