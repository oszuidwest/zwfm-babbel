-- Create global inline-IPA pronunciation rules table.
CREATE TABLE pronunciation_rules (
    string_to_replace VARCHAR(255) NOT NULL PRIMARY KEY,
    ipa               VARCHAR(255) NOT NULL,
    case_sensitive    TINYINT(1)   NOT NULL DEFAULT 1,
    word_boundaries   TINYINT(1)   NOT NULL DEFAULT 1,
    created_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_bin;
