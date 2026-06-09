CREATE TABLE pronunciation_rules (
    id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    string_to_replace VARCHAR(255) NOT NULL,
    ipa               VARCHAR(255) NOT NULL,
    case_sensitive    TINYINT(1)   NOT NULL DEFAULT 1,
    word_boundaries   TINYINT(1)   NOT NULL DEFAULT 1,
    created_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_string_to_replace (string_to_replace)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_bin;
