-- Persistent history has no foreign keys or retention cleanup.
CREATE TABLE audit_events (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    occurred_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    actor_type  VARCHAR(20)  NOT NULL,
    user_id     BIGINT       NULL,
    entity_type VARCHAR(50)  NOT NULL,
    entity_id   BIGINT       NOT NULL,
    action      VARCHAR(50)  NOT NULL,
    changes     JSON         NULL,
    INDEX idx_audit_occurred (occurred_at, id),
    INDEX idx_audit_entity (entity_type, entity_id, occurred_at),
    INDEX idx_audit_user (user_id, occurred_at)
);
