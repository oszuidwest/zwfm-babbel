-- Persist asynchronous bulletin-generation jobs for polling and restart recovery.
CREATE TABLE bulletin_jobs (
    id           BIGINT AUTO_INCREMENT PRIMARY KEY,
    station_id   INT NOT NULL,
    target_date  DATE NOT NULL,
    status       VARCHAR(20) NOT NULL DEFAULT 'queued',
    attempt      INT NOT NULL DEFAULT 0,
    bulletin_id  INT NULL,
    error_code   VARCHAR(100) NOT NULL DEFAULT '',
    error_detail VARCHAR(1000) NOT NULL DEFAULT '',
    lease_until  DATETIME(6) NULL,
    started_at   DATETIME NULL,
    completed_at DATETIME NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT chk_bulletin_jobs_status CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    CONSTRAINT fk_bulletin_jobs_station FOREIGN KEY (station_id) REFERENCES stations(id) ON DELETE CASCADE,
    CONSTRAINT fk_bulletin_jobs_bulletin FOREIGN KEY (bulletin_id) REFERENCES bulletins(id) ON DELETE SET NULL,
    INDEX idx_bulletin_jobs_status_created (status, created_at),
    INDEX idx_bulletin_jobs_lease_until (lease_until),
    INDEX idx_bulletin_jobs_station (station_id),
    INDEX idx_bulletin_jobs_bulletin (bulletin_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
