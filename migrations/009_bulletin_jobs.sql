-- Persist asynchronous bulletin-generation jobs for polling and restart recovery.
-- Delta for databases that predate this table; fresh databases already get it
-- from the 001 snapshot, so this is a no-op there.
CREATE TABLE IF NOT EXISTS bulletin_jobs (
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
    -- (station_id, status) serves the one-active-job-per-station claim guard
    -- and the station FK; (status) serves the queued/expired claim scan.
    INDEX idx_bulletin_jobs_station_status (station_id, status),
    INDEX idx_bulletin_jobs_status (status),
    INDEX idx_bulletin_jobs_bulletin (bulletin_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
