-- =============================================================================
-- CTI - Event Queue / Watched-Event Routing Foundation
-- sql/migration_017_event_queue_engine.sql
--
-- Adds event-native scan tables so the backend can execute SpiderFoot-style
-- watched-event routing while still projecting into query_history for the
-- existing UI and correlation engine.
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_events (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id INT UNSIGNED NOT NULL,
    event_hash CHAR(64) NOT NULL,
    event_type VARCHAR(150) NOT NULL,
    event_data TEXT NOT NULL,
    module_slug VARCHAR(120) NOT NULL,
    source_event_hash CHAR(64) NOT NULL DEFAULT 'ROOT',
    source_data TEXT NULL,
    parent_event_hash CHAR(64) NULL,
    event_depth INT NOT NULL DEFAULT 0,
    confidence TINYINT UNSIGNED NOT NULL DEFAULT 0,
    risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
    visibility TINYINT UNSIGNED NOT NULL DEFAULT 100,
    false_positive TINYINT(1) NOT NULL DEFAULT 0,
    raw_payload_json JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_scan_events_scan_hash (scan_id, event_hash),
    KEY idx_scan_events_scan_type (scan_id, event_type),
    KEY idx_scan_events_scan_depth (scan_id, event_depth),
    KEY idx_scan_events_parent (scan_id, parent_event_hash),
    CONSTRAINT fk_scan_events_scan
        FOREIGN KEY (scan_id) REFERENCES scans(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS scan_event_queue (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id INT UNSIGNED NOT NULL,
    event_hash CHAR(64) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'queued',
    priority INT NOT NULL DEFAULT 100,
    attempt_count INT NOT NULL DEFAULT 0,
    last_error TEXT NULL,
    queued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP NULL DEFAULT NULL,
    finished_at TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_scan_event_queue_scan_hash (scan_id, event_hash),
    KEY idx_scan_event_queue_status (scan_id, status, priority, id),
    CONSTRAINT fk_scan_event_queue_scan
        FOREIGN KEY (scan_id) REFERENCES scans(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS scan_event_handlers (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id INT UNSIGNED NOT NULL,
    event_hash CHAR(64) NOT NULL,
    module_slug VARCHAR(120) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'processing',
    result_count INT NOT NULL DEFAULT 0,
    produced_count INT NOT NULL DEFAULT 0,
    query_history_ids_json JSON NULL,
    produced_event_hashes_json JSON NULL,
    error_message TEXT NULL,
    started_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_scan_event_handlers_scan_event_module (scan_id, event_hash, module_slug),
    KEY idx_scan_event_handlers_scan (scan_id, event_hash),
    KEY idx_scan_event_handlers_status (scan_id, status),
    CONSTRAINT fk_scan_event_handlers_scan
        FOREIGN KEY (scan_id) REFERENCES scans(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS scan_event_relationships (
    id INT UNSIGNED NOT NULL AUTO_INCREMENT,
    scan_id INT UNSIGNED NOT NULL,
    parent_event_hash CHAR(64) NOT NULL,
    child_event_hash CHAR(64) NOT NULL,
    module_slug VARCHAR(120) NOT NULL,
    relationship_type VARCHAR(40) NOT NULL DEFAULT 'discovered',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_scan_event_relationships_unique (scan_id, parent_event_hash, child_event_hash, module_slug, relationship_type),
    KEY idx_scan_event_relationships_parent (scan_id, parent_event_hash),
    KEY idx_scan_event_relationships_child (scan_id, child_event_hash),
    CONSTRAINT fk_scan_event_relationships_scan
        FOREIGN KEY (scan_id) REFERENCES scans(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
