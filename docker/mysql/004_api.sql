-- Migration: audit log
-- Safe to run multiple times.

CREATE TABLE IF NOT EXISTS api_audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    api_key_id INT NULL,
    ip_address VARCHAR(45),
    endpoint VARCHAR(255),
    params TEXT,
    status_code INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_created (created_at),
    INDEX idx_audit_user (user_id)
);
