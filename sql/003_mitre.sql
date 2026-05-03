-- Migration: Add MITRE ATT&CK support (existing deployments)
-- Safe to run multiple times.

SET @db = DATABASE();

-- Add mitre column to archives if missing
SET @s = IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA=@db AND TABLE_NAME='archives' AND COLUMN_NAME='mitre') = 0,
    'ALTER TABLE archives ADD COLUMN mitre JSON DEFAULT NULL',
    'SELECT 1'
);
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Create mitre_techniques table
CREATE TABLE IF NOT EXISTS mitre_techniques (
    id INT AUTO_INCREMENT PRIMARY KEY,
    technique_id VARCHAR(20) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    tactic VARCHAR(500) DEFAULT NULL,
    parent_id VARCHAR(20) DEFAULT NULL,
    INDEX idx_mitre_parent (parent_id)
);

-- Create mitre_sync table
CREATE TABLE IF NOT EXISTS mitre_sync (
    id INT AUTO_INCREMENT PRIMARY KEY,
    last_updated TIMESTAMP DEFAULT NULL
);
