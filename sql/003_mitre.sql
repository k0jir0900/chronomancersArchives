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

-- Add domain column to mitre_techniques if missing
SET @s = IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA=@db AND TABLE_NAME='mitre_techniques' AND COLUMN_NAME='domain') = 0,
    "ALTER TABLE mitre_techniques ADD COLUMN domain VARCHAR(20) NOT NULL DEFAULT 'enterprise'",
    'SELECT 1'
);
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Replace single-column unique on technique_id with composite (technique_id, domain)
SET @s = IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
     WHERE TABLE_SCHEMA=@db AND TABLE_NAME='mitre_techniques' AND INDEX_NAME='technique_id') > 0,
    'ALTER TABLE mitre_techniques DROP INDEX technique_id',
    'SELECT 1'
);
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @s = IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
     WHERE TABLE_SCHEMA=@db AND TABLE_NAME='mitre_techniques' AND INDEX_NAME='uniq_tech_domain') = 0,
    'ALTER TABLE mitre_techniques ADD UNIQUE KEY uniq_tech_domain (technique_id, domain)',
    'SELECT 1'
);
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Add domain column to mitre_sync if missing
SET @s = IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA=@db AND TABLE_NAME='mitre_sync' AND COLUMN_NAME='domain') = 0,
    "ALTER TABLE mitre_sync ADD COLUMN domain VARCHAR(20) NOT NULL DEFAULT 'enterprise'",
    'SELECT 1'
);
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;
