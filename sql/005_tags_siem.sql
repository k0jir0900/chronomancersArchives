-- Migration: SIEM column + Tags pool
-- Safe to run multiple times.

SET @db = DATABASE();

-- Add siem column to archives if missing
SET @s = IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA=@db AND TABLE_NAME='archives' AND COLUMN_NAME='siem') = 0,
    'ALTER TABLE archives ADD COLUMN siem VARCHAR(50) DEFAULT NULL',
    'SELECT 1'
);
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Add tags column to archives if missing
SET @s = IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA=@db AND TABLE_NAME='archives' AND COLUMN_NAME='tags') = 0,
    'ALTER TABLE archives ADD COLUMN tags JSON DEFAULT NULL',
    'SELECT 1'
);
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Tags pool
CREATE TABLE IF NOT EXISTS tags_pool (
    id INT AUTO_INCREMENT PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    value VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_cat_value (category, value),
    INDEX idx_tag_category (category)
);

-- Seed base pool (idempotent)
INSERT IGNORE INTO tags_pool (category, value) VALUES
    ('baseline', 'gold'),
    ('baseline', 'silver'),
    ('baseline', 'bronze'),
    ('baseline', 'custom'),
    ('hardware_family', 'server'),
    ('hardware_family', 'workstation'),
    ('hardware_family', 'network_device'),
    ('hardware_family', 'mobile'),
    ('hardware_family', 'iot'),
    ('hardware_family', 'scada'),
    ('hardware_family', 'plc'),
    ('os_family', 'windows'),
    ('os_family', 'linux'),
    ('os_family', 'macos'),
    ('os_family', 'unix'),
    ('os_family', 'android'),
    ('os_family', 'ios'),
    ('os_family', 'embedded'),
    ('network_family', 'firewall'),
    ('network_family', 'router'),
    ('network_family', 'switch'),
    ('network_family', 'load_balancer'),
    ('network_family', 'proxy'),
    ('network_family', 'ids_ips'),
    ('application_family', 'web'),
    ('application_family', 'database'),
    ('application_family', 'email'),
    ('application_family', 'file_share'),
    ('application_family', 'identity'),
    ('application_family', 'virtualization'),
    ('application_family', 'container'),
    ('vendor', 'microsoft'),
    ('vendor', 'cisco'),
    ('vendor', 'palo_alto'),
    ('vendor', 'fortinet'),
    ('vendor', 'vmware'),
    ('vendor', 'redhat'),
    ('vendor', 'ubuntu'),
    ('vendor', 'debian'),
    ('vendor', 'oracle'),
    ('criticality', 'critical'),
    ('criticality', 'high'),
    ('criticality', 'medium'),
    ('criticality', 'low');
