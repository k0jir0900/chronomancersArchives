-- Idempotent index migration for existing deployments.
-- Safe to run multiple times.

SET @db = DATABASE();

SET @s = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='archives' AND INDEX_NAME='idx_rule_name')=0,
    'CREATE INDEX idx_rule_name ON archives (rule_name)', 'SELECT 1');
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @s = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='archives' AND INDEX_NAME='idx_created_at')=0,
    'CREATE INDEX idx_created_at ON archives (created_at)', 'SELECT 1');
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @s = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='archives' AND INDEX_NAME='idx_tuning_driver')=0,
    'CREATE INDEX idx_tuning_driver ON archives (tuning_driver)', 'SELECT 1');
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @s = IF((SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='archives' AND INDEX_NAME='idx_action_type')=0,
    'CREATE INDEX idx_action_type ON archives (action_type)', 'SELECT 1');
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;
