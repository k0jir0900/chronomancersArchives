-- Migration: severity column on archives
-- Safe to run multiple times.

SET @db = DATABASE();

SET @s = IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA=@db AND TABLE_NAME='archives' AND COLUMN_NAME='severity') = 0,
    'ALTER TABLE archives ADD COLUMN severity VARCHAR(20) DEFAULT NULL',
    'SELECT 1'
);
PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;
