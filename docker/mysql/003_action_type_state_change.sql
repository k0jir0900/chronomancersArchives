-- Add 'state_change' to the archives.action_type ENUM.
-- Non-destructive: existing rows keep their values.
ALTER TABLE archives
    MODIFY action_type ENUM('creation', 'modification', 'state_change', 'elimination') NOT NULL;
