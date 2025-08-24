-- V4__Add_audit_columns_to_audit_log.sql
-- Add Spring Data JPA auditing columns to audit_log table

-- Add the missing auditing columns to audit_log table (only if they don't exist)
ALTER TABLE audit_log 
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(100),
    ADD COLUMN IF NOT EXISTS updated_by VARCHAR(100),
    ADD COLUMN IF NOT EXISTS last_modified_date TIMESTAMP WITH TIME ZONE;

-- Create indexes for the new auditing columns (only if they don't exist)
CREATE INDEX IF NOT EXISTS idx_audit_log_created_by ON audit_log (created_by);
CREATE INDEX IF NOT EXISTS idx_audit_log_updated_by ON audit_log (updated_by);
CREATE INDEX IF NOT EXISTS idx_audit_log_last_modified_date ON audit_log (last_modified_date DESC);

-- Add comments for documentation
COMMENT ON COLUMN audit_log.created_by IS 'User who created this audit log entry';
COMMENT ON COLUMN audit_log.updated_by IS 'User who last modified this audit log entry';
COMMENT ON COLUMN audit_log.last_modified_date IS 'When this audit log entry was last modified';

-- Update the trigger to also update last_modified_date
CREATE OR REPLACE FUNCTION update_audit_log_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    NEW.last_modified_date = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
