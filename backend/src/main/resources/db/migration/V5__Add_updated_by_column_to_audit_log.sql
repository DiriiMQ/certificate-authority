-- V5__Add_updated_by_column_to_audit_log.sql
-- Add the missing updated_by column to audit_log table

-- Add the missing updated_by column (only if it doesn't exist)
ALTER TABLE audit_log 
    ADD COLUMN IF NOT EXISTS updated_by VARCHAR(100);

-- Create index for the new column (only if it doesn't exist)
CREATE INDEX IF NOT EXISTS idx_audit_log_updated_by ON audit_log (updated_by);

-- Add comment for documentation
COMMENT ON COLUMN audit_log.updated_by IS 'User who last modified this audit log entry';
