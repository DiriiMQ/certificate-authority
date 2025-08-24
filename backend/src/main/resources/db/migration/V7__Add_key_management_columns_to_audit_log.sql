-- Migration: Add key management columns to audit_log table
-- Version: V7
-- Description: Add new columns needed for key management operations audit logging

-- Add new columns for key management operations
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS username VARCHAR(255);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS key_identifier VARCHAR(100);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS image_name VARCHAR(500);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS result_type VARCHAR(20);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS operation_type VARCHAR(30);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS details TEXT;
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS additional_metadata TEXT;

-- Add indexes for performance on new columns
CREATE INDEX IF NOT EXISTS idx_audit_log_username ON audit_log(username);
CREATE INDEX IF NOT EXISTS idx_audit_log_key_identifier ON audit_log(key_identifier);
CREATE INDEX IF NOT EXISTS idx_audit_log_result_type ON audit_log(result_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_operation_type ON audit_log(operation_type);

-- Add comments for documentation
COMMENT ON COLUMN audit_log.username IS 'Username of the user performing key management operations';
COMMENT ON COLUMN audit_log.key_identifier IS 'Identifier of the cryptographic key involved in the operation';
COMMENT ON COLUMN audit_log.image_name IS 'Name of the image file for image-related operations';
COMMENT ON COLUMN audit_log.result_type IS 'Result type enum value (SUCCESS, FAIL, FAILURE)';
COMMENT ON COLUMN audit_log.operation_type IS 'Operation type enum value (SIGN, VERIFY, KEY_GENERATION, KEY_ROTATION, etc.)';
COMMENT ON COLUMN audit_log.details IS 'Detailed information about the operation';
COMMENT ON COLUMN audit_log.additional_metadata IS 'Additional metadata in key-value format';
