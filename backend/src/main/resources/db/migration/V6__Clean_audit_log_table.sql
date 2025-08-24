-- V6__Clean_audit_log_table.sql
-- Clean up audit_log table structure and remove inappropriate test data

-- Remove the inappropriate migration marker record
DELETE FROM audit_log 
WHERE image_hash = 'initial_migration_marker' 
  AND algorithm = 'migration' 
  AND user_id = 'system' 
  AND created_by = 'flyway';

-- Drop the redundant last_modified_date column that was added in V4
-- This column is not used by the JPA entity and causes confusion
ALTER TABLE audit_log DROP COLUMN IF EXISTS last_modified_date;

-- Drop the associated index for last_modified_date
DROP INDEX IF EXISTS idx_audit_log_last_modified_date;

-- Recreate the trigger function to only update updated_at column
-- This fixes the inconsistency where the trigger was updating both columns
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Ensure the trigger is correctly attached (recreate if needed)
DROP TRIGGER IF EXISTS update_audit_log_updated_at ON audit_log;
CREATE TRIGGER update_audit_log_updated_at 
    BEFORE UPDATE ON audit_log 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Add validation constraints to ensure data quality
-- Ensure image_hash is exactly 64 characters (SHA-256 hex)
ALTER TABLE audit_log 
    ADD CONSTRAINT chk_audit_log_image_hash_format 
    CHECK (LENGTH(image_hash) = 64 AND image_hash ~ '^[a-fA-F0-9]{64}$');

-- Ensure algorithm is one of the supported values
ALTER TABLE audit_log 
    ADD CONSTRAINT chk_audit_log_algorithm_valid 
    CHECK (algorithm IN ('Ed25519', 'ECDSA P-256', 'RSA-3072'));

-- Ensure signature_type is valid if provided
ALTER TABLE audit_log 
    ADD CONSTRAINT chk_audit_log_signature_type_valid 
    CHECK (signature_type IS NULL OR signature_type IN ('embedded', 'detached'));

-- Ensure image_size_bytes is positive if provided
ALTER TABLE audit_log 
    ADD CONSTRAINT chk_audit_log_image_size_positive 
    CHECK (image_size_bytes IS NULL OR image_size_bytes > 0);

-- Update table comment to reflect cleanup
COMMENT ON TABLE audit_log IS 'Audit trail for all image signing and verification operations (cleaned V6)';

-- Add constraint comments for documentation
COMMENT ON CONSTRAINT chk_audit_log_image_hash_format ON audit_log IS 'Ensures image_hash is a valid 64-character SHA-256 hex string';
COMMENT ON CONSTRAINT chk_audit_log_algorithm_valid ON audit_log IS 'Ensures algorithm is one of the supported cryptographic algorithms';
COMMENT ON CONSTRAINT chk_audit_log_signature_type_valid ON audit_log IS 'Ensures signature_type is either embedded or detached';
COMMENT ON CONSTRAINT chk_audit_log_image_size_positive ON audit_log IS 'Ensures image_size_bytes is positive when provided';

-- Migration completed successfully
SELECT 'V6__Clean_audit_log_table migration completed successfully' AS status;
