-- Migration: Fix ENUM types to support key management operations
-- Version: V8
-- Description: Properly extend operation_type and result_type ENUMs to support key management

-- Add new values to operation_type enum
ALTER TYPE operation_type ADD VALUE IF NOT EXISTS 'KEY_GENERATION';
ALTER TYPE operation_type ADD VALUE IF NOT EXISTS 'KEY_ROTATION';
ALTER TYPE operation_type ADD VALUE IF NOT EXISTS 'SIGN_IMAGE';
ALTER TYPE operation_type ADD VALUE IF NOT EXISTS 'VIEW_AUDIT_LOG';

-- Add new value to result_type enum  
ALTER TYPE result_type ADD VALUE IF NOT EXISTS 'FAILURE';

-- Add constraint checks for the new columns to ensure they use valid enum values
ALTER TABLE audit_log ADD CONSTRAINT chk_audit_log_operation_type_valid 
  CHECK (operation_type IS NULL OR operation_type IN ('SIGN', 'VERIFY', 'KEY_GENERATION', 'KEY_ROTATION', 'SIGN_IMAGE', 'VIEW_AUDIT_LOG'));

ALTER TABLE audit_log ADD CONSTRAINT chk_audit_log_result_type_valid 
  CHECK (result_type IS NULL OR result_type IN ('SUCCESS', 'FAIL', 'FAILURE'));

-- Add additional validation constraints
ALTER TABLE audit_log ADD CONSTRAINT chk_audit_log_algorithm_valid 
  CHECK (algorithm IN ('Ed25519', 'ECDSA P-256', 'RSA-3072'));

ALTER TABLE audit_log ADD CONSTRAINT chk_audit_log_image_hash_format 
  CHECK (LENGTH(image_hash) = 64 AND image_hash ~ '^[a-fA-F0-9]{64}$');

ALTER TABLE audit_log ADD CONSTRAINT chk_audit_log_signature_type_valid 
  CHECK (signature_type IS NULL OR signature_type IN ('embedded', 'detached'));

ALTER TABLE audit_log ADD CONSTRAINT chk_audit_log_image_size_positive 
  CHECK (image_size_bytes IS NULL OR image_size_bytes > 0);

-- Add comments for the updated enum values
COMMENT ON TYPE operation_type IS 'Types of operations: SIGN, VERIFY, KEY_GENERATION, KEY_ROTATION, SIGN_IMAGE, VIEW_AUDIT_LOG';
COMMENT ON TYPE result_type IS 'Result types: SUCCESS, FAIL, FAILURE';

-- Migration completed successfully
SELECT 'V8__Fix_enum_types_for_key_management migration completed successfully' AS status;