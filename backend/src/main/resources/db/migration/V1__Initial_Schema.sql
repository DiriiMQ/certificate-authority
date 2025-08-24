-- V1__Initial_Schema.sql
-- Initial database schema for Certificate Authority
-- This migration creates the core audit_log table and supporting structures

-- Enable UUID extension for generating UUIDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create custom ENUM types for audit logging
CREATE TYPE operation_type AS ENUM ('SIGN', 'VERIFY');
CREATE TYPE result_type AS ENUM ('SUCCESS', 'FAIL');

-- Create audit_log table for tracking all sign/verify operations
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation operation_type NOT NULL,
    image_hash VARCHAR(64) NOT NULL, -- SHA-256 hash (64 hex characters)
    algorithm VARCHAR(50) NOT NULL,   -- Ed25519, ECDSA P-256, RSA-3072
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(255),            -- User identifier
    result result_type NOT NULL,
    
    -- Additional metadata for audit purposes
    image_filename VARCHAR(500),     -- Original filename
    image_size_bytes BIGINT,        -- File size in bytes
    signature_type VARCHAR(20),     -- 'embedded' or 'detached'
    error_message TEXT,             -- Error details for failed operations
    
    -- Audit trail metadata (managed by Spring Data JPA)
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),        -- User who created the record
    updated_by VARCHAR(100)         -- User who last updated the record
);

-- Create indexes for commonly queried columns (matching JPA @Index annotations)
CREATE INDEX idx_audit_log_timestamp ON audit_log (timestamp DESC);
CREATE INDEX idx_audit_log_user_id ON audit_log (user_id);
CREATE INDEX idx_audit_log_operation ON audit_log (operation);
CREATE INDEX idx_audit_log_result ON audit_log (result);
CREATE INDEX idx_audit_log_algorithm ON audit_log (algorithm);
CREATE INDEX idx_audit_log_image_hash ON audit_log (image_hash);

-- Create composite index for common query patterns
CREATE INDEX idx_audit_log_user_operation_time ON audit_log (user_id, operation, timestamp DESC);

-- Add table and column comments for documentation
COMMENT ON TABLE audit_log IS 'Audit trail for all image signing and verification operations';
COMMENT ON COLUMN audit_log.id IS 'Unique identifier for each audit log entry';
COMMENT ON COLUMN audit_log.operation IS 'Type of operation: SIGN or VERIFY';
COMMENT ON COLUMN audit_log.image_hash IS 'SHA-256 hash of the image content (hex encoded)';
COMMENT ON COLUMN audit_log.algorithm IS 'Cryptographic algorithm used: Ed25519, ECDSA P-256, or RSA-3072';
COMMENT ON COLUMN audit_log.timestamp IS 'UTC timestamp when operation occurred';
COMMENT ON COLUMN audit_log.user_id IS 'Identifier of user who performed the operation';
COMMENT ON COLUMN audit_log.result IS 'Result of the operation: SUCCESS or FAIL';
COMMENT ON COLUMN audit_log.image_filename IS 'Original filename of the processed image';
COMMENT ON COLUMN audit_log.image_size_bytes IS 'Size of the image file in bytes';
COMMENT ON COLUMN audit_log.signature_type IS 'Type of signature: embedded in metadata or detached file';
COMMENT ON COLUMN audit_log.error_message IS 'Detailed error message for failed operations';
COMMENT ON COLUMN audit_log.created_at IS 'Timestamp when record was created (managed by JPA auditing)';
COMMENT ON COLUMN audit_log.updated_at IS 'Timestamp when record was last updated (managed by JPA auditing)';
COMMENT ON COLUMN audit_log.created_by IS 'User who created the record (managed by JPA auditing)';
COMMENT ON COLUMN audit_log.updated_by IS 'User who last updated the record (managed by JPA auditing)';

-- Create a function to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update updated_at on row changes
CREATE TRIGGER update_audit_log_updated_at 
    BEFORE UPDATE ON audit_log 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Create a view for common audit queries and reporting
CREATE VIEW audit_log_summary AS
SELECT 
    operation,
    algorithm,
    result,
    DATE_TRUNC('day', timestamp) as date,
    COUNT(*) as operation_count,
    COUNT(CASE WHEN result = 'SUCCESS' THEN 1 END) as success_count,
    COUNT(CASE WHEN result = 'FAIL' THEN 1 END) as fail_count,
    AVG(image_size_bytes) as avg_image_size_bytes
FROM audit_log
GROUP BY operation, algorithm, result, DATE_TRUNC('day', timestamp)
ORDER BY date DESC, operation;

COMMENT ON VIEW audit_log_summary IS 'Summary view for audit log reporting and analytics';

-- Create a view for recent operations (last 30 days)
CREATE VIEW recent_audit_log AS
SELECT *
FROM audit_log
WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '30 days'
ORDER BY timestamp DESC;

COMMENT ON VIEW recent_audit_log IS 'View showing audit log entries from the last 30 days';

-- Insert initial success message
INSERT INTO audit_log (operation, image_hash, algorithm, user_id, result, image_filename, image_size_bytes, signature_type, created_by)
VALUES ('SIGN', 'initial_migration_marker', 'migration', 'system', 'SUCCESS', 'V1__Initial_Schema.sql', 0, 'migration', 'flyway')
ON CONFLICT DO NOTHING;

-- Database initialization complete
SELECT 'V1__Initial_Schema migration completed successfully' AS status;