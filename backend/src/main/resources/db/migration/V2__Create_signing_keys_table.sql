-- V2__Create_signing_keys_table.sql
-- Creates the signing_keys table for managing cryptographic keys with lifecycle tracking

-- Create signing_keys table
CREATE TABLE signing_keys (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_identifier          VARCHAR(100) NOT NULL UNIQUE,
    algorithm               VARCHAR(50) NOT NULL,
    public_key_data         TEXT NOT NULL,
    private_key_data        TEXT NOT NULL,
    key_size_bits           INTEGER NOT NULL,
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at              TIMESTAMP WITH TIME ZONE,
    last_used_at            TIMESTAMP WITH TIME ZONE,
    usage_count             BIGINT NOT NULL DEFAULT 0,
    created_by              VARCHAR(255),
    deactivated_at          TIMESTAMP WITH TIME ZONE,
    deactivated_by          VARCHAR(255),
    deactivation_reason     VARCHAR(500),
    version                 BIGINT NOT NULL DEFAULT 0
);

-- Create indexes for performance optimization
CREATE INDEX idx_signing_keys_algorithm ON signing_keys (algorithm);
CREATE INDEX idx_signing_keys_active ON signing_keys (is_active);
CREATE INDEX idx_signing_keys_created_at ON signing_keys (created_at DESC);
CREATE INDEX idx_signing_keys_expires_at ON signing_keys (expires_at);
CREATE INDEX idx_signing_keys_active_algorithm ON signing_keys (is_active, algorithm);
CREATE INDEX idx_signing_keys_lifecycle ON signing_keys (created_at, expires_at, is_active);
CREATE INDEX idx_signing_keys_usage_count ON signing_keys (usage_count DESC);
CREATE INDEX idx_signing_keys_last_used_at ON signing_keys (last_used_at DESC);
CREATE INDEX idx_signing_keys_created_by ON signing_keys (created_by);
CREATE INDEX idx_signing_keys_deactivated_at ON signing_keys (deactivated_at);

-- Create composite indexes for complex queries
CREATE INDEX idx_signing_keys_active_created ON signing_keys (is_active, created_at DESC);
CREATE INDEX idx_signing_keys_active_expires ON signing_keys (is_active, expires_at);
CREATE INDEX idx_signing_keys_algorithm_usage ON signing_keys (algorithm, usage_count DESC);

-- Create a trigger to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_signing_keys_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_signing_keys_updated_at
    BEFORE UPDATE ON signing_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_signing_keys_updated_at();

-- Create a partial index for active keys only (performance optimization)
CREATE INDEX idx_signing_keys_active_only ON signing_keys (algorithm, created_at DESC, usage_count)
    WHERE is_active = TRUE;

-- Create a partial index for expired keys (maintenance queries)
CREATE INDEX idx_signing_keys_expired ON signing_keys (expires_at)
    WHERE expires_at IS NOT NULL AND is_active = TRUE;

-- Add comments for documentation
COMMENT ON TABLE signing_keys IS 'Cryptographic signing keys with lifecycle management and usage tracking';
COMMENT ON COLUMN signing_keys.id IS 'Primary key UUID';
COMMENT ON COLUMN signing_keys.key_identifier IS 'Unique human-readable identifier for the key';
COMMENT ON COLUMN signing_keys.algorithm IS 'Cryptographic algorithm (Ed25519, ECDSA_P256, RSA_3072)';
COMMENT ON COLUMN signing_keys.public_key_data IS 'Base64 encoded public key data';
COMMENT ON COLUMN signing_keys.private_key_data IS 'Base64 encoded encrypted private key data';
COMMENT ON COLUMN signing_keys.key_size_bits IS 'Key size in bits for the algorithm';
COMMENT ON COLUMN signing_keys.is_active IS 'Whether the key is currently active and usable';
COMMENT ON COLUMN signing_keys.created_at IS 'When the key was created';
COMMENT ON COLUMN signing_keys.updated_at IS 'When the key record was last updated';
COMMENT ON COLUMN signing_keys.expires_at IS 'When the key expires (NULL means no expiration)';
COMMENT ON COLUMN signing_keys.last_used_at IS 'When the key was last used for signing';
COMMENT ON COLUMN signing_keys.usage_count IS 'Number of times the key has been used for signing';
COMMENT ON COLUMN signing_keys.created_by IS 'User who created the key';
COMMENT ON COLUMN signing_keys.deactivated_at IS 'When the key was deactivated';
COMMENT ON COLUMN signing_keys.deactivated_by IS 'User who deactivated the key';
COMMENT ON COLUMN signing_keys.deactivation_reason IS 'Reason for key deactivation';
COMMENT ON COLUMN signing_keys.version IS 'Version number for optimistic locking';

-- Create views for common queries
CREATE OR REPLACE VIEW active_signing_keys AS
SELECT 
    id,
    key_identifier,
    algorithm,
    key_size_bits,
    created_at,
    expires_at,
    last_used_at,
    usage_count,
    created_by,
    CASE 
        WHEN expires_at IS NULL THEN 'Never'
        WHEN expires_at > CURRENT_TIMESTAMP THEN 'Active'
        ELSE 'Expired'
    END AS expiration_status
FROM signing_keys
WHERE is_active = TRUE
ORDER BY algorithm, created_at DESC;

COMMENT ON VIEW active_signing_keys IS 'View of all active signing keys with expiration status';

-- Create a view for key rotation candidates
CREATE OR REPLACE VIEW key_rotation_candidates AS
SELECT 
    id,
    key_identifier,
    algorithm,
    created_at,
    expires_at,
    usage_count,
    last_used_at,
    EXTRACT(DAYS FROM (CURRENT_TIMESTAMP - created_at)) AS age_days,
    CASE
        WHEN expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP + INTERVAL '30 days' THEN 'EXPIRING_SOON'
        WHEN EXTRACT(DAYS FROM (CURRENT_TIMESTAMP - created_at)) > 90 THEN 'OLD_AGE'
        WHEN usage_count > 10000 THEN 'HIGH_USAGE'
        ELSE 'NORMAL'
    END AS rotation_reason
FROM signing_keys
WHERE is_active = TRUE
    AND (
        expires_at <= CURRENT_TIMESTAMP + INTERVAL '30 days'
        OR EXTRACT(DAYS FROM (CURRENT_TIMESTAMP - created_at)) > 90
        OR usage_count > 10000
    )
ORDER BY 
    CASE 
        WHEN expires_at <= CURRENT_TIMESTAMP + INTERVAL '7 days' THEN 1
        WHEN expires_at <= CURRENT_TIMESTAMP + INTERVAL '30 days' THEN 2
        WHEN usage_count > 50000 THEN 3
        WHEN usage_count > 10000 THEN 4
        ELSE 5
    END,
    created_at ASC;

COMMENT ON VIEW key_rotation_candidates IS 'View of keys that may need rotation based on age, usage, or expiration';