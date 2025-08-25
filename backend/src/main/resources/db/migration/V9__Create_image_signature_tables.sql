-- V9: Create tables for image signature tracking and metadata
-- This migration adds support for tracking embedded image signatures and metadata

-- Create image_signatures table to track signed images
CREATE TABLE image_signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Image identification
    image_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of original image
    image_name VARCHAR(255) NOT NULL,
    image_size BIGINT NOT NULL,
    image_format VARCHAR(10) NOT NULL CHECK (image_format IN ('PNG', 'JPEG', 'JPG', 'TIFF')),
    mime_type VARCHAR(50) NOT NULL,
    
    -- Signature information
    signature_data TEXT NOT NULL, -- Base64 encoded signature
    signature_algorithm VARCHAR(20) NOT NULL CHECK (signature_algorithm IN ('Ed25519', 'ECDSA_P256', 'RSA_3072')),
    signature_format VARCHAR(20) NOT NULL CHECK (signature_format IN ('EMBEDDED', 'DETACHED')),
    embedding_location VARCHAR(50), -- Where signature was embedded (e.g., 'PNG_iTXt', 'JPEG_COM')
    
    -- Key information
    signing_key_id UUID NOT NULL,
    key_identifier VARCHAR(255) NOT NULL, -- Key identifier used for signing
    
    -- Signature metadata
    signature_timestamp TIMESTAMP NOT NULL, -- When signature was created
    signature_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of the signature itself
    
    -- Verification tracking
    verification_count INTEGER DEFAULT 0,
    last_verification_at TIMESTAMP,
    last_verification_result BOOLEAN,
    
    -- Audit columns
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),
    updated_by VARCHAR(100),
    
    -- Foreign key constraints
    CONSTRAINT fk_image_signatures_signing_key 
        FOREIGN KEY (signing_key_id) 
        REFERENCES signing_keys(id) 
        ON DELETE RESTRICT,
    
    -- Indexes for performance
    CONSTRAINT idx_image_signatures_hash UNIQUE (image_hash),
    CONSTRAINT idx_image_signatures_name_format UNIQUE (image_name, image_format)
);

-- Create index on commonly queried columns
CREATE INDEX idx_image_signatures_timestamp ON image_signatures(signature_timestamp DESC);
CREATE INDEX idx_image_signatures_algorithm ON image_signatures(signature_algorithm);
CREATE INDEX idx_image_signatures_format ON image_signatures(signature_format);
CREATE INDEX idx_image_signatures_key_id ON image_signatures(signing_key_id);
CREATE INDEX idx_image_signatures_verification ON image_signatures(last_verification_at DESC);

-- Create image_metadata table for storing additional image metadata
CREATE TABLE image_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Link to image signature
    image_signature_id UUID NOT NULL,
    
    -- Metadata information
    metadata_key VARCHAR(100) NOT NULL,
    metadata_value TEXT,
    metadata_type VARCHAR(20) NOT NULL CHECK (metadata_type IN ('STRING', 'NUMBER', 'BOOLEAN', 'JSON')),
    
    -- Source information
    metadata_source VARCHAR(50) NOT NULL, -- e.g., 'EXIF', 'IPTC', 'XMP', 'CUSTOM'
    
    -- Audit columns
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Foreign key constraint
    CONSTRAINT fk_image_metadata_signature 
        FOREIGN KEY (image_signature_id) 
        REFERENCES image_signatures(id) 
        ON DELETE CASCADE,
    
    -- Unique constraint to prevent duplicate metadata keys per image
    CONSTRAINT idx_image_metadata_unique UNIQUE (image_signature_id, metadata_key, metadata_source)
);

-- Create indexes for metadata queries
CREATE INDEX idx_image_metadata_key ON image_metadata(metadata_key);
CREATE INDEX idx_image_metadata_source ON image_metadata(metadata_source);
CREATE INDEX idx_image_metadata_signature_id ON image_metadata(image_signature_id);

-- Add new operation types to audit_log if not already present
-- (This is handled by the enum in Java, but we add a comment for documentation)
-- New operation types: EMBED_SIGNATURE, EXTRACT_SIGNATURE, VERIFY_EMBEDDED_SIGNATURE

-- Create trigger to update updated_at timestamp automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers to new tables
CREATE TRIGGER update_image_signatures_updated_at 
    BEFORE UPDATE ON image_signatures 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_image_metadata_updated_at 
    BEFORE UPDATE ON image_metadata 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Add table comments for documentation
COMMENT ON TABLE image_signatures IS 'Tracks digital signatures embedded in or associated with image files';
COMMENT ON TABLE image_metadata IS 'Stores additional metadata extracted from signed images';

COMMENT ON COLUMN image_signatures.image_hash IS 'SHA-256 hash of the original image content before signing';
COMMENT ON COLUMN image_signatures.signature_data IS 'Base64 encoded digital signature';
COMMENT ON COLUMN image_signatures.embedding_location IS 'Technical location where signature was embedded in the image format';
COMMENT ON COLUMN image_signatures.verification_count IS 'Number of times this signature has been verified';

COMMENT ON COLUMN image_metadata.metadata_source IS 'Source of the metadata (EXIF, IPTC, XMP, or CUSTOM)';
COMMENT ON COLUMN image_metadata.metadata_type IS 'Data type of the metadata value for proper deserialization';