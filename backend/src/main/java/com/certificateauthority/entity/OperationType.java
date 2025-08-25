package com.certificateauthority.entity;

/**
 * Enum representing the type of cryptographic operation performed
 */
public enum OperationType {
    /**
     * Image signing operation
     */
    SIGN,
    
    /**
     * Image signature verification operation
     */
    VERIFY,
    
    /**
     * Key generation operation
     */
    KEY_GENERATION,
    
    /**
     * Key rotation operation
     */
    KEY_ROTATION,
    
    /**
     * Image signing operation (alias for SIGN)
     */
    SIGN_IMAGE,
    
    /**
     * View audit log operation
     */
    VIEW_AUDIT_LOG,
    
    /**
     * Embed signature in image metadata operation
     */
    EMBED_SIGNATURE,
    
    /**
     * Extract signature from image metadata operation
     */
    EXTRACT_SIGNATURE,
    
    /**
     * Verify embedded signature operation
     */
    VERIFY_EMBEDDED_SIGNATURE,
    
    /**
     * Generate detached signature file operation
     */
    GENERATE_DETACHED_SIGNATURE,
    
    /**
     * Verify detached signature operation
     */
    VERIFY_DETACHED_SIGNATURE
}