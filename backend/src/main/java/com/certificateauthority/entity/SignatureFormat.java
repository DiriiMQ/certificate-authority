package com.certificateauthority.entity;

/**
 * Enum representing signature format types
 */
public enum SignatureFormat {
    /**
     * Signature is embedded within the image file metadata
     */
    EMBEDDED,
    
    /**
     * Signature is stored as a separate detached file
     */
    DETACHED
}