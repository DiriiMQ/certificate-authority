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
    VIEW_AUDIT_LOG
}