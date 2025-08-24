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
    VERIFY
}