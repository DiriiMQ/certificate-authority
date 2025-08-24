package com.certificateauthority.entity;

/**
 * Enum representing the result of a cryptographic operation
 */
public enum ResultType {
    /**
     * Operation completed successfully
     */
    SUCCESS,
    
    /**
     * Operation failed due to error
     */
    FAIL,
    
    /**
     * Operation failed due to error (alias for FAIL)
     */
    FAILURE
}