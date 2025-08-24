package com.certificateauthority.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.UuidGenerator;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

/**
 * JPA Entity for audit_log table
 * Tracks all image signing and verification operations with comprehensive audit trail
 */
@Entity
@Table(name = "audit_log", indexes = {
    @Index(name = "idx_audit_log_timestamp", columnList = "timestamp DESC"),
    @Index(name = "idx_audit_log_user_id", columnList = "user_id"),
    @Index(name = "idx_audit_log_operation", columnList = "operation"),
    @Index(name = "idx_audit_log_result", columnList = "result"),
    @Index(name = "idx_audit_log_algorithm", columnList = "algorithm"),
    @Index(name = "idx_audit_log_image_hash", columnList = "image_hash"),
    @Index(name = "idx_audit_log_user_operation_time", columnList = "user_id, operation, timestamp DESC")
})
@EntityListeners(AuditingEntityListener.class)
public class AuditLog {

    /**
     * UUID primary key with automatic generation
     */
    @Id
    @UuidGenerator
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    /**
     * Type of operation performed (sign or verify)
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "operation", nullable = false, length = 10)
    private OperationType operation;

    /**
     * SHA-256 hash of the image content (64 hex characters)
     */
    @Column(name = "image_hash", nullable = false, length = 64)
    private String imageHash;

    /**
     * Cryptographic algorithm used (Ed25519, ECDSA P-256, RSA-3072)
     */
    @Column(name = "algorithm", nullable = false, length = 50)
    private String algorithm;

    /**
     * UTC timestamp when operation occurred
     */
    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    /**
     * Identifier of user who performed the operation
     */
    @Column(name = "user_id", length = 255)
    private String userId;

    /**
     * Result of the operation (success or fail)
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "result", nullable = false, length = 10)
    private ResultType result;

    /**
     * Original filename of the processed image
     */
    @Column(name = "image_filename", length = 500)
    private String imageFilename;

    /**
     * Size of the image file in bytes
     */
    @Column(name = "image_size_bytes")
    private Long imageSizeBytes;

    /**
     * Type of signature: 'embedded' or 'detached'
     */
    @Column(name = "signature_type", length = 20)
    private String signatureType;

    /**
     * Detailed error message for failed operations
     */
    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    /**
     * Audit trail - automatically populated by Spring Data JPA
     */
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @CreatedBy
    @Column(name = "created_by", length = 100, updatable = false)
    private String createdBy;

    @LastModifiedBy
    @Column(name = "updated_by", length = 100)
    private String updatedBy;

    /**
     * Additional fields for key management operations
     */
    @Column(name = "username", length = 255)
    private String username;

    @Column(name = "key_identifier", length = 100)
    private String keyIdentifier;

    @Column(name = "image_name", length = 500)
    private String imageName;

    @Column(name = "result_type")
    @Enumerated(EnumType.STRING)
    private ResultType resultType;

    @Column(name = "operation_type")
    @Enumerated(EnumType.STRING)
    private OperationType operationType;

    @Column(name = "details", columnDefinition = "TEXT")
    private String details;

    @Column(name = "additional_metadata", columnDefinition = "TEXT")
    private String additionalMetadata;

    /**
     * Default constructor for JPA
     */
    public AuditLog() {
        this.timestamp = LocalDateTime.now();
    }

    /**
     * Constructor for creating audit log entries
     */
    public AuditLog(OperationType operation, String imageHash, String algorithm, 
                   String userId, ResultType result) {
        this();
        this.operation = operation;
        this.imageHash = imageHash;
        this.algorithm = algorithm;
        this.userId = userId;
        this.result = result;
    }

    /**
     * Constructor with additional metadata
     */
    public AuditLog(OperationType operation, String imageHash, String algorithm, 
                   String userId, ResultType result, String imageFilename, 
                   Long imageSizeBytes, String signatureType) {
        this(operation, imageHash, algorithm, userId, result);
        this.imageFilename = imageFilename;
        this.imageSizeBytes = imageSizeBytes;
        this.signatureType = signatureType;
    }

    // Getters and Setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public OperationType getOperation() {
        return operation;
    }

    public void setOperation(OperationType operation) {
        this.operation = operation;
    }

    public String getImageHash() {
        return imageHash;
    }

    public void setImageHash(String imageHash) {
        this.imageHash = imageHash;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public ResultType getResult() {
        return result;
    }

    public void setResult(ResultType result) {
        this.result = result;
    }

    public String getImageFilename() {
        return imageFilename;
    }

    public void setImageFilename(String imageFilename) {
        this.imageFilename = imageFilename;
    }

    public Long getImageSizeBytes() {
        return imageSizeBytes;
    }

    public void setImageSizeBytes(Long imageSizeBytes) {
        this.imageSizeBytes = imageSizeBytes;
    }

    public String getSignatureType() {
        return signatureType;
    }

    public void setSignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public String getUpdatedBy() {
        return updatedBy;
    }

    public void setUpdatedBy(String updatedBy) {
        this.updatedBy = updatedBy;
    }

    // Additional setters for key management operations
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(String keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    public String getImageName() {
        return imageName;
    }

    public void setImageName(String imageName) {
        this.imageName = imageName;
    }

    public ResultType getResultType() {
        return resultType;
    }

    public void setResultType(ResultType resultType) {
        this.resultType = resultType;
    }

    public OperationType getOperationType() {
        return operationType;
    }

    public void setOperationType(OperationType operationType) {
        this.operationType = operationType;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public String getAdditionalMetadata() {
        return additionalMetadata;
    }

    public void setAdditionalMetadata(String additionalMetadata) {
        this.additionalMetadata = additionalMetadata;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditLog auditLog = (AuditLog) o;
        return Objects.equals(id, auditLog.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "AuditLog{" +
                "id=" + id +
                ", operation=" + operation +
                ", imageHash='" + imageHash + '\'' +
                ", algorithm='" + algorithm + '\'' +
                ", timestamp=" + timestamp +
                ", userId='" + userId + '\'' +
                ", result=" + result +
                ", imageFilename='" + imageFilename + '\'' +
                ", imageSizeBytes=" + imageSizeBytes +
                ", signatureType='" + signatureType + '\'' +
                ", createdAt=" + createdAt +
                ", updatedAt=" + updatedAt +
                '}';
    }
}