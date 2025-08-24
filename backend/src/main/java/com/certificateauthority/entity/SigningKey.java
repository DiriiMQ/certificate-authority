package com.certificateauthority.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

/**
 * JPA Entity for signing key management and lifecycle tracking
 * 
 * This entity stores cryptographic keys used for image signing operations with:
 * - Key lifecycle management (creation, expiration, active status)
 * - Algorithm-specific key data storage
 * - Audit trail for key operations
 * - Security metadata and rotation tracking
 */
@Entity
@Table(name = "signing_keys", indexes = {
    @Index(name = "idx_signing_keys_algorithm", columnList = "algorithm"),
    @Index(name = "idx_signing_keys_active", columnList = "is_active"),
    @Index(name = "idx_signing_keys_created_at", columnList = "created_at DESC"),
    @Index(name = "idx_signing_keys_expires_at", columnList = "expires_at"),
    @Index(name = "idx_signing_keys_active_algorithm", columnList = "is_active, algorithm"),
    @Index(name = "idx_signing_keys_lifecycle", columnList = "created_at, expires_at, is_active")
})
@EntityListeners(AuditingEntityListener.class)
public class SigningKey {

    @Id
    @GeneratedValue(generator = "UUID")
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "key_identifier", nullable = false, unique = true, length = 100)
    private String keyIdentifier;

    @Column(name = "algorithm", nullable = false, length = 50)
    private String algorithm;

    @Column(name = "public_key_data", nullable = false, columnDefinition = "TEXT")
    private String publicKeyData;

    @Column(name = "private_key_data", nullable = false, columnDefinition = "TEXT")
    private String privateKeyData;

    @Column(name = "key_size_bits", nullable = false)
    private Integer keySizeBits;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreatedDate
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    @LastModifiedDate
    private LocalDateTime updatedAt;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    @Column(name = "usage_count", nullable = false)
    private Long usageCount = 0L;

    @Column(name = "created_by", length = 255)
    private String createdBy;

    @Column(name = "deactivated_at")
    private LocalDateTime deactivatedAt;

    @Column(name = "deactivated_by", length = 255)
    private String deactivatedBy;

    @Column(name = "deactivation_reason", length = 500)
    private String deactivationReason;

    @Version
    @Column(name = "version")
    private Long version = 0L;

    public SigningKey() {}

    public SigningKey(String keyIdentifier, String algorithm, String publicKeyData, 
                     String privateKeyData, Integer keySizeBits, String createdBy) {
        this.keyIdentifier = keyIdentifier;
        this.algorithm = algorithm;
        this.publicKeyData = publicKeyData;
        this.privateKeyData = privateKeyData;
        this.keySizeBits = keySizeBits;
        this.createdBy = createdBy;
        this.isActive = true;
        this.usageCount = 0L;
    }

    // Getters and Setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(String keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getPublicKeyData() {
        return publicKeyData;
    }

    public void setPublicKeyData(String publicKeyData) {
        this.publicKeyData = publicKeyData;
    }

    public String getPrivateKeyData() {
        return privateKeyData;
    }

    public void setPrivateKeyData(String privateKeyData) {
        this.privateKeyData = privateKeyData;
    }

    public Integer getKeySizeBits() {
        return keySizeBits;
    }

    public void setKeySizeBits(Integer keySizeBits) {
        this.keySizeBits = keySizeBits;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
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

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public LocalDateTime getLastUsedAt() {
        return lastUsedAt;
    }

    public void setLastUsedAt(LocalDateTime lastUsedAt) {
        this.lastUsedAt = lastUsedAt;
    }

    public Long getUsageCount() {
        return usageCount;
    }

    public void setUsageCount(Long usageCount) {
        this.usageCount = usageCount;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public LocalDateTime getDeactivatedAt() {
        return deactivatedAt;
    }

    public void setDeactivatedAt(LocalDateTime deactivatedAt) {
        this.deactivatedAt = deactivatedAt;
    }

    public String getDeactivatedBy() {
        return deactivatedBy;
    }

    public void setDeactivatedBy(String deactivatedBy) {
        this.deactivatedBy = deactivatedBy;
    }

    public String getDeactivationReason() {
        return deactivationReason;
    }

    public void setDeactivationReason(String deactivationReason) {
        this.deactivationReason = deactivationReason;
    }

    public Long getVersion() {
        return version;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    // Business Methods
    public void deactivate(String deactivatedBy, String reason) {
        this.isActive = false;
        this.deactivatedAt = LocalDateTime.now();
        this.deactivatedBy = deactivatedBy;
        this.deactivationReason = reason;
    }

    public void incrementUsage() {
        this.usageCount++;
        this.lastUsedAt = LocalDateTime.now();
    }

    public boolean isExpired() {
        return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
    }

    public boolean isUsable() {
        return isActive && !isExpired();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SigningKey that = (SigningKey) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "SigningKey{" +
                "id=" + id +
                ", keyIdentifier='" + keyIdentifier + '\'' +
                ", algorithm='" + algorithm + '\'' +
                ", keySizeBits=" + keySizeBits +
                ", isActive=" + isActive +
                ", createdAt=" + createdAt +
                ", expiresAt=" + expiresAt +
                ", usageCount=" + usageCount +
                '}';
    }
}