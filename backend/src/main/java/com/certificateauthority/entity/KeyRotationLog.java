package com.certificateauthority.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

/**
 * JPA Entity for key rotation audit trail and lifecycle management
 * 
 * This entity tracks all key rotation operations including:
 * - Key creation and activation events
 * - Key deactivation and replacement operations
 * - Automatic rotation based on time or usage policies
 * - Manual key rotation initiated by administrators
 * - Emergency key revocation and replacement
 */
@Entity
@Table(name = "key_rotation_log", indexes = {
    @Index(name = "idx_key_rotation_log_rotation_timestamp", columnList = "rotation_timestamp DESC"),
    @Index(name = "idx_key_rotation_log_old_key_id", columnList = "old_key_id"),
    @Index(name = "idx_key_rotation_log_new_key_id", columnList = "new_key_id"),
    @Index(name = "idx_key_rotation_log_rotation_type", columnList = "rotation_type"),
    @Index(name = "idx_key_rotation_log_initiated_by", columnList = "initiated_by"),
    @Index(name = "idx_key_rotation_log_algorithm", columnList = "algorithm"),
    @Index(name = "idx_key_rotation_log_reason", columnList = "rotation_reason")
})
@EntityListeners(AuditingEntityListener.class)
public class KeyRotationLog {

    @Id
    @GeneratedValue(generator = "UUID")
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "old_key_id", nullable = true, foreignKey = @ForeignKey(name = "fk_key_rotation_log_old_key"))
    private SigningKey oldKey;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "new_key_id", nullable = false, foreignKey = @ForeignKey(name = "fk_key_rotation_log_new_key"))
    private SigningKey newKey;

    @Enumerated(EnumType.STRING)
    @Column(name = "rotation_type", nullable = false, length = 20)
    private RotationType rotationType;

    @Enumerated(EnumType.STRING)
    @Column(name = "rotation_reason", nullable = false, length = 30)
    private RotationReason rotationReason;

    @Column(name = "algorithm", nullable = false, length = 50)
    private String algorithm;

    @Column(name = "rotation_timestamp", nullable = false, updatable = false)
    @CreatedDate
    private LocalDateTime rotationTimestamp;

    @Column(name = "initiated_by", nullable = false, length = 255)
    private String initiatedBy;

    @Column(name = "rotation_notes", length = 1000)
    private String rotationNotes;

    @Column(name = "old_key_usage_count")
    private Long oldKeyUsageCount;

    @Column(name = "old_key_age_days")
    private Integer oldKeyAgeDays;

    @Column(name = "success", nullable = false)
    private Boolean success = true;

    @Column(name = "error_message", length = 500)
    private String errorMessage;

    @Column(name = "rotation_duration_ms")
    private Long rotationDurationMs;

    public KeyRotationLog() {}

    public KeyRotationLog(SigningKey oldKey, SigningKey newKey, RotationType rotationType, 
                         RotationReason rotationReason, String initiatedBy, String rotationNotes) {
        this.oldKey = oldKey;
        this.newKey = newKey;
        this.rotationType = rotationType;
        this.rotationReason = rotationReason;
        this.algorithm = newKey.getAlgorithm();
        this.initiatedBy = initiatedBy;
        this.rotationNotes = rotationNotes;
        this.success = true;
        
        if (oldKey != null) {
            this.oldKeyUsageCount = oldKey.getUsageCount();
            if (oldKey.getCreatedAt() != null) {
                this.oldKeyAgeDays = (int) java.time.temporal.ChronoUnit.DAYS.between(
                    oldKey.getCreatedAt().toLocalDate(), 
                    LocalDateTime.now().toLocalDate()
                );
            }
        }
    }

    // Getters and Setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public SigningKey getOldKey() {
        return oldKey;
    }

    public void setOldKey(SigningKey oldKey) {
        this.oldKey = oldKey;
    }

    public SigningKey getNewKey() {
        return newKey;
    }

    public void setNewKey(SigningKey newKey) {
        this.newKey = newKey;
    }

    public RotationType getRotationType() {
        return rotationType;
    }

    public void setRotationType(RotationType rotationType) {
        this.rotationType = rotationType;
    }

    public RotationReason getRotationReason() {
        return rotationReason;
    }

    public void setRotationReason(RotationReason rotationReason) {
        this.rotationReason = rotationReason;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public LocalDateTime getRotationTimestamp() {
        return rotationTimestamp;
    }

    public void setRotationTimestamp(LocalDateTime rotationTimestamp) {
        this.rotationTimestamp = rotationTimestamp;
    }

    public String getInitiatedBy() {
        return initiatedBy;
    }

    public void setInitiatedBy(String initiatedBy) {
        this.initiatedBy = initiatedBy;
    }

    public String getRotationNotes() {
        return rotationNotes;
    }

    public void setRotationNotes(String rotationNotes) {
        this.rotationNotes = rotationNotes;
    }

    public Long getOldKeyUsageCount() {
        return oldKeyUsageCount;
    }

    public void setOldKeyUsageCount(Long oldKeyUsageCount) {
        this.oldKeyUsageCount = oldKeyUsageCount;
    }

    public Integer getOldKeyAgeDays() {
        return oldKeyAgeDays;
    }

    public void setOldKeyAgeDays(Integer oldKeyAgeDays) {
        this.oldKeyAgeDays = oldKeyAgeDays;
    }

    public Boolean getSuccess() {
        return success;
    }

    public void setSuccess(Boolean success) {
        this.success = success;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public Long getRotationDurationMs() {
        return rotationDurationMs;
    }

    public void setRotationDurationMs(Long rotationDurationMs) {
        this.rotationDurationMs = rotationDurationMs;
    }

    // Business Methods
    public void markFailed(String errorMessage) {
        this.success = false;
        this.errorMessage = errorMessage;
    }

    public void setRotationDuration(long startTime) {
        this.rotationDurationMs = System.currentTimeMillis() - startTime;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyRotationLog that = (KeyRotationLog) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "KeyRotationLog{" +
                "id=" + id +
                ", rotationType=" + rotationType +
                ", rotationReason=" + rotationReason +
                ", algorithm='" + algorithm + '\'' +
                ", rotationTimestamp=" + rotationTimestamp +
                ", initiatedBy='" + initiatedBy + '\'' +
                ", success=" + success +
                '}';
    }

    /**
     * Enum for different types of key rotation operations
     */
    public enum RotationType {
        INITIAL_KEY_CREATION("Initial key creation"),
        SCHEDULED_ROTATION("Scheduled automatic rotation"),
        MANUAL_ROTATION("Manual administrator rotation"),
        EMERGENCY_ROTATION("Emergency key replacement"),
        POLICY_DRIVEN_ROTATION("Policy-driven rotation");

        private final String description;

        RotationType(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    /**
     * Enum for reasons behind key rotation
     */
    public enum RotationReason {
        TIME_BASED("Time-based rotation policy"),
        USAGE_BASED("Usage count threshold reached"),
        SECURITY_INCIDENT("Security incident response"),
        KEY_COMPROMISE("Suspected key compromise"),
        ALGORITHM_UPDATE("Algorithm security update"),
        COMPLIANCE_REQUIREMENT("Regulatory compliance"),
        MAINTENANCE("Routine maintenance"),
        ADMINISTRATOR_REQUEST("Administrator request");

        private final String description;

        RotationReason(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }
}