package com.certificateauthority.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * JPA Entity representing metadata associated with a signed image.
 * Stores key-value pairs of metadata extracted from image files.
 */
@Entity
@Table(name = "image_metadata")
@EntityListeners(AuditingEntityListener.class)
public class ImageMetadata {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    
    // Link to image signature
    @Column(name = "image_signature_id", nullable = false)
    private UUID imageSignatureId;
    
    // Metadata information
    @Column(name = "metadata_key", nullable = false, length = 100)
    private String metadataKey;
    
    @Column(name = "metadata_value", columnDefinition = "TEXT")
    private String metadataValue;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "metadata_type", nullable = false, length = 20)
    private MetadataType metadataType;
    
    // Source information
    @Column(name = "metadata_source", nullable = false, length = 50)
    private String metadataSource;
    
    // Audit columns
    @CreatedDate
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
    
    // Relationships
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "image_signature_id", insertable = false, updatable = false)
    private ImageSignature imageSignature;
    
    // Constructors
    public ImageMetadata() {}
    
    public ImageMetadata(UUID imageSignatureId, String metadataKey, 
                        String metadataValue, MetadataType metadataType, 
                        String metadataSource) {
        this.imageSignatureId = imageSignatureId;
        this.metadataKey = metadataKey;
        this.metadataValue = metadataValue;
        this.metadataType = metadataType;
        this.metadataSource = metadataSource;
    }
    
    // Getters and Setters
    public UUID getId() {
        return id;
    }
    
    public void setId(UUID id) {
        this.id = id;
    }
    
    public UUID getImageSignatureId() {
        return imageSignatureId;
    }
    
    public void setImageSignatureId(UUID imageSignatureId) {
        this.imageSignatureId = imageSignatureId;
    }
    
    public String getMetadataKey() {
        return metadataKey;
    }
    
    public void setMetadataKey(String metadataKey) {
        this.metadataKey = metadataKey;
    }
    
    public String getMetadataValue() {
        return metadataValue;
    }
    
    public void setMetadataValue(String metadataValue) {
        this.metadataValue = metadataValue;
    }
    
    public MetadataType getMetadataType() {
        return metadataType;
    }
    
    public void setMetadataType(MetadataType metadataType) {
        this.metadataType = metadataType;
    }
    
    public String getMetadataSource() {
        return metadataSource;
    }
    
    public void setMetadataSource(String metadataSource) {
        this.metadataSource = metadataSource;
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
    
    public ImageSignature getImageSignature() {
        return imageSignature;
    }
    
    public void setImageSignature(ImageSignature imageSignature) {
        this.imageSignature = imageSignature;
    }
    
    // Convenience methods for type-safe value access
    public String getStringValue() {
        return metadataValue;
    }
    
    public Double getNumericValue() {
        if (metadataType == MetadataType.NUMBER && metadataValue != null) {
            try {
                return Double.parseDouble(metadataValue);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }
    
    public Boolean getBooleanValue() {
        if (metadataType == MetadataType.BOOLEAN && metadataValue != null) {
            return Boolean.parseBoolean(metadataValue);
        }
        return null;
    }
    
    // Static factory methods for common metadata types
    public static ImageMetadata createString(UUID imageSignatureId, String key, 
                                           String value, String source) {
        return new ImageMetadata(imageSignatureId, key, value, MetadataType.STRING, source);
    }
    
    public static ImageMetadata createNumber(UUID imageSignatureId, String key, 
                                           Number value, String source) {
        return new ImageMetadata(imageSignatureId, key, value.toString(), 
                               MetadataType.NUMBER, source);
    }
    
    public static ImageMetadata createBoolean(UUID imageSignatureId, String key, 
                                            Boolean value, String source) {
        return new ImageMetadata(imageSignatureId, key, value.toString(), 
                               MetadataType.BOOLEAN, source);
    }
    
    public static ImageMetadata createJson(UUID imageSignatureId, String key, 
                                         String jsonValue, String source) {
        return new ImageMetadata(imageSignatureId, key, jsonValue, 
                               MetadataType.JSON, source);
    }
}