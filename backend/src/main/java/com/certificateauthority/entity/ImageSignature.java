package com.certificateauthority.entity;

import jakarta.persistence.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * JPA Entity representing a digital signature associated with an image file.
 * Tracks both embedded and detached signatures along with verification history.
 */
@Entity
@Table(name = "image_signatures")
@EntityListeners(AuditingEntityListener.class)
public class ImageSignature {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;
    
    // Image identification
    @Column(name = "image_hash", nullable = false, length = 64, unique = true)
    private String imageHash;
    
    @Column(name = "image_name", nullable = false, length = 255)
    private String imageName;
    
    @Column(name = "image_size", nullable = false)
    private Long imageSize;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "image_format", nullable = false, length = 10)
    private ImageFormat imageFormat;
    
    @Column(name = "mime_type", nullable = false, length = 50)
    private String mimeType;
    
    // Signature information
    @Column(name = "signature_data", nullable = false, columnDefinition = "TEXT")
    private String signatureData;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "signature_algorithm", nullable = false, length = 20)
    private SignatureAlgorithm signatureAlgorithm;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "signature_format", nullable = false, length = 20)
    private SignatureFormat signatureFormat;
    
    @Column(name = "embedding_location", length = 50)
    private String embeddingLocation;
    
    // Key information
    @Column(name = "signing_key_id", nullable = false)
    private UUID signingKeyId;
    
    @Column(name = "key_identifier", nullable = false, length = 255)
    private String keyIdentifier;
    
    // Signature metadata
    @Column(name = "signature_timestamp", nullable = false)
    private LocalDateTime signatureTimestamp;
    
    @Column(name = "signature_hash", nullable = false, length = 64)
    private String signatureHash;
    
    // Verification tracking
    @Column(name = "verification_count", nullable = false)
    private Integer verificationCount = 0;
    
    @Column(name = "last_verification_at")
    private LocalDateTime lastVerificationAt;
    
    @Column(name = "last_verification_result")
    private Boolean lastVerificationResult;
    
    // Audit columns
    @CreatedDate
    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
    
    @Column(name = "created_by", length = 100)
    private String createdBy;
    
    @Column(name = "updated_by", length = 100)
    private String updatedBy;
    
    // Relationships
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "signing_key_id", insertable = false, updatable = false)
    private SigningKey signingKey;
    
    @OneToMany(mappedBy = "imageSignature", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ImageMetadata> metadata = new ArrayList<>();
    
    // Constructors
    public ImageSignature() {}
    
    public ImageSignature(String imageHash, String imageName, Long imageSize, 
                         ImageFormat imageFormat, String mimeType, String signatureData,
                         SignatureAlgorithm signatureAlgorithm, SignatureFormat signatureFormat,
                         UUID signingKeyId, String keyIdentifier, String signatureHash) {
        this.imageHash = imageHash;
        this.imageName = imageName;
        this.imageSize = imageSize;
        this.imageFormat = imageFormat;
        this.mimeType = mimeType;
        this.signatureData = signatureData;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureFormat = signatureFormat;
        this.signingKeyId = signingKeyId;
        this.keyIdentifier = keyIdentifier;
        this.signatureHash = signatureHash;
        this.signatureTimestamp = LocalDateTime.now();
    }
    
    // Getters and Setters
    public UUID getId() {
        return id;
    }
    
    public void setId(UUID id) {
        this.id = id;
    }
    
    public String getImageHash() {
        return imageHash;
    }
    
    public void setImageHash(String imageHash) {
        this.imageHash = imageHash;
    }
    
    public String getImageName() {
        return imageName;
    }
    
    public void setImageName(String imageName) {
        this.imageName = imageName;
    }
    
    public Long getImageSize() {
        return imageSize;
    }
    
    public void setImageSize(Long imageSize) {
        this.imageSize = imageSize;
    }
    
    public ImageFormat getImageFormat() {
        return imageFormat;
    }
    
    public void setImageFormat(ImageFormat imageFormat) {
        this.imageFormat = imageFormat;
    }
    
    public String getMimeType() {
        return mimeType;
    }
    
    public void setMimeType(String mimeType) {
        this.mimeType = mimeType;
    }
    
    public String getSignatureData() {
        return signatureData;
    }
    
    public void setSignatureData(String signatureData) {
        this.signatureData = signatureData;
    }
    
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
    
    public void setSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }
    
    public SignatureFormat getSignatureFormat() {
        return signatureFormat;
    }
    
    public void setSignatureFormat(SignatureFormat signatureFormat) {
        this.signatureFormat = signatureFormat;
    }
    
    public String getEmbeddingLocation() {
        return embeddingLocation;
    }
    
    public void setEmbeddingLocation(String embeddingLocation) {
        this.embeddingLocation = embeddingLocation;
    }
    
    public UUID getSigningKeyId() {
        return signingKeyId;
    }
    
    public void setSigningKeyId(UUID signingKeyId) {
        this.signingKeyId = signingKeyId;
    }
    
    public String getKeyIdentifier() {
        return keyIdentifier;
    }
    
    public void setKeyIdentifier(String keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }
    
    public LocalDateTime getSignatureTimestamp() {
        return signatureTimestamp;
    }
    
    public void setSignatureTimestamp(LocalDateTime signatureTimestamp) {
        this.signatureTimestamp = signatureTimestamp;
    }
    
    public String getSignatureHash() {
        return signatureHash;
    }
    
    public void setSignatureHash(String signatureHash) {
        this.signatureHash = signatureHash;
    }
    
    public Integer getVerificationCount() {
        return verificationCount;
    }
    
    public void setVerificationCount(Integer verificationCount) {
        this.verificationCount = verificationCount;
    }
    
    public LocalDateTime getLastVerificationAt() {
        return lastVerificationAt;
    }
    
    public void setLastVerificationAt(LocalDateTime lastVerificationAt) {
        this.lastVerificationAt = lastVerificationAt;
    }
    
    public Boolean getLastVerificationResult() {
        return lastVerificationResult;
    }
    
    public void setLastVerificationResult(Boolean lastVerificationResult) {
        this.lastVerificationResult = lastVerificationResult;
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
    
    public SigningKey getSigningKey() {
        return signingKey;
    }
    
    public void setSigningKey(SigningKey signingKey) {
        this.signingKey = signingKey;
    }
    
    public List<ImageMetadata> getMetadata() {
        return metadata;
    }
    
    public void setMetadata(List<ImageMetadata> metadata) {
        this.metadata = metadata;
    }
    
    // Convenience methods
    public void incrementVerificationCount() {
        this.verificationCount++;
    }
    
    public void recordVerificationResult(Boolean result) {
        this.lastVerificationResult = result;
        this.lastVerificationAt = LocalDateTime.now();
        incrementVerificationCount();
    }
    
    public boolean isEmbeddedSignature() {
        return SignatureFormat.EMBEDDED.equals(this.signatureFormat);
    }
    
    public boolean isDetachedSignature() {
        return SignatureFormat.DETACHED.equals(this.signatureFormat);
    }
}