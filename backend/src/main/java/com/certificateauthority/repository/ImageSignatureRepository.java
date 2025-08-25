package com.certificateauthority.repository;

import com.certificateauthority.entity.ImageSignature;
import com.certificateauthority.entity.SignatureAlgorithm;
import com.certificateauthority.entity.SignatureFormat;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for ImageSignature entity operations
 */
@Repository
public interface ImageSignatureRepository extends JpaRepository<ImageSignature, UUID> {
    
    /**
     * Find image signature by image hash
     */
    Optional<ImageSignature> findByImageHash(String imageHash);
    
    /**
     * Find image signatures by image name
     */
    List<ImageSignature> findByImageName(String imageName);
    
    /**
     * Find image signatures by signing key ID
     */
    List<ImageSignature> findBySigningKeyId(UUID signingKeyId);
    
    /**
     * Find image signatures by signature algorithm
     */
    List<ImageSignature> findBySignatureAlgorithm(SignatureAlgorithm algorithm);
    
    /**
     * Find image signatures by signature format
     */
    List<ImageSignature> findBySignatureFormat(SignatureFormat format);
    
    /**
     * Find image signatures created within a date range
     */
    List<ImageSignature> findBySignatureTimestampBetween(LocalDateTime startDate, 
                                                         LocalDateTime endDate);
    
    /**
     * Find image signatures by verification result
     */
    List<ImageSignature> findByLastVerificationResult(Boolean result);
    
    /**
     * Find image signatures that have been verified
     */
    @Query("SELECT i FROM ImageSignature i WHERE i.lastVerificationAt IS NOT NULL")
    List<ImageSignature> findVerifiedSignatures();
    
    /**
     * Find image signatures that have never been verified
     */
    @Query("SELECT i FROM ImageSignature i WHERE i.lastVerificationAt IS NULL")
    List<ImageSignature> findUnverifiedSignatures();
    
    /**
     * Count signatures by algorithm
     */
    long countBySignatureAlgorithm(SignatureAlgorithm algorithm);
    
    /**
     * Count signatures by format
     */
    long countBySignatureFormat(SignatureFormat format);
    
    /**
     * Count signatures created between dates
     */
    long countBySignatureTimestampBetween(LocalDateTime startDate, LocalDateTime endDate);
    
    /**
     * Find signatures with high verification count (potentially suspicious)
     */
    @Query("SELECT i FROM ImageSignature i WHERE i.verificationCount > :threshold ORDER BY i.verificationCount DESC")
    List<ImageSignature> findHighlyVerifiedSignatures(@Param("threshold") int threshold);
    
    /**
     * Find recent signatures with pagination
     */
    @Query("SELECT i FROM ImageSignature i ORDER BY i.signatureTimestamp DESC")
    Page<ImageSignature> findRecentSignatures(Pageable pageable);
    
    /**
     * Find signatures by key identifier pattern
     */
    List<ImageSignature> findByKeyIdentifierContaining(String keyIdentifierPattern);
    
    /**
     * Count total verification attempts across all signatures
     */
    @Query("SELECT SUM(i.verificationCount) FROM ImageSignature i")
    Long getTotalVerificationCount();
    
    /**
     * Get signature statistics
     */
    @Query("SELECT " +
           "COUNT(i) as totalSignatures, " +
           "COUNT(CASE WHEN i.signatureFormat = 'EMBEDDED' THEN 1 END) as embeddedCount, " +
           "COUNT(CASE WHEN i.signatureFormat = 'DETACHED' THEN 1 END) as detachedCount, " +
           "COUNT(CASE WHEN i.lastVerificationResult = true THEN 1 END) as validCount, " +
           "COUNT(CASE WHEN i.lastVerificationResult = false THEN 1 END) as invalidCount " +
           "FROM ImageSignature i")
    Object[] getSignatureStatistics();
    
    /**
     * Find signatures that need verification (older than specified time)
     */
    @Query("SELECT i FROM ImageSignature i WHERE " +
           "i.lastVerificationAt IS NULL OR " +
           "i.lastVerificationAt < :cutoffTime")
    List<ImageSignature> findSignaturesNeedingVerification(@Param("cutoffTime") LocalDateTime cutoffTime);
    
    /**
     * Check if signature exists for image hash
     */
    boolean existsByImageHash(String imageHash);
    
    /**
     * Delete signatures older than specified date
     */
    void deleteBySignatureTimestampBefore(LocalDateTime cutoffDate);
}