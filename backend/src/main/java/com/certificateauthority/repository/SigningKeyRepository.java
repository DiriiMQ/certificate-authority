package com.certificateauthority.repository;

import com.certificateauthority.entity.SigningKey;
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
 * Spring Data JPA Repository for SigningKey entities
 * Provides CRUD operations and custom query methods for signing key management
 */
@Repository
public interface SigningKeyRepository extends JpaRepository<SigningKey, UUID> {

    // ==================== Basic Query Methods ====================

    /**
     * Find signing key by key identifier
     *
     * @param keyIdentifier The unique key identifier
     * @return Optional signing key
     */
    Optional<SigningKey> findByKeyIdentifier(String keyIdentifier);

    /**
     * Find all active signing keys
     *
     * @param pageable Pagination information
     * @return Page of active signing keys
     */
    Page<SigningKey> findByIsActiveTrue(Pageable pageable);

    /**
     * Find all inactive signing keys
     *
     * @param pageable Pagination information
     * @return Page of inactive signing keys
     */
    Page<SigningKey> findByIsActiveFalse(Pageable pageable);

    /**
     * Find signing keys by algorithm
     *
     * @param algorithm The cryptographic algorithm
     * @param pageable  Pagination information
     * @return Page of signing keys using the specified algorithm
     */
    Page<SigningKey> findByAlgorithm(String algorithm, Pageable pageable);

    /**
     * Find active signing keys by algorithm
     *
     * @param algorithm The cryptographic algorithm
     * @param pageable  Pagination information
     * @return Page of active signing keys using the specified algorithm
     */
    Page<SigningKey> findByAlgorithmAndIsActiveTrue(String algorithm, Pageable pageable);

    /**
     * Find signing keys created by a specific user
     *
     * @param createdBy The user who created the key
     * @param pageable  Pagination information
     * @return Page of signing keys created by the user
     */
    Page<SigningKey> findByCreatedBy(String createdBy, Pageable pageable);

    // ==================== Date Range Queries ====================

    /**
     * Find signing keys created within a date range
     *
     * @param startDate Start of the date range
     * @param endDate   End of the date range
     * @param pageable  Pagination information
     * @return Page of signing keys created within the date range
     */
    Page<SigningKey> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate, Pageable pageable);

    /**
     * Find signing keys that expire before a specific date
     *
     * @param expirationDate The expiration threshold date
     * @param pageable       Pagination information
     * @return Page of signing keys expiring before the date
     */
    Page<SigningKey> findByExpiresAtBefore(LocalDateTime expirationDate, Pageable pageable);

    /**
     * Find active signing keys that expire within a time period
     *
     * @param expirationDate The expiration threshold date
     * @param pageable       Pagination information
     * @return Page of active signing keys expiring before the date
     */
    Page<SigningKey> findByIsActiveTrueAndExpiresAtBefore(LocalDateTime expirationDate, Pageable pageable);

    // ==================== Complex Query Methods ====================

    /**
     * Find the most recently created active key for a specific algorithm
     *
     * @param algorithm The cryptographic algorithm
     * @return Optional most recent active signing key for the algorithm
     */
    @Query("SELECT sk FROM SigningKey sk WHERE sk.algorithm = :algorithm AND sk.isActive = true " +
           "ORDER BY sk.createdAt DESC LIMIT 1")
    Optional<SigningKey> findMostRecentActiveKeyByAlgorithm(@Param("algorithm") String algorithm);

    /**
     * Find all usable keys (active and not expired) for a specific algorithm
     *
     * @param algorithm The cryptographic algorithm
     * @param now       Current timestamp for expiration check
     * @return List of usable signing keys
     */
    @Query("SELECT sk FROM SigningKey sk WHERE sk.algorithm = :algorithm AND sk.isActive = true " +
           "AND (sk.expiresAt IS NULL OR sk.expiresAt > :now) ORDER BY sk.createdAt DESC")
    List<SigningKey> findUsableKeysByAlgorithm(@Param("algorithm") String algorithm, @Param("now") LocalDateTime now);

    /**
     * Find keys that need rotation based on usage count threshold
     *
     * @param usageThreshold The usage count threshold
     * @param pageable       Pagination information
     * @return Page of keys exceeding usage threshold
     */
    @Query("SELECT sk FROM SigningKey sk WHERE sk.isActive = true AND sk.usageCount >= :usageThreshold " +
           "ORDER BY sk.usageCount DESC, sk.createdAt ASC")
    Page<SigningKey> findKeysNeedingRotationByUsage(@Param("usageThreshold") Long usageThreshold, Pageable pageable);

    /**
     * Find keys that need rotation based on age
     *
     * @param ageThreshold The age threshold date
     * @param pageable     Pagination information
     * @return Page of keys older than threshold
     */
    @Query("SELECT sk FROM SigningKey sk WHERE sk.isActive = true AND sk.createdAt < :ageThreshold " +
           "ORDER BY sk.createdAt ASC")
    Page<SigningKey> findKeysNeedingRotationByAge(@Param("ageThreshold") LocalDateTime ageThreshold, Pageable pageable);

    /**
     * Find keys with high usage in a specific time period
     *
     * @param startDate      Start of the time period
     * @param endDate        End of the time period
     * @param usageThreshold Usage threshold
     * @param pageable       Pagination information
     * @return Page of highly used keys
     */
    @Query("SELECT sk FROM SigningKey sk WHERE sk.lastUsedAt BETWEEN :startDate AND :endDate " +
           "AND sk.usageCount >= :usageThreshold ORDER BY sk.usageCount DESC")
    Page<SigningKey> findHighlyUsedKeysInPeriod(@Param("startDate") LocalDateTime startDate,
                                               @Param("endDate") LocalDateTime endDate,
                                               @Param("usageThreshold") Long usageThreshold,
                                               Pageable pageable);

    // ==================== Statistical Queries ====================

    /**
     * Count active keys by algorithm
     *
     * @param algorithm The cryptographic algorithm
     * @return Count of active keys for the algorithm
     */
    long countByAlgorithmAndIsActiveTrue(String algorithm);

    /**
     * Count total keys by algorithm
     *
     * @param algorithm The cryptographic algorithm
     * @return Total count of keys for the algorithm
     */
    long countByAlgorithm(String algorithm);

    /**
     * Count keys created by a specific user
     *
     * @param createdBy The user who created the keys
     * @return Count of keys created by the user
     */
    long countByCreatedBy(String createdBy);

    /**
     * Get algorithm usage statistics
     *
     * @return List of algorithm statistics [algorithm, total_count, active_count, avg_usage]
     */
    @Query("SELECT sk.algorithm, COUNT(sk) as totalCount, " +
           "COUNT(CASE WHEN sk.isActive = true THEN 1 END) as activeCount, " +
           "AVG(sk.usageCount) as avgUsage " +
           "FROM SigningKey sk GROUP BY sk.algorithm ORDER BY totalCount DESC")
    List<Object[]> getAlgorithmStatistics();

    /**
     * Get key lifecycle statistics
     *
     * @return List of lifecycle statistics [created_date, created_count, deactivated_count]
     */
    @Query("SELECT DATE(sk.createdAt) as createdDate, COUNT(sk) as createdCount, " +
           "COUNT(CASE WHEN sk.isActive = false THEN 1 END) as deactivatedCount " +
           "FROM SigningKey sk GROUP BY DATE(sk.createdAt) ORDER BY createdDate DESC")
    List<Object[]> getKeyLifecycleStatistics();

    // ==================== Maintenance Queries ====================

    /**
     * Find keys ready for cleanup (inactive and old)
     *
     * @param cleanupThreshold Date threshold for cleanup
     * @param pageable         Pagination information
     * @return Page of keys ready for cleanup
     */
    @Query("SELECT sk FROM SigningKey sk WHERE sk.isActive = false " +
           "AND sk.deactivatedAt < :cleanupThreshold ORDER BY sk.deactivatedAt ASC")
    Page<SigningKey> findKeysReadyForCleanup(@Param("cleanupThreshold") LocalDateTime cleanupThreshold, Pageable pageable);

    /**
     * Update last used timestamp and increment usage count
     *
     * @param keyId The key ID to update
     * @param now   Current timestamp
     */
    @Query("UPDATE SigningKey sk SET sk.lastUsedAt = :now, sk.usageCount = sk.usageCount + 1 " +
           "WHERE sk.id = :keyId")
    void updateKeyUsage(@Param("keyId") UUID keyId, @Param("now") LocalDateTime now);
}