package com.certificateauthority.repository;

import com.certificateauthority.entity.KeyRotationLog;
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
 * Spring Data JPA Repository for KeyRotationLog entities
 * Provides CRUD operations and custom query methods for key rotation audit trail
 */
@Repository
public interface KeyRotationLogRepository extends JpaRepository<KeyRotationLog, UUID> {

    // ==================== Basic Query Methods ====================

    /**
     * Find rotation logs by rotation type
     *
     * @param rotationType The type of rotation
     * @param pageable     Pagination information
     * @return Page of rotation logs for the specified type
     */
    Page<KeyRotationLog> findByRotationType(KeyRotationLog.RotationType rotationType, Pageable pageable);

    /**
     * Find rotation logs by rotation reason
     *
     * @param rotationReason The reason for rotation
     * @param pageable       Pagination information
     * @return Page of rotation logs for the specified reason
     */
    Page<KeyRotationLog> findByRotationReason(KeyRotationLog.RotationReason rotationReason, Pageable pageable);

    /**
     * Find rotation logs by algorithm
     *
     * @param algorithm The cryptographic algorithm
     * @param pageable  Pagination information
     * @return Page of rotation logs for the specified algorithm
     */
    Page<KeyRotationLog> findByAlgorithm(String algorithm, Pageable pageable);

    /**
     * Find rotation logs initiated by a specific user
     *
     * @param initiatedBy The user who initiated the rotation
     * @param pageable    Pagination information
     * @return Page of rotation logs initiated by the user
     */
    Page<KeyRotationLog> findByInitiatedBy(String initiatedBy, Pageable pageable);

    /**
     * Find successful rotation logs
     *
     * @param pageable Pagination information
     * @return Page of successful rotation logs
     */
    Page<KeyRotationLog> findBySuccessTrue(Pageable pageable);

    /**
     * Find failed rotation logs
     *
     * @param pageable Pagination information
     * @return Page of failed rotation logs
     */
    Page<KeyRotationLog> findBySuccessFalse(Pageable pageable);

    // ==================== Key-specific Queries ====================

    /**
     * Find rotation logs involving a specific old key
     *
     * @param oldKey   The old key involved in rotation
     * @param pageable Pagination information
     * @return Page of rotation logs involving the old key
     */
    Page<KeyRotationLog> findByOldKey(SigningKey oldKey, Pageable pageable);

    /**
     * Find rotation logs involving a specific new key
     *
     * @param newKey   The new key involved in rotation
     * @param pageable Pagination information
     * @return Page of rotation logs involving the new key
     */
    Page<KeyRotationLog> findByNewKey(SigningKey newKey, Pageable pageable);

    /**
     * Find the most recent rotation log for a specific key (as old key)
     *
     * @param oldKey The old key to search for
     * @return Optional most recent rotation log
     */
    @Query("SELECT krl FROM KeyRotationLog krl WHERE krl.oldKey = :oldKey " +
           "ORDER BY krl.rotationTimestamp DESC LIMIT 1")
    Optional<KeyRotationLog> findMostRecentRotationByOldKey(@Param("oldKey") SigningKey oldKey);

    /**
     * Find the creation log for a specific key (as new key with no old key)
     *
     * @param newKey The new key to search for
     * @return Optional creation log
     */
    @Query("SELECT krl FROM KeyRotationLog krl WHERE krl.newKey = :newKey AND krl.oldKey IS NULL " +
           "ORDER BY krl.rotationTimestamp DESC LIMIT 1")
    Optional<KeyRotationLog> findKeyCreationLog(@Param("newKey") SigningKey newKey);

    // ==================== Date Range Queries ====================

    /**
     * Find rotation logs within a date range
     *
     * @param startDate Start of the date range
     * @param endDate   End of the date range
     * @param pageable  Pagination information
     * @return Page of rotation logs within the date range
     */
    Page<KeyRotationLog> findByRotationTimestampBetween(LocalDateTime startDate, LocalDateTime endDate, Pageable pageable);

    /**
     * Find rotation logs after a specific date
     *
     * @param date     The date threshold
     * @param pageable Pagination information
     * @return Page of rotation logs after the specified date
     */
    Page<KeyRotationLog> findByRotationTimestampAfter(LocalDateTime date, Pageable pageable);

    /**
     * Find recent rotation logs (last N days)
     *
     * @param date     Number of days to look back
     * @param pageable Pagination information
     * @return Page of recent rotation logs
     */
    @Query("SELECT krl FROM KeyRotationLog krl WHERE krl.rotationTimestamp >= :date " +
           "ORDER BY krl.rotationTimestamp DESC")
    Page<KeyRotationLog> findRecentRotations(@Param("date") LocalDateTime date, Pageable pageable);

    // ==================== Complex Query Methods ====================

    /**
     * Find emergency rotations within a time period
     *
     * @param startDate Start of the time period
     * @param endDate   End of the time period
     * @param pageable  Pagination information
     * @return Page of emergency rotations
     */
    @Query("SELECT krl FROM KeyRotationLog krl WHERE krl.rotationType = 'EMERGENCY_ROTATION' " +
           "AND krl.rotationTimestamp BETWEEN :startDate AND :endDate " +
           "ORDER BY krl.rotationTimestamp DESC")
    Page<KeyRotationLog> findEmergencyRotationsInPeriod(@Param("startDate") LocalDateTime startDate,
                                                        @Param("endDate") LocalDateTime endDate,
                                                        Pageable pageable);

    /**
     * Find failed rotations with error messages
     *
     * @param pageable Pagination information
     * @return Page of failed rotations with error messages
     */
    @Query("SELECT krl FROM KeyRotationLog krl WHERE krl.success = false AND krl.errorMessage IS NOT NULL " +
           "ORDER BY krl.rotationTimestamp DESC")
    Page<KeyRotationLog> findFailedRotationsWithErrors(Pageable pageable);

    /**
     * Find rotations by type and algorithm
     *
     * @param rotationType The rotation type
     * @param algorithm    The algorithm
     * @param pageable     Pagination information
     * @return Page of rotations matching both criteria
     */
    Page<KeyRotationLog> findByRotationTypeAndAlgorithm(KeyRotationLog.RotationType rotationType,
                                                        String algorithm,
                                                        Pageable pageable);

    /**
     * Find rotations with high old key usage
     *
     * @param usageThreshold The usage threshold
     * @param pageable       Pagination information
     * @return Page of rotations where old keys had high usage
     */
    @Query("SELECT krl FROM KeyRotationLog krl WHERE krl.oldKeyUsageCount >= :usageThreshold " +
           "ORDER BY krl.oldKeyUsageCount DESC")
    Page<KeyRotationLog> findRotationsWithHighOldKeyUsage(@Param("usageThreshold") Long usageThreshold,
                                                          Pageable pageable);

    // ==================== Statistical Queries ====================

    /**
     * Count rotations by type
     *
     * @param rotationType The rotation type
     * @return Count of rotations for the type
     */
    long countByRotationType(KeyRotationLog.RotationType rotationType);

    /**
     * Count rotations by reason
     *
     * @param rotationReason The rotation reason
     * @return Count of rotations for the reason
     */
    long countByRotationReason(KeyRotationLog.RotationReason rotationReason);

    /**
     * Count successful rotations
     *
     * @return Count of successful rotations
     */
    long countBySuccessTrue();

    /**
     * Count failed rotations
     *
     * @return Count of failed rotations
     */
    long countBySuccessFalse();

    /**
     * Count rotations within date range
     *
     * @param startDate Start of the date range
     * @param endDate   End of the date range
     * @return Count of rotations within the date range
     */
    long countByRotationTimestampBetween(LocalDateTime startDate, LocalDateTime endDate);

    /**
     * Get rotation type statistics
     *
     * @return List of rotation type statistics [type, count, success_count, avg_duration]
     */
    @Query("SELECT krl.rotationType, COUNT(krl) as totalCount, " +
           "COUNT(CASE WHEN krl.success = true THEN 1 END) as successCount, " +
           "AVG(krl.rotationDurationMs) as avgDuration " +
           "FROM KeyRotationLog krl GROUP BY krl.rotationType ORDER BY totalCount DESC")
    List<Object[]> getRotationTypeStatistics();

    /**
     * Get rotation reason statistics
     *
     * @return List of rotation reason statistics [reason, count, success_rate]
     */
    @Query("SELECT krl.rotationReason, COUNT(krl) as totalCount, " +
           "COUNT(CASE WHEN krl.success = true THEN 1 END) * 100.0 / COUNT(krl) as successRate " +
           "FROM KeyRotationLog krl GROUP BY krl.rotationReason ORDER BY totalCount DESC")
    List<Object[]> getRotationReasonStatistics();

    /**
     * Get daily rotation statistics for the last N days
     *
     * @param days Number of days to analyze
     * @return List of daily statistics [date, count, success_count, avg_duration]
     */
    @Query("SELECT DATE(krl.rotationTimestamp) as rotationDate, COUNT(krl) as totalCount, " +
           "COUNT(CASE WHEN krl.success = true THEN 1 END) as successCount, " +
           "AVG(krl.rotationDurationMs) as avgDuration " +
           "FROM KeyRotationLog krl WHERE krl.rotationTimestamp >= :date " +
           "GROUP BY DATE(krl.rotationTimestamp) ORDER BY rotationDate DESC")
    List<Object[]> getDailyRotationStatistics(@Param("date") LocalDateTime date);

    /**
     * Get algorithm rotation frequency
     *
     * @return List of algorithm rotation frequency [algorithm, count, avg_old_key_usage]
     */
    @Query("SELECT krl.algorithm, COUNT(krl) as rotationCount, AVG(krl.oldKeyUsageCount) as avgOldKeyUsage " +
           "FROM KeyRotationLog krl WHERE krl.oldKey IS NOT NULL " +
           "GROUP BY krl.algorithm ORDER BY rotationCount DESC")
    List<Object[]> getAlgorithmRotationFrequency();

    // ==================== Advanced Analytics ====================

    /**
     * Find rotation patterns by user
     *
     * @param initiatedBy The user to analyze
     * @param pageable    Pagination information
     * @return Page of rotations with pattern analysis
     */
    @Query("SELECT krl FROM KeyRotationLog krl WHERE krl.initiatedBy = :initiatedBy " +
           "ORDER BY krl.rotationTimestamp DESC")
    Page<KeyRotationLog> findRotationPatternsByUser(@Param("initiatedBy") String initiatedBy, Pageable pageable);

    /**
     * Find correlations between rotation reasons and key age
     *
     * @return List of correlation data [reason, avg_key_age_days, count]
     */
    @Query("SELECT krl.rotationReason, AVG(krl.oldKeyAgeDays) as avgKeyAge, COUNT(krl) as count " +
           "FROM KeyRotationLog krl WHERE krl.oldKeyAgeDays IS NOT NULL " +
           "GROUP BY krl.rotationReason ORDER BY avgKeyAge DESC")
    List<Object[]> getRotationReasonToKeyAgeCorrelation();

    /**
     * Delete old rotation logs beyond retention period
     *
     * @param cutoffDate The cutoff date for deletion
     * @return Number of deleted records
     */
    @Query("DELETE FROM KeyRotationLog krl WHERE krl.rotationTimestamp < :cutoffDate")
    long deleteByRotationTimestampBefore(@Param("cutoffDate") LocalDateTime cutoffDate);
}