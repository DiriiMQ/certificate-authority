package com.certificateauthority.repository;

import com.certificateauthority.entity.AuditLog;
import com.certificateauthority.entity.OperationType;
import com.certificateauthority.entity.ResultType;
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
 * Spring Data JPA Repository for AuditLog entities
 * Provides CRUD operations and custom query methods for audit log management
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    // ==================== Basic Query Methods ====================

    /**
     * Find audit logs by operation type
     *
     * @param operation The operation type (SIGN or VERIFY)
     * @param pageable  Pagination information
     * @return Page of audit logs for the specified operation
     */
    Page<AuditLog> findByOperation(OperationType operation, Pageable pageable);

    /**
     * Find audit logs by result type
     *
     * @param result   The result type (SUCCESS or FAIL)
     * @param pageable Pagination information
     * @return Page of audit logs with the specified result
     */
    Page<AuditLog> findByResult(ResultType result, Pageable pageable);

    /**
     * Find audit logs by user ID
     *
     * @param userId   The user identifier
     * @param pageable Pagination information
     * @return Page of audit logs for the specified user
     */
    Page<AuditLog> findByUserId(String userId, Pageable pageable);

    /**
     * Find audit logs by algorithm
     *
     * @param algorithm The cryptographic algorithm
     * @param pageable  Pagination information
     * @return Page of audit logs using the specified algorithm
     */
    Page<AuditLog> findByAlgorithm(String algorithm, Pageable pageable);

    /**
     * Find audit logs by image hash
     *
     * @param imageHash The SHA-256 hash of the image
     * @return Optional audit log entry
     */
    Optional<AuditLog> findByImageHash(String imageHash);

    /**
     * Find all audit logs for a specific image hash
     *
     * @param imageHash The SHA-256 hash of the image
     * @return List of all audit log entries for this image
     */
    List<AuditLog> findAllByImageHash(String imageHash);

    // ==================== Date Range Queries ====================

    /**
     * Find audit logs within a date range
     *
     * @param startDate Start of the date range
     * @param endDate   End of the date range
     * @param pageable  Pagination information
     * @return Page of audit logs within the date range
     */
    Page<AuditLog> findByTimestampBetween(LocalDateTime startDate, LocalDateTime endDate, Pageable pageable);

    /**
     * Find audit logs created after a specific date
     *
     * @param date     The date threshold
     * @param pageable Pagination information
     * @return Page of audit logs created after the specified date
     */
    Page<AuditLog> findByTimestampAfter(LocalDateTime date, Pageable pageable);

    /**
     * Find recent audit logs (last N days)
     *
     * @param days     Number of days to look back
     * @param pageable Pagination information
     * @return Page of recent audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.timestamp >= :date ORDER BY a.timestamp DESC")
    Page<AuditLog> findRecentLogs(@Param("date") LocalDateTime date, Pageable pageable);

    // ==================== Complex Query Methods ====================

    /**
     * Find audit logs by operation and result
     *
     * @param operation The operation type
     * @param result    The result type
     * @param pageable  Pagination information
     * @return Page of audit logs matching both criteria
     */
    Page<AuditLog> findByOperationAndResult(OperationType operation, ResultType result, Pageable pageable);

    /**
     * Find audit logs by user and operation within date range
     *
     * @param userId    The user identifier
     * @param operation The operation type
     * @param startDate Start of the date range
     * @param endDate   End of the date range
     * @param pageable  Pagination information
     * @return Page of filtered audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.userId = :userId AND a.operation = :operation " +
           "AND a.timestamp BETWEEN :startDate AND :endDate ORDER BY a.timestamp DESC")
    Page<AuditLog> findByUserAndOperationAndDateRange(
            @Param("userId") String userId,
            @Param("operation") OperationType operation,
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate,
            Pageable pageable);

    /**
     * Find failed operations with error messages
     *
     * @param pageable Pagination information
     * @return Page of failed audit logs with error messages
     */
    @Query("SELECT a FROM AuditLog a WHERE a.result = 'FAIL' AND a.errorMessage IS NOT NULL ORDER BY a.timestamp DESC")
    Page<AuditLog> findFailedOperationsWithErrors(Pageable pageable);

    // ==================== Statistical Queries ====================

    /**
     * Count total operations by type
     *
     * @param operation The operation type
     * @return Total count of operations
     */
    long countByOperation(OperationType operation);

    /**
     * Count operations by result type
     *
     * @param result The result type
     * @return Total count of operations with this result
     */
    long countByResult(ResultType result);

    /**
     * Count operations by user
     *
     * @param userId The user identifier
     * @return Total count of operations by this user
     */
    long countByUserId(String userId);

    /**
     * Count operations within date range
     *
     * @param startDate Start of the date range
     * @param endDate   End of the date range
     * @return Total count of operations within the date range
     */
    long countByTimestampBetween(LocalDateTime startDate, LocalDateTime endDate);

    /**
     * Count operations by created date range
     *
     * @param startDate Start of the date range
     * @param endDate   End of the date range
     * @return Total count of operations within the date range
     */
    long countByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

    /**
     * Count operations by result type and created date range
     *
     * @param resultType The result type
     * @param startDate Start of the date range
     * @param endDate   End of the date range
     * @return Total count of operations within the date range
     */
    long countByResultTypeAndCreatedAtBetween(ResultType resultType, LocalDateTime startDate, LocalDateTime endDate);

    /**
     * Get operation statistics by algorithm
     *
     * @return List of algorithm usage statistics
     */
    @Query("SELECT a.algorithm, COUNT(a) as count, " +
           "COUNT(CASE WHEN a.result = 'SUCCESS' THEN 1 END) as successCount, " +
           "COUNT(CASE WHEN a.result = 'FAIL' THEN 1 END) as failCount " +
           "FROM AuditLog a GROUP BY a.algorithm ORDER BY count DESC")
    List<Object[]> getAlgorithmStatistics();

    /**
     * Get daily operation counts for the last N days
     *
     * @param days Number of days to analyze
     * @return List of daily statistics
     */
    @Query("SELECT DATE(a.timestamp) as date, COUNT(a) as count, " +
           "COUNT(CASE WHEN a.result = 'SUCCESS' THEN 1 END) as successCount, " +
           "COUNT(CASE WHEN a.result = 'FAIL' THEN 1 END) as failCount " +
           "FROM AuditLog a WHERE a.timestamp >= :date " +
           "GROUP BY DATE(a.timestamp) ORDER BY date DESC")
    List<Object[]> getDailyStatistics(@Param("date") LocalDateTime date);

    // ==================== Advanced Search Queries ====================

    /**
     * Search audit logs with multiple optional filters
     *
     * @param operation Optional operation type filter
     * @param result    Optional result type filter
     * @param userId    Optional user ID filter
     * @param algorithm Optional algorithm filter
     * @param startDate Optional start date filter
     * @param endDate   Optional end date filter
     * @param pageable  Pagination information
     * @return Page of filtered audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE " +
           "(:operation IS NULL OR a.operation = :operation) AND " +
           "(:result IS NULL OR a.result = :result) AND " +
           "(:userId IS NULL OR a.userId = :userId) AND " +
           "(:algorithm IS NULL OR a.algorithm = :algorithm) AND " +
           "(:startDate IS NULL OR a.timestamp >= :startDate) AND " +
           "(:endDate IS NULL OR a.timestamp <= :endDate) " +
           "ORDER BY a.timestamp DESC")
    Page<AuditLog> findWithFilters(
            @Param("operation") OperationType operation,
            @Param("result") ResultType result,
            @Param("userId") String userId,
            @Param("algorithm") String algorithm,
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate,
            Pageable pageable);

    /**
     * Find audit logs by image filename pattern
     *
     * @param filenamePattern The filename pattern (supports SQL LIKE wildcards)
     * @param pageable        Pagination information
     * @return Page of audit logs matching the filename pattern
     */
    @Query("SELECT a FROM AuditLog a WHERE a.imageFilename LIKE :pattern ORDER BY a.timestamp DESC")
    Page<AuditLog> findByImageFilenamePattern(@Param("pattern") String filenamePattern, Pageable pageable);

    /**
     * Find the most recent audit log entry for an image
     *
     * @param imageHash The SHA-256 hash of the image
     * @return Optional most recent audit log for the image
     */
    @Query("SELECT a FROM AuditLog a WHERE a.imageHash = :imageHash ORDER BY a.timestamp DESC LIMIT 1")
    Optional<AuditLog> findMostRecentByImageHash(@Param("imageHash") String imageHash);

    /**
     * Delete old audit logs beyond retention period
     *
     * @param cutoffDate The cutoff date for deletion
     * @return Number of deleted records
     */
    @Query("DELETE FROM AuditLog a WHERE a.timestamp < :cutoffDate")
    long deleteByTimestampBefore(@Param("cutoffDate") LocalDateTime cutoffDate);
}