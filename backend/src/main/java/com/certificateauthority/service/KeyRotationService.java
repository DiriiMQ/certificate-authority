package com.certificateauthority.service;

import com.certificateauthority.entity.KeyRotationLog;
import com.certificateauthority.entity.SigningKey;
import com.certificateauthority.repository.KeyRotationLogRepository;
import com.certificateauthority.repository.SigningKeyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Service for automated key rotation policies and lifecycle management.
 * 
 * Features:
 * - Policy-driven key rotation based on time intervals, usage counts, or manual triggers
 * - Automated scheduled rotation with configurable policies
 * - Emergency key rotation for security incidents
 * - Graceful key transition with overlap periods
 * - Comprehensive audit logging through KeyRotationLog
 * - Bulk rotation operations for algorithm updates
 * 
 * Rotation policies:
 * - Time-based: Rotate keys after a specific duration
 * - Usage-based: Rotate keys after reaching usage threshold
 * - Manual: Administrator-initiated rotation
 * - Emergency: Immediate rotation for security incidents
 * - Compliance: Regulatory requirement-driven rotation
 */
@Service
@Transactional
public class KeyRotationService {

    private final KeyGenerationService keyGenerationService;
    private final KeyStorageService keyStorageService;
    private final SigningKeyRepository signingKeyRepository;
    private final KeyRotationLogRepository keyRotationLogRepository;

    // Configuration properties with defaults
    @Value("${app.key-rotation.default-key-lifetime-days:90}")
    private int defaultKeyLifetimeDays;

    @Value("${app.key-rotation.usage-threshold:10000}")
    private long usageThreshold;

    @Value("${app.key-rotation.overlap-period-hours:24}")
    private int overlapPeriodHours;

    @Value("${app.key-rotation.auto-rotation-enabled:true}")
    private boolean autoRotationEnabled;

    @Value("${app.key-rotation.emergency-deactivation-delay-hours:1}")
    private int emergencyDeactivationDelayHours;

    @Autowired
    public KeyRotationService(KeyGenerationService keyGenerationService,
                            KeyStorageService keyStorageService,
                            SigningKeyRepository signingKeyRepository,
                            KeyRotationLogRepository keyRotationLogRepository) {
        this.keyGenerationService = keyGenerationService;
        this.keyStorageService = keyStorageService;
        this.signingKeyRepository = signingKeyRepository;
        this.keyRotationLogRepository = keyRotationLogRepository;
    }

    /**
     * Rotate a specific key manually.
     * 
     * @param keyId Key ID to rotate
     * @param initiatedBy Username initiating the rotation
     * @param reason Reason for rotation
     * @param notes Additional notes for the rotation
     * @return RotationResult containing details of the operation
     */
    public RotationResult rotateKey(UUID keyId, String initiatedBy, 
                                  KeyRotationLog.RotationReason reason, String notes) {
        long startTime = System.currentTimeMillis();
        KeyRotationLog rotationLog = null;

        try {
            // Retrieve the key to rotate
            SigningKey oldKey = signingKeyRepository.findById(keyId)
                .orElseThrow(() -> new IllegalArgumentException("Key not found with ID: " + keyId));

            if (!oldKey.getIsActive()) {
                throw new IllegalArgumentException("Cannot rotate inactive key: " + keyId);
            }

            // Generate new key with same algorithm
            KeyGenerationService.KeyPairResult newKeyPair = keyGenerationService
                .generateKeyPair(oldKey.getAlgorithm());

            // Generate unique identifier for new key
            String newKeyIdentifier = generateKeyIdentifier(oldKey.getAlgorithm());

            // Calculate expiration for new key
            LocalDateTime newKeyExpiration = LocalDateTime.now().plusDays(defaultKeyLifetimeDays);

            // Store new key
            SigningKey newKey = keyStorageService.storeKey(
                newKeyIdentifier,
                newKeyPair.getAlgorithm(),
                newKeyPair.getPublicKeyBase64(),
                newKeyPair.getPrivateKeyBase64(),
                newKeyPair.getKeySizeBits(),
                initiatedBy,
                defaultKeyLifetimeDays * 24 // Convert to hours
            );

            // Create rotation log entry
            rotationLog = new KeyRotationLog(
                oldKey, 
                newKey, 
                KeyRotationLog.RotationType.MANUAL_ROTATION,
                reason, 
                initiatedBy, 
                notes
            );
            rotationLog = keyRotationLogRepository.save(rotationLog);

            // Schedule old key deactivation after overlap period
            scheduleKeyDeactivation(oldKey, overlapPeriodHours, initiatedBy, 
                "Automatic deactivation after rotation overlap period");

            rotationLog.setRotationDuration(startTime);
            keyRotationLogRepository.save(rotationLog);

            return new RotationResult(true, "Key rotated successfully", 
                oldKey, newKey, rotationLog, null);

        } catch (Exception e) {
            // Log the failure
            if (rotationLog != null) {
                rotationLog.markFailed(e.getMessage());
                rotationLog.setRotationDuration(startTime);
                keyRotationLogRepository.save(rotationLog);
            }
            
            return new RotationResult(false, "Key rotation failed: " + e.getMessage(), 
                null, null, rotationLog, e);
        }
    }

    /**
     * Emergency key rotation for security incidents.
     * Immediately deactivates the old key without overlap period.
     * 
     * @param keyId Key ID to rotate
     * @param initiatedBy Username initiating the rotation
     * @param securityIncidentDetails Details of the security incident
     * @return RotationResult containing details of the operation
     */
    public RotationResult emergencyRotateKey(UUID keyId, String initiatedBy, 
                                           String securityIncidentDetails) {
        long startTime = System.currentTimeMillis();
        KeyRotationLog rotationLog = null;

        try {
            // Retrieve the key to rotate
            SigningKey oldKey = signingKeyRepository.findById(keyId)
                .orElseThrow(() -> new IllegalArgumentException("Key not found with ID: " + keyId));

            // Generate new key with same algorithm
            KeyGenerationService.KeyPairResult newKeyPair = keyGenerationService
                .generateKeyPair(oldKey.getAlgorithm());

            String newKeyIdentifier = generateKeyIdentifier(oldKey.getAlgorithm());

            // Store new key
            SigningKey newKey = keyStorageService.storeKey(
                newKeyIdentifier,
                newKeyPair.getAlgorithm(),
                newKeyPair.getPublicKeyBase64(),
                newKeyPair.getPrivateKeyBase64(),
                newKeyPair.getKeySizeBits(),
                initiatedBy,
                defaultKeyLifetimeDays * 24
            );

            // Create emergency rotation log
            rotationLog = new KeyRotationLog(
                oldKey, 
                newKey, 
                KeyRotationLog.RotationType.EMERGENCY_ROTATION,
                KeyRotationLog.RotationReason.SECURITY_INCIDENT, 
                initiatedBy, 
                "Emergency rotation: " + securityIncidentDetails
            );
            rotationLog = keyRotationLogRepository.save(rotationLog);

            // Immediately deactivate old key (no overlap for emergency)
            oldKey.deactivate(initiatedBy, "Emergency deactivation: " + securityIncidentDetails);
            signingKeyRepository.save(oldKey);

            rotationLog.setRotationDuration(startTime);
            keyRotationLogRepository.save(rotationLog);

            return new RotationResult(true, "Emergency rotation completed successfully", 
                oldKey, newKey, rotationLog, null);

        } catch (Exception e) {
            if (rotationLog != null) {
                rotationLog.markFailed(e.getMessage());
                rotationLog.setRotationDuration(startTime);
                keyRotationLogRepository.save(rotationLog);
            }
            
            return new RotationResult(false, "Emergency rotation failed: " + e.getMessage(), 
                null, null, rotationLog, e);
        }
    }

    /**
     * Scheduled automatic key rotation based on policies.
     * Runs every hour to check for keys needing rotation.
     */
    @Scheduled(fixedRate = 3600000) // Every hour
    @Async
    public CompletableFuture<Void> scheduledKeyRotation() {
        if (!autoRotationEnabled) {
            return CompletableFuture.completedFuture(null);
        }

        try {
            // Find keys needing rotation based on age
            LocalDateTime ageThreshold = LocalDateTime.now().minusDays(defaultKeyLifetimeDays);
            List<SigningKey> keysNeedingAgeRotation = signingKeyRepository
                .findKeysNeedingRotationByAge(ageThreshold, PageRequest.of(0, 100))
                .getContent();

            // Find keys needing rotation based on usage
            List<SigningKey> keysNeedingUsageRotation = signingKeyRepository
                .findKeysNeedingRotationByUsage(usageThreshold, PageRequest.of(0, 100))
                .getContent();

            // Combine and deduplicate
            Set<SigningKey> keysToRotate = new HashSet<>(keysNeedingAgeRotation);
            keysToRotate.addAll(keysNeedingUsageRotation);

            // Rotate each key
            for (SigningKey key : keysToRotate) {
                try {
                    KeyRotationLog.RotationReason reason = keysNeedingAgeRotation.contains(key) ?
                        KeyRotationLog.RotationReason.TIME_BASED :
                        KeyRotationLog.RotationReason.USAGE_BASED;
                    
                    rotateKeyAutomatically(key, reason);
                } catch (Exception e) {
                    // Log error but continue with other keys
                    System.err.println("Failed to rotate key " + key.getId() + ": " + e.getMessage());
                }
            }

        } catch (Exception e) {
            System.err.println("Error in scheduled key rotation: " + e.getMessage());
        }

        return CompletableFuture.completedFuture(null);
    }

    /**
     * Rotate keys for a specific algorithm (e.g., for algorithm updates).
     * 
     * @param algorithm Algorithm to rotate
     * @param initiatedBy Username initiating the rotation
     * @param reason Reason for bulk rotation
     * @return List of RotationResult for each key rotated
     */
    public List<RotationResult> rotateKeysByAlgorithm(String algorithm, String initiatedBy, 
                                                     KeyRotationLog.RotationReason reason) {
        List<SigningKey> keys = signingKeyRepository.findUsableKeysByAlgorithm(algorithm, LocalDateTime.now());
        List<RotationResult> results = new ArrayList<>();

        for (SigningKey key : keys) {
            try {
                RotationResult result = rotateKey(key.getId(), initiatedBy, reason, 
                    "Bulk rotation for algorithm: " + algorithm);
                results.add(result);
            } catch (Exception e) {
                results.add(new RotationResult(false, "Failed to rotate key " + key.getId() + ": " + e.getMessage(),
                    key, null, null, e));
            }
        }

        return results;
    }

    /**
     * Handle expired keys by deactivating them.
     * Runs daily to clean up expired keys.
     */
    @Scheduled(cron = "0 0 2 * * ?") // Daily at 2 AM
    @Async
    public CompletableFuture<Void> handleExpiredKeys() {
        try {
            LocalDateTime now = LocalDateTime.now();
            List<SigningKey> expiredKeys = signingKeyRepository
                .findByIsActiveTrueAndExpiresAtBefore(now, PageRequest.of(0, 1000))
                .getContent();

            for (SigningKey expiredKey : expiredKeys) {
                try {
                    expiredKey.deactivate("system", "Automatic deactivation - key expired");
                    signingKeyRepository.save(expiredKey);

                    // Log the deactivation
                    KeyRotationLog log = new KeyRotationLog(
                        expiredKey, 
                        null, // No replacement key for expiration
                        KeyRotationLog.RotationType.SCHEDULED_ROTATION,
                        KeyRotationLog.RotationReason.TIME_BASED,
                        "system",
                        "Automatic deactivation of expired key"
                    );
                    keyRotationLogRepository.save(log);

                } catch (Exception e) {
                    System.err.println("Failed to deactivate expired key " + expiredKey.getId() + ": " + e.getMessage());
                }
            }

        } catch (Exception e) {
            System.err.println("Error in expired key handling: " + e.getMessage());
        }

        return CompletableFuture.completedFuture(null);
    }

    /**
     * Validate key lifecycle and recommend actions.
     * 
     * @param keyId Key ID to validate
     * @return KeyLifecycleValidation containing validation results and recommendations
     */
    public KeyLifecycleValidation validateKeyLifecycle(UUID keyId) {
        try {
            SigningKey key = signingKeyRepository.findById(keyId)
                .orElseThrow(() -> new IllegalArgumentException("Key not found with ID: " + keyId));

            KeyLifecycleValidation validation = new KeyLifecycleValidation(key);

            // Check age
            if (key.getCreatedAt() != null) {
                long ageInDays = ChronoUnit.DAYS.between(key.getCreatedAt(), LocalDateTime.now());
                validation.setAgeDays(ageInDays);
                
                if (ageInDays >= defaultKeyLifetimeDays) {
                    validation.addRecommendation("Key has exceeded recommended lifetime, consider rotation");
                } else if (ageInDays >= defaultKeyLifetimeDays * 0.8) {
                    validation.addRecommendation("Key approaching end of recommended lifetime");
                }
            }

            // Check usage
            if (key.getUsageCount() >= usageThreshold) {
                validation.addRecommendation("Key has exceeded usage threshold, consider rotation");
            } else if (key.getUsageCount() >= usageThreshold * 0.8) {
                validation.addRecommendation("Key approaching usage threshold");
            }

            // Check expiration
            if (key.getExpiresAt() != null) {
                long daysToExpiration = ChronoUnit.DAYS.between(LocalDateTime.now(), key.getExpiresAt());
                validation.setDaysToExpiration(daysToExpiration);
                
                if (daysToExpiration <= 0) {
                    validation.addRecommendation("Key has expired and should be deactivated");
                } else if (daysToExpiration <= 7) {
                    validation.addRecommendation("Key expires soon, plan for rotation");
                }
            }

            // Check if key is usable
            if (!key.isUsable()) {
                validation.addRecommendation("Key is not usable (inactive or expired)");
            }

            return validation;

        } catch (Exception e) {
            return new KeyLifecycleValidation(null).addRecommendation("Error validating key: " + e.getMessage());
        }
    }

    /**
     * Get rotation statistics for monitoring and reporting.
     * 
     * @return RotationStatistics containing various rotation metrics
     */
    public RotationStatistics getRotationStatistics() {
        RotationStatistics stats = new RotationStatistics();
        
        // Basic counts
        stats.setTotalRotations(keyRotationLogRepository.count());
        stats.setSuccessfulRotations(keyRotationLogRepository.countBySuccessTrue());
        stats.setFailedRotations(keyRotationLogRepository.countBySuccessFalse());
        
        // Recent rotations (last 30 days)
        LocalDateTime thirtyDaysAgo = LocalDateTime.now().minusDays(30);
        stats.setRecentRotations(keyRotationLogRepository.countByRotationTimestampBetween(
            thirtyDaysAgo, LocalDateTime.now()));
        
        // Type statistics
        stats.setRotationTypeStats(keyRotationLogRepository.getRotationTypeStatistics());
        stats.setRotationReasonStats(keyRotationLogRepository.getRotationReasonStatistics());
        
        return stats;
    }

    // ==================== Private Helper Methods ====================

    /**
     * Automatically rotate a key with system user.
     */
    private RotationResult rotateKeyAutomatically(SigningKey key, KeyRotationLog.RotationReason reason) {
        return rotateKey(key.getId(), "system", reason, "Automatic rotation based on policy");
    }

    /**
     * Schedule key deactivation after specified hours.
     */
    private void scheduleKeyDeactivation(SigningKey key, int hours, String deactivatedBy, String reason) {
        // In a production system, this would use a job scheduler like Quartz
        // For now, we'll set an expiration time that the cleanup job will handle
        LocalDateTime deactivationTime = LocalDateTime.now().plusHours(hours);
        
        // Update key with shorter expiration for overlap period
        if (key.getExpiresAt() == null || key.getExpiresAt().isAfter(deactivationTime)) {
            key.setExpiresAt(deactivationTime);
            signingKeyRepository.save(key);
        }
    }

    /**
     * Generate unique key identifier.
     */
    private String generateKeyIdentifier(String algorithm) {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String randomSuffix = UUID.randomUUID().toString().substring(0, 8);
        return algorithm.toLowerCase() + "-" + timestamp + "-" + randomSuffix;
    }

    // ==================== Result Classes ====================

    /**
     * Result of a key rotation operation.
     */
    public static class RotationResult {
        private final boolean success;
        private final String message;
        private final SigningKey oldKey;
        private final SigningKey newKey;
        private final KeyRotationLog rotationLog;
        private final Exception error;

        public RotationResult(boolean success, String message, SigningKey oldKey, 
                            SigningKey newKey, KeyRotationLog rotationLog, Exception error) {
            this.success = success;
            this.message = message;
            this.oldKey = oldKey;
            this.newKey = newKey;
            this.rotationLog = rotationLog;
            this.error = error;
        }

        // Getters
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public SigningKey getOldKey() { return oldKey; }
        public SigningKey getNewKey() { return newKey; }
        public KeyRotationLog getRotationLog() { return rotationLog; }
        public Exception getError() { return error; }
    }

    /**
     * Key lifecycle validation result.
     */
    public static class KeyLifecycleValidation {
        private final SigningKey key;
        private long ageDays;
        private long daysToExpiration;
        private final List<String> recommendations = new ArrayList<>();

        public KeyLifecycleValidation(SigningKey key) {
            this.key = key;
        }

        public KeyLifecycleValidation addRecommendation(String recommendation) {
            recommendations.add(recommendation);
            return this;
        }

        // Getters and setters
        public SigningKey getKey() { return key; }
        public long getAgeDays() { return ageDays; }
        public void setAgeDays(long ageDays) { this.ageDays = ageDays; }
        public long getDaysToExpiration() { return daysToExpiration; }
        public void setDaysToExpiration(long daysToExpiration) { this.daysToExpiration = daysToExpiration; }
        public List<String> getRecommendations() { return recommendations; }
        public boolean hasRecommendations() { return !recommendations.isEmpty(); }
    }

    /**
     * Rotation statistics for monitoring.
     */
    public static class RotationStatistics {
        private long totalRotations;
        private long successfulRotations;
        private long failedRotations;
        private long recentRotations;
        private List<Object[]> rotationTypeStats;
        private List<Object[]> rotationReasonStats;

        // Getters and setters
        public long getTotalRotations() { return totalRotations; }
        public void setTotalRotations(long totalRotations) { this.totalRotations = totalRotations; }
        public long getSuccessfulRotations() { return successfulRotations; }
        public void setSuccessfulRotations(long successfulRotations) { this.successfulRotations = successfulRotations; }
        public long getFailedRotations() { return failedRotations; }
        public void setFailedRotations(long failedRotations) { this.failedRotations = failedRotations; }
        public long getRecentRotations() { return recentRotations; }
        public void setRecentRotations(long recentRotations) { this.recentRotations = recentRotations; }
        public List<Object[]> getRotationTypeStats() { return rotationTypeStats; }
        public void setRotationTypeStats(List<Object[]> rotationTypeStats) { this.rotationTypeStats = rotationTypeStats; }
        public List<Object[]> getRotationReasonStats() { return rotationReasonStats; }
        public void setRotationReasonStats(List<Object[]> rotationReasonStats) { this.rotationReasonStats = rotationReasonStats; }
        
        public double getSuccessRate() {
            return totalRotations > 0 ? (double) successfulRotations / totalRotations * 100 : 0;
        }
    }
}
