package com.certificateauthority.service;

import com.certificateauthority.entity.SigningKey;
import com.certificateauthority.repository.SigningKeyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Main facade service for cryptographic key management operations.
 * 
 * This service orchestrates all key-related operations by coordinating between:
 * - KeyGenerationService: Algorithm-specific key generation
 * - KeyStorageService: Secure key storage and retrieval
 * - KeyRotationService: Automated key rotation and lifecycle management
 * - KeyAccessControlService: Security validation and access control
 * 
 * Features:
 * - Unified API for all key management operations
 * - Transaction management and error handling
 * - Performance optimization with caching
 * - Comprehensive audit logging
 * - Security enforcement at service level
 * - Algorithm preference management
 * - Key usage statistics and monitoring
 * 
 * Security:
 * - All operations require appropriate authentication and authorization
 * - Dual control for critical operations
 * - Rate limiting and suspicious activity detection
 * - Comprehensive audit trails
 */
@Service
@Transactional
public class KeyManagementService {

    private final KeyGenerationService keyGenerationService;
    private final KeyStorageService keyStorageService;
    private final KeyRotationService keyRotationService;
    private final KeyAccessControlService keyAccessControlService;
    private final SigningKeyRepository signingKeyRepository;

    // Default algorithm preferences
    @Value("${app.key-management.default-algorithm:Ed25519}")
    private String defaultAlgorithm;

    @Value("${app.key-management.default-key-lifetime-days:90}")
    private int defaultKeyLifetimeDays;

    @Value("${app.key-management.auto-rotation-enabled:true}")
    private boolean autoRotationEnabled;

    @Autowired
    public KeyManagementService(KeyGenerationService keyGenerationService,
                              KeyStorageService keyStorageService,
                              KeyRotationService keyRotationService,
                              KeyAccessControlService keyAccessControlService,
                              SigningKeyRepository signingKeyRepository) {
        this.keyGenerationService = keyGenerationService;
        this.keyStorageService = keyStorageService;
        this.keyRotationService = keyRotationService;
        this.keyAccessControlService = keyAccessControlService;
        this.signingKeyRepository = signingKeyRepository;
    }

    /**
     * Generate a new signing key with the default algorithm.
     * 
     * @param createdBy Username creating the key
     * @return KeyManagementResult containing the generated key details
     */
    @PreAuthorize("hasRole('KEY_ADMIN')")
    public KeyManagementResult generateNewKey(String createdBy) {
        return generateNewKey(defaultAlgorithm, createdBy, null);
    }

    /**
     * Generate a new signing key with specified algorithm.
     * 
     * @param algorithm Algorithm to use (Ed25519, ECDSA_P256, RSA_3072)
     * @param createdBy Username creating the key
     * @param notes Optional notes about the key generation
     * @return KeyManagementResult containing the generated key details
     */
    @PreAuthorize("hasRole('KEY_ADMIN')")
    @CacheEvict(value = "activeKeys", key = "#algorithm")
    public KeyManagementResult generateNewKey(String algorithm, String createdBy, String notes) {
        long startTime = System.currentTimeMillis();
        
        try {
            // Validate access
            Map<String, Object> context = Map.of(
                "algorithm", algorithm,
                "notes", notes != null ? notes : ""
            );
            
            KeyAccessControlService.AccessValidationResult accessResult = 
                keyAccessControlService.validateAccess(
                    KeyAccessControlService.KeyOperation.GENERATE_KEY, null, context);
            
            if (!accessResult.isGranted()) {
                return new KeyManagementResult(false, accessResult.getMessage(), null, null, null);
            }

            // Validate algorithm support
            if (!keyGenerationService.isAlgorithmSupported(algorithm)) {
                String message = "Unsupported algorithm: " + algorithm;
                keyAccessControlService.logSecurityEvent(createdBy, 
                    KeyAccessControlService.KeyOperation.GENERATE_KEY, null, message, 
                    com.certificateauthority.entity.ResultType.FAILURE, context);
                return new KeyManagementResult(false, message, null, null, null);
            }

            // Generate key pair
            KeyGenerationService.KeyPairResult keyPair = keyGenerationService.generateKeyPair(algorithm);
            
            // Generate unique identifier
            String keyIdentifier = generateKeyIdentifier(algorithm);
            
            // Store key securely
            SigningKey storedKey = keyStorageService.storeKey(
                keyIdentifier,
                keyPair.getAlgorithm(),
                keyPair.getPublicKeyBase64(),
                keyPair.getPrivateKeyBase64(),
                keyPair.getKeySizeBits(),
                createdBy,
                defaultKeyLifetimeDays * 24 // Convert to hours
            );

            // Log successful generation
            keyAccessControlService.logSecurityEvent(createdBy,
                KeyAccessControlService.KeyOperation.GENERATE_KEY, storedKey.getId(),
                "Key generated successfully: " + keyIdentifier,
                com.certificateauthority.entity.ResultType.SUCCESS, context);

            long duration = System.currentTimeMillis() - startTime;
            
            return new KeyManagementResult(true, "Key generated successfully", 
                storedKey, keyPair, Map.of("duration_ms", duration));

        } catch (Exception e) {
            String errorMessage = "Key generation failed: " + e.getMessage();
            keyAccessControlService.logSecurityEvent(createdBy,
                KeyAccessControlService.KeyOperation.GENERATE_KEY, null, errorMessage,
                com.certificateauthority.entity.ResultType.FAILURE, Map.of("error", e.getMessage()));
            
            return new KeyManagementResult(false, errorMessage, null, null, 
                Map.of("error_details", e.getMessage()));
        }
    }

    /**
     * Get the current active signing key for the default algorithm.
     * 
     * @return KeyManagementResult containing the active key
     */
    @PreAuthorize("hasRole('KEY_OPERATOR') or hasRole('KEY_ADMIN')")
    @Cacheable(value = "activeKeys", key = "'" + defaultAlgorithm + "'")
    public KeyManagementResult getSigningKey() {
        return getSigningKey(defaultAlgorithm);
    }

    /**
     * Get the current active signing key for specified algorithm.
     * 
     * @param algorithm Algorithm to get key for
     * @return KeyManagementResult containing the active key
     */
    @PreAuthorize("hasRole('KEY_OPERATOR') or hasRole('KEY_ADMIN')")
    @Cacheable(value = "activeKeys", key = "#algorithm")
    public KeyManagementResult getSigningKey(String algorithm) {
        try {
            String username = getCurrentUsername();
            
            // Validate access
            KeyAccessControlService.AccessValidationResult accessResult = 
                keyAccessControlService.validateAccess(
                    KeyAccessControlService.KeyOperation.USE_KEY, null, 
                    Map.of("algorithm", algorithm));
            
            if (!accessResult.isGranted()) {
                return new KeyManagementResult(false, accessResult.getMessage(), null, null, null);
            }

            // Retrieve active key
            Optional<KeyStorageService.SigningKeyWithDecryptedData> keyOpt = 
                keyStorageService.retrieveActiveKeyByAlgorithm(algorithm);
            
            if (keyOpt.isEmpty()) {
                String message = "No active key found for algorithm: " + algorithm;
                keyAccessControlService.logSecurityEvent(username,
                    KeyAccessControlService.KeyOperation.USE_KEY, null, message,
                    com.certificateauthority.entity.ResultType.FAILURE, Map.of("algorithm", algorithm));
                return new KeyManagementResult(false, message, null, null, null);
            }

            KeyStorageService.SigningKeyWithDecryptedData keyData = keyOpt.get();
            
            // Check if key needs rotation soon
            Map<String, Object> metadata = new HashMap<>();
            if (shouldRotateSoon(keyData.getSigningKey())) {
                metadata.put("rotation_recommended", true);
                metadata.put("rotation_reason", "Key approaching expiration or usage threshold");
            }

            return new KeyManagementResult(true, "Active key retrieved", 
                keyData.getSigningKey(), null, metadata);

        } catch (Exception e) {
            String errorMessage = "Failed to retrieve signing key: " + e.getMessage();
            keyAccessControlService.logSecurityEvent(getCurrentUsername(),
                KeyAccessControlService.KeyOperation.USE_KEY, null, errorMessage,
                com.certificateauthority.entity.ResultType.FAILURE, Map.of("algorithm", algorithm));
            
            return new KeyManagementResult(false, errorMessage, null, null, null);
        }
    }

    /**
     * Rotate keys for all algorithms or a specific algorithm.
     * 
     * @param algorithm Algorithm to rotate (null for all algorithms)
     * @param reason Reason for rotation
     * @param notes Additional notes
     * @return KeyManagementResult containing rotation summary
     */
    @PreAuthorize("hasRole('KEY_ADMIN')")
    @CacheEvict(value = "activeKeys", allEntries = true)
    public KeyManagementResult rotateKeys(String algorithm, String reason, String notes) {
        try {
            String username = getCurrentUsername();
            List<KeyRotationService.RotationResult> results = new ArrayList<>();
            
            if (algorithm != null) {
                // Rotate specific algorithm
                com.certificateauthority.entity.KeyRotationLog.RotationReason rotationReason = 
                    parseRotationReason(reason);
                
                List<KeyRotationService.RotationResult> algorithmResults = 
                    keyRotationService.rotateKeysByAlgorithm(algorithm, username, rotationReason);
                results.addAll(algorithmResults);
            } else {
                // Rotate all algorithms
                String[] algorithms = {"Ed25519", "ECDSA_P256", "RSA_3072"};
                for (String alg : algorithms) {
                    try {
                        com.certificateauthority.entity.KeyRotationLog.RotationReason rotationReason = 
                            parseRotationReason(reason);
                        
                        List<KeyRotationService.RotationResult> algorithmResults = 
                            keyRotationService.rotateKeysByAlgorithm(alg, username, rotationReason);
                        results.addAll(algorithmResults);
                    } catch (Exception e) {
                        // Continue with other algorithms if one fails
                    }
                }
            }

            // Summarize results
            long successful = results.stream().mapToLong(r -> r.isSuccess() ? 1 : 0).sum();
            long failed = results.size() - successful;
            
            Map<String, Object> summary = Map.of(
                "total_rotations", results.size(),
                "successful", successful,
                "failed", failed,
                "success_rate", results.isEmpty() ? 0.0 : (double) successful / results.size() * 100
            );

            String message = String.format("Rotation completed: %d successful, %d failed", 
                successful, failed);
            
            return new KeyManagementResult(failed == 0, message, null, null, summary);

        } catch (Exception e) {
            return new KeyManagementResult(false, "Rotation failed: " + e.getMessage(), 
                null, null, Map.of("error", e.getMessage()));
        }
    }

    /**
     * Validate integrity of a specific key or all keys.
     * 
     * @param keyId Key ID to validate (null for all keys)
     * @return KeyManagementResult containing validation results
     */
    @PreAuthorize("hasRole('KEY_ADMIN')")
    public KeyManagementResult validateKeyIntegrity(UUID keyId) {
        try {
            List<KeyIntegrityResult> results = new ArrayList<>();
            
            if (keyId != null) {
                // Validate specific key
                boolean isValid = keyStorageService.validateKeyIntegrity(keyId);
                Optional<SigningKey> keyOpt = signingKeyRepository.findById(keyId);
                
                if (keyOpt.isPresent()) {
                    results.add(new KeyIntegrityResult(keyOpt.get(), isValid, 
                        isValid ? "Key integrity verified" : "Key integrity check failed"));
                } else {
                    return new KeyManagementResult(false, "Key not found: " + keyId, null, null, null);
                }
            } else {
                // Validate all active keys
                List<SigningKey> activeKeys = signingKeyRepository.findByIsActiveTrue(
                    org.springframework.data.domain.PageRequest.of(0, 1000)).getContent();
                
                for (SigningKey key : activeKeys) {
                    boolean isValid = keyStorageService.validateKeyIntegrity(key.getId());
                    results.add(new KeyIntegrityResult(key, isValid,
                        isValid ? "Valid" : "Integrity check failed"));
                }
            }

            // Summarize results
            long validKeys = results.stream().mapToLong(r -> r.isValid() ? 1 : 0).sum();
            long invalidKeys = results.size() - validKeys;
            
            Map<String, Object> summary = Map.of(
                "total_keys_checked", results.size(),
                "valid_keys", validKeys,
                "invalid_keys", invalidKeys,
                "integrity_rate", results.isEmpty() ? 100.0 : (double) validKeys / results.size() * 100,
                "results", results
            );

            boolean allValid = invalidKeys == 0;
            String message = String.format("Integrity check completed: %d valid, %d invalid", 
                validKeys, invalidKeys);
            
            return new KeyManagementResult(allValid, message, null, null, summary);

        } catch (Exception e) {
            return new KeyManagementResult(false, "Integrity validation failed: " + e.getMessage(),
                null, null, Map.of("error", e.getMessage()));
        }
    }

    /**
     * Get comprehensive key management statistics.
     * 
     * @return KeyManagementResult containing statistics
     */
    @PreAuthorize("hasRole('KEY_ADMIN') or hasRole('KEY_VIEWER')")
    public KeyManagementResult getKeyStatistics() {
        try {
            // Get storage statistics
            List<Object[]> algorithmStats = keyStorageService.getKeyStatistics();
            
            // Get rotation statistics
            KeyRotationService.RotationStatistics rotationStats = 
                keyRotationService.getRotationStatistics();
            
            // Get security statistics
            KeyAccessControlService.SecurityStatistics securityStats = 
                keyAccessControlService.getSecurityStatistics();
            
            // Compile comprehensive statistics
            Map<String, Object> statistics = new HashMap<>();
            statistics.put("algorithm_statistics", algorithmStats);
            statistics.put("rotation_statistics", rotationStats);
            statistics.put("security_statistics", securityStats);
            statistics.put("generated_at", LocalDateTime.now());
            
            // Add key lifecycle summary
            long totalKeys = signingKeyRepository.count();
            long activeKeys = signingKeyRepository.countByIsActiveTrue();
            long expiredKeys = signingKeyRepository.countByIsActiveTrueAndExpiresAtBefore(LocalDateTime.now());
            
            Map<String, Object> lifecycleSummary = Map.of(
                "total_keys", totalKeys,
                "active_keys", activeKeys,
                "inactive_keys", totalKeys - activeKeys,
                "expired_keys", expiredKeys,
                "active_rate", totalKeys > 0 ? (double) activeKeys / totalKeys * 100 : 0
            );
            
            statistics.put("lifecycle_summary", lifecycleSummary);
            
            return new KeyManagementResult(true, "Statistics retrieved successfully", 
                null, null, statistics);

        } catch (Exception e) {
            return new KeyManagementResult(false, "Failed to retrieve statistics: " + e.getMessage(),
                null, null, Map.of("error", e.getMessage()));
        }
    }

    /**
     * Emergency key rotation for security incidents.
     * 
     * @param keyId Key to rotate immediately
     * @param incidentDetails Details of the security incident
     * @return KeyManagementResult containing rotation result
     */
    @PreAuthorize("hasRole('KEY_ADMIN') or hasRole('EMERGENCY_RESPONDER')")
    @CacheEvict(value = "activeKeys", allEntries = true)
    public KeyManagementResult emergencyKeyRotation(UUID keyId, String incidentDetails) {
        try {
            String username = getCurrentUsername();
            
            // Check for dual control requirement
            KeyAccessControlService.DualControlResult dualControlResult = 
                keyAccessControlService.requireDualApproval(
                    KeyAccessControlService.KeyOperation.EMERGENCY_ROTATE, keyId, username,
                    Map.of("incident_details", incidentDetails));
            
            if (dualControlResult.requiresApproval() && !dualControlResult.isApproved()) {
                return new KeyManagementResult(false, 
                    "Emergency rotation requires dual approval. Operation ID: " + dualControlResult.getOperationId(),
                    null, null, Map.of("operation_id", dualControlResult.getOperationId()));
            }

            // Perform emergency rotation
            KeyRotationService.RotationResult result = 
                keyRotationService.emergencyRotateKey(keyId, username, incidentDetails);
            
            // Complete dual control operation if it was required
            if (dualControlResult.requiresApproval()) {
                keyAccessControlService.completeDualControlOperation(
                    dualControlResult.getOperationId(), result.isSuccess());
            }

            Map<String, Object> metadata = Map.of(
                "emergency_rotation", true,
                "incident_details", incidentDetails,
                "old_key_id", result.getOldKey() != null ? result.getOldKey().getId() : null,
                "new_key_id", result.getNewKey() != null ? result.getNewKey().getId() : null
            );

            return new KeyManagementResult(result.isSuccess(), result.getMessage(),
                result.getNewKey(), null, metadata);

        } catch (Exception e) {
            return new KeyManagementResult(false, "Emergency rotation failed: " + e.getMessage(),
                null, null, Map.of("error", e.getMessage()));
        }
    }

    /**
     * Asynchronously check and rotate keys that need rotation.
     * 
     * @return CompletableFuture indicating completion
     */
    public CompletableFuture<Void> performScheduledMaintenance() {
        return CompletableFuture.runAsync(() -> {
            try {
                if (autoRotationEnabled) {
                    // This will trigger the scheduled rotation in KeyRotationService
                    keyRotationService.scheduledKeyRotation();
                }
                
                // Clean up expired dual control operations
                cleanupExpiredDualControlOperations();
                
            } catch (Exception e) {
                System.err.println("Scheduled maintenance failed: " + e.getMessage());
            }
        });
    }

    // ==================== Private Helper Methods ====================

    private String getCurrentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "system";
    }

    private String generateKeyIdentifier(String algorithm) {
        String timestamp = String.valueOf(System.currentTimeMillis());
        String randomSuffix = UUID.randomUUID().toString().substring(0, 8);
        return algorithm.toLowerCase() + "-" + timestamp + "-" + randomSuffix;
    }

    private boolean shouldRotateSoon(SigningKey key) {
        if (key.getExpiresAt() != null) {
            long daysToExpiration = java.time.temporal.ChronoUnit.DAYS.between(
                LocalDateTime.now(), key.getExpiresAt());
            if (daysToExpiration <= 7) return true;
        }
        
        // Check usage threshold (80% of limit)
        return key.getUsageCount() >= 8000; // Assuming 10000 is the threshold
    }

    private com.certificateauthority.entity.KeyRotationLog.RotationReason parseRotationReason(String reason) {
        if (reason == null) return com.certificateauthority.entity.KeyRotationLog.RotationReason.ADMINISTRATOR_REQUEST;
        
        return switch (reason.toUpperCase()) {
            case "TIME_BASED" -> com.certificateauthority.entity.KeyRotationLog.RotationReason.TIME_BASED;
            case "USAGE_BASED" -> com.certificateauthority.entity.KeyRotationLog.RotationReason.USAGE_BASED;
            case "SECURITY_INCIDENT" -> com.certificateauthority.entity.KeyRotationLog.RotationReason.SECURITY_INCIDENT;
            case "COMPLIANCE" -> com.certificateauthority.entity.KeyRotationLog.RotationReason.COMPLIANCE_REQUIREMENT;
            case "MAINTENANCE" -> com.certificateauthority.entity.KeyRotationLog.RotationReason.MAINTENANCE;
            default -> com.certificateauthority.entity.KeyRotationLog.RotationReason.ADMINISTRATOR_REQUEST;
        };
    }

    private void cleanupExpiredDualControlOperations() {
        // This would be implemented to clean up expired operations
        // For now, it's handled in KeyAccessControlService
    }

    // ==================== Result Classes ====================

    /**
     * Result of key management operations.
     */
    public static class KeyManagementResult {
        private final boolean success;
        private final String message;
        private final SigningKey signingKey;
        private final KeyGenerationService.KeyPairResult keyPair;
        private final Map<String, Object> metadata;

        public KeyManagementResult(boolean success, String message, SigningKey signingKey,
                                 KeyGenerationService.KeyPairResult keyPair, Map<String, Object> metadata) {
            this.success = success;
            this.message = message;
            this.signingKey = signingKey;
            this.keyPair = keyPair;
            this.metadata = metadata != null ? metadata : new HashMap<>();
        }

        // Getters
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public SigningKey getSigningKey() { return signingKey; }
        public KeyGenerationService.KeyPairResult getKeyPair() { return keyPair; }
        public Map<String, Object> getMetadata() { return metadata; }
        
        // Helper methods
        public boolean hasSigningKey() { return signingKey != null; }
        public boolean hasKeyPair() { return keyPair != null; }
        public Object getMetadata(String key) { return metadata.get(key); }
    }

    /**
     * Result of key integrity validation.
     */
    public static class KeyIntegrityResult {
        private final SigningKey key;
        private final boolean valid;
        private final String message;

        public KeyIntegrityResult(SigningKey key, boolean valid, String message) {
            this.key = key;
            this.valid = valid;
            this.message = message;
        }

        public SigningKey getKey() { return key; }
        public boolean isValid() { return valid; }
        public String getMessage() { return message; }
    }
}


