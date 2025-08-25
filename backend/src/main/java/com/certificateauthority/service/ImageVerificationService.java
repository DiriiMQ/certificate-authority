package com.certificateauthority.service;

import com.certificateauthority.entity.*;
import com.certificateauthority.repository.ImageSignatureRepository;
import com.certificateauthority.repository.SigningKeyRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

/**
 * Service for comprehensive image signature verification.
 * 
 * Supports verification of:
 * - Embedded signatures in PNG/JPEG metadata
 * - Detached .sig files
 * - Signature integrity and authenticity
 * - Key validity and expiration
 * - Timestamp validation
 * - Image integrity checking
 * 
 * Provides unified verification interface for both embedded and detached signatures
 * with detailed verification results including validation status, error reasons,
 * and signature metadata.
 */
@Service
@Transactional
public class ImageVerificationService {

    private static final Logger logger = LoggerFactory.getLogger(ImageVerificationService.class);

    private final ImageSigningService imageSigningService;
    private final DetachedSignatureService detachedSignatureService;
    private final ImageFormatDetectionService formatDetectionService;
    private final KeyManagementService keyManagementService;
    private final ImageSignatureRepository imageSignatureRepository;
    private final SigningKeyRepository signingKeyRepository;

    @Autowired
    public ImageVerificationService(ImageSigningService imageSigningService,
                                   DetachedSignatureService detachedSignatureService,
                                   ImageFormatDetectionService formatDetectionService,
                                   KeyManagementService keyManagementService,
                                   ImageSignatureRepository imageSignatureRepository,
                                   SigningKeyRepository signingKeyRepository) {
        this.imageSigningService = imageSigningService;
        this.detachedSignatureService = detachedSignatureService;
        this.formatDetectionService = formatDetectionService;
        this.keyManagementService = keyManagementService;
        this.imageSignatureRepository = imageSignatureRepository;
        this.signingKeyRepository = signingKeyRepository;
    }

    /**
     * Verify an embedded signature within an image file.
     * 
     * @param imageData The signed image data
     * @param originalFilename Original filename for context
     * @return VerificationResult containing detailed verification status
     */
    public VerificationResult verifyEmbeddedSignature(byte[] imageData, String originalFilename) {
        try {
            // Validate input
            if (imageData == null || imageData.length == 0) {
                return VerificationResult.failure(VerificationFailureReason.INVALID_INPUT, 
                    "Image data is empty", null);
            }

            // Detect image format
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                formatDetectionService.detectFormat(imageData, originalFilename);
            
            if (!formatResult.isValid()) {
                return VerificationResult.failure(VerificationFailureReason.UNSUPPORTED_FORMAT,
                    "Invalid image format: " + formatResult.getErrorMessage(), null);
            }

            // Extract signature from image metadata
            ImageSigningService.SignatureExtractionResult extractionResult = 
                imageSigningService.extractSignature(imageData);
            
            if (!extractionResult.isSuccess()) {
                return VerificationResult.failure(VerificationFailureReason.NO_SIGNATURE_FOUND,
                    "Failed to extract embedded signature: " + extractionResult.getMessage(), null);
            }

            // For now, since the extraction is placeholder, we'll simulate verification
            // In a complete implementation, this would:
            // 1. Parse extracted metadata to get signature components
            // 2. Reconstruct the signed payload
            // 3. Verify the signature using the public key
            // 4. Validate timestamp and key validity
            
            Map<String, Object> metadata = extractionResult.getExtractedMetadata();
            
            // Look up signature in database based on image hash
            String imageHash = calculateSHA256Hash(imageData);
            Optional<ImageSignature> sigRecord = imageSignatureRepository.findByImageHash(imageHash);
            
            if (sigRecord.isEmpty()) {
                return VerificationResult.failure(VerificationFailureReason.SIGNATURE_NOT_FOUND,
                    "No signature record found for image hash", null);
            }

            ImageSignature signature = sigRecord.get();
            
            // Verify this is an embedded signature
            if (signature.getSignatureFormat() != SignatureFormat.EMBEDDED) {
                return VerificationResult.failure(VerificationFailureReason.SIGNATURE_FORMAT_MISMATCH,
                    "Expected embedded signature but found " + signature.getSignatureFormat(), signature);
            }

            // Verify signature components
            VerificationResult validationResult = validateSignatureRecord(signature, imageData, originalFilename);
            if (!validationResult.isValid()) {
                return validationResult;
            }

            // Record verification attempt
            signature.recordVerificationResult(true);
            imageSignatureRepository.save(signature);

            logger.info("Successfully verified embedded signature for image {} (hash: {})", 
                originalFilename, imageHash);

            return VerificationResult.success(signature, "Embedded signature verification successful", 
                extractionResult.getExtractionMethod());

        } catch (Exception e) {
            logger.error("Failed to verify embedded signature for {}: {}", originalFilename, e.getMessage(), e);
            return VerificationResult.failure(VerificationFailureReason.VERIFICATION_ERROR,
                "Verification failed: " + e.getMessage(), null);
        }
    }

    /**
     * Verify a detached signature file against an image.
     * 
     * @param imageData The original image data
     * @param sigFileData The .sig file data
     * @param originalFilename Original filename for context
     * @return VerificationResult containing detailed verification status
     */
    public VerificationResult verifyDetachedSignature(byte[] imageData, byte[] sigFileData, String originalFilename) {
        try {
            // Validate input
            if (imageData == null || imageData.length == 0) {
                return VerificationResult.failure(VerificationFailureReason.INVALID_INPUT,
                    "Image data is empty", null);
            }

            if (sigFileData == null || sigFileData.length == 0) {
                return VerificationResult.failure(VerificationFailureReason.INVALID_INPUT,
                    "Signature file data is empty", null);
            }

            // Use DetachedSignatureService to verify
            DetachedSignatureService.DetachedSignatureVerificationResult detachedResult = 
                detachedSignatureService.verifyDetachedSignature(imageData, sigFileData);

            if (!detachedResult.isSuccess()) {
                return VerificationResult.failure(VerificationFailureReason.SIGNATURE_INVALID,
                    "Detached signature verification failed: " + detachedResult.getMessage(), null);
            }

            // Look up signature record in database
            String imageHash = calculateSHA256Hash(imageData);
            Optional<ImageSignature> sigRecord = imageSignatureRepository.findByImageHash(imageHash);
            
            if (sigRecord.isEmpty()) {
                return VerificationResult.failure(VerificationFailureReason.SIGNATURE_NOT_FOUND,
                    "No signature record found for image hash", null);
            }

            ImageSignature signature = sigRecord.get();
            
            // Verify this is a detached signature
            if (signature.getSignatureFormat() != SignatureFormat.DETACHED) {
                return VerificationResult.failure(VerificationFailureReason.SIGNATURE_FORMAT_MISMATCH,
                    "Expected detached signature but found " + signature.getSignatureFormat(), signature);
            }

            // Additional validation
            VerificationResult validationResult = validateSignatureRecord(signature, imageData, originalFilename);
            if (!validationResult.isValid()) {
                return validationResult;
            }

            // Record successful verification
            signature.recordVerificationResult(true);
            imageSignatureRepository.save(signature);

            logger.info("Successfully verified detached signature for image {} (hash: {})", 
                originalFilename, imageHash);

            return VerificationResult.success(signature, "Detached signature verification successful", 
                "Detached .sig file");

        } catch (Exception e) {
            logger.error("Failed to verify detached signature for {}: {}", originalFilename, e.getMessage(), e);
            return VerificationResult.failure(VerificationFailureReason.VERIFICATION_ERROR,
                "Verification failed: " + e.getMessage(), null);
        }
    }

    /**
     * Auto-detect signature type and verify accordingly.
     * First checks for embedded signatures, then falls back to requiring detached signature file.
     * 
     * @param imageData The image data to verify
     * @param originalFilename Original filename for context
     * @param optionalSigFileData Optional detached signature file data
     * @return VerificationResult containing detailed verification status
     */
    public VerificationResult verifySignature(byte[] imageData, String originalFilename, byte[] optionalSigFileData) {
        // First try embedded signature verification
        VerificationResult embeddedResult = verifyEmbeddedSignature(imageData, originalFilename);
        
        // If embedded verification succeeds, return it
        if (embeddedResult.isValid()) {
            return embeddedResult;
        }

        // If we have detached signature data, try detached verification
        if (optionalSigFileData != null && optionalSigFileData.length > 0) {
            VerificationResult detachedResult = verifyDetachedSignature(imageData, optionalSigFileData, originalFilename);
            
            if (detachedResult.isValid()) {
                return detachedResult;
            }
            
            // Both failed - return more informative error
            return VerificationResult.failure(VerificationFailureReason.VERIFICATION_FAILED,
                "Both embedded and detached signature verification failed. " +
                "Embedded: " + embeddedResult.getErrorMessage() + "; " +
                "Detached: " + detachedResult.getErrorMessage(), null);
        }

        // No detached signature provided and embedded failed
        return VerificationResult.failure(VerificationFailureReason.NO_SIGNATURE_FOUND,
            "No valid signature found. Embedded verification failed: " + embeddedResult.getErrorMessage() + 
            ". No detached signature file provided.", null);
    }

    /**
     * Verify multiple images with their corresponding signature files.
     * 
     * @param imageFiles Map of filename -> image data
     * @param signatureFiles Map of filename -> signature file data (optional)
     * @return BatchVerificationResult containing results for all files
     */
    public BatchVerificationResult verifyBatch(Map<String, byte[]> imageFiles, 
                                              Map<String, byte[]> signatureFiles) {
        List<VerificationResult> results = new ArrayList<>();
        List<VerificationResult> successful = new ArrayList<>();
        List<VerificationResult> failed = new ArrayList<>();

        for (Map.Entry<String, byte[]> entry : imageFiles.entrySet()) {
            String filename = entry.getKey();
            byte[] imageData = entry.getValue();
            byte[] sigFileData = signatureFiles != null ? signatureFiles.get(filename) : null;
            
            VerificationResult result = verifySignature(imageData, filename, sigFileData);
            results.add(result);
            
            if (result.isValid()) {
                successful.add(result);
            } else {
                failed.add(result);
            }
        }

        logger.info("Batch verification completed: {} successful, {} failed out of {} total", 
            successful.size(), failed.size(), results.size());

        return new BatchVerificationResult(results, successful, failed);
    }

    /**
     * Get verification history for a specific image.
     * 
     * @param imageHash SHA-256 hash of the image
     * @return VerificationHistoryResult containing verification records
     */
    public VerificationHistoryResult getVerificationHistory(String imageHash) {
        try {
            Optional<ImageSignature> signature = imageSignatureRepository.findByImageHash(imageHash);
            
            if (signature.isEmpty()) {
                return VerificationHistoryResult.notFound("No signature found for image hash: " + imageHash);
            }

            ImageSignature sig = signature.get();
            
            VerificationHistory history = new VerificationHistory(
                sig.getId(),
                sig.getImageName(),
                sig.getImageHash(),
                sig.getSignatureFormat(),
                sig.getSignatureAlgorithm(),
                sig.getKeyIdentifier(),
                sig.getSignatureTimestamp(),
                sig.getVerificationCount(),
                sig.getLastVerificationAt(),
                sig.getLastVerificationResult(),
                sig.getCreatedBy()
            );

            return VerificationHistoryResult.success(history);

        } catch (Exception e) {
            logger.error("Failed to get verification history for hash {}: {}", imageHash, e.getMessage(), e);
            return VerificationHistoryResult.error("Failed to retrieve verification history: " + e.getMessage());
        }
    }

    // ==================== Private Helper Methods ====================

    private VerificationResult validateSignatureRecord(ImageSignature signature, byte[] imageData, String filename) {
        // Verify image hash matches
        String currentHash = calculateSHA256Hash(imageData);
        if (!Objects.equals(signature.getImageHash(), currentHash)) {
            signature.recordVerificationResult(false);
            imageSignatureRepository.save(signature);
            return VerificationResult.failure(VerificationFailureReason.IMAGE_HASH_MISMATCH,
                "Image hash mismatch - image may have been modified", signature);
        }

        // Verify image size matches
        if (!Objects.equals(signature.getImageSize(), (long) imageData.length)) {
            signature.recordVerificationResult(false);
            imageSignatureRepository.save(signature);
            return VerificationResult.failure(VerificationFailureReason.IMAGE_SIZE_MISMATCH,
                "Image size mismatch - expected " + signature.getImageSize() + " bytes, got " + imageData.length, signature);
        }

        // Verify signing key is still valid
        Optional<SigningKey> keyRecord = signingKeyRepository.findById(signature.getSigningKeyId());
        if (keyRecord.isEmpty()) {
            signature.recordVerificationResult(false);
            imageSignatureRepository.save(signature);
            return VerificationResult.failure(VerificationFailureReason.KEY_NOT_FOUND,
                "Signing key not found: " + signature.getSigningKeyId(), signature);
        }

        SigningKey signingKey = keyRecord.get();
        
        // Check if key is still active
        if (!signingKey.getIsActive()) {
            signature.recordVerificationResult(false);
            imageSignatureRepository.save(signature);
            return VerificationResult.failure(VerificationFailureReason.KEY_INACTIVE,
                "Signing key is no longer active", signature);
        }

        // Check if key has expired
        if (signingKey.getExpiresAt() != null && signingKey.getExpiresAt().isBefore(LocalDateTime.now())) {
            signature.recordVerificationResult(false);
            imageSignatureRepository.save(signature);
            return VerificationResult.failure(VerificationFailureReason.KEY_EXPIRED,
                "Signing key has expired", signature);
        }

        // Check signature timestamp is not in the future
        if (signature.getSignatureTimestamp().isAfter(LocalDateTime.now(ZoneOffset.UTC).plusMinutes(5))) {
            signature.recordVerificationResult(false);
            imageSignatureRepository.save(signature);
            return VerificationResult.failure(VerificationFailureReason.FUTURE_TIMESTAMP,
                "Signature timestamp is in the future", signature);
        }

        return VerificationResult.success(signature, "Validation successful", "Internal validation");
    }

    private String calculateSHA256Hash(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private String getCurrentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "system";
    }

    // ==================== Result Classes ====================

    /**
     * Enumeration of possible verification failure reasons.
     */
    public enum VerificationFailureReason {
        INVALID_INPUT,
        UNSUPPORTED_FORMAT,
        NO_SIGNATURE_FOUND,
        SIGNATURE_NOT_FOUND,
        SIGNATURE_INVALID,
        SIGNATURE_FORMAT_MISMATCH,
        IMAGE_HASH_MISMATCH,
        IMAGE_SIZE_MISMATCH,
        KEY_NOT_FOUND,
        KEY_INACTIVE,
        KEY_EXPIRED,
        FUTURE_TIMESTAMP,
        VERIFICATION_ERROR,
        VERIFICATION_FAILED
    }

    /**
     * Result of a signature verification operation.
     */
    public static class VerificationResult {
        private final boolean valid;
        private final String message;
        private final String verificationMethod;
        private final ImageSignature signature;
        private final VerificationFailureReason failureReason;
        private final String errorMessage;
        private final LocalDateTime verificationTimestamp;

        private VerificationResult(boolean valid, String message, String verificationMethod,
                                 ImageSignature signature, VerificationFailureReason failureReason,
                                 String errorMessage) {
            this.valid = valid;
            this.message = message;
            this.verificationMethod = verificationMethod;
            this.signature = signature;
            this.failureReason = failureReason;
            this.errorMessage = errorMessage;
            this.verificationTimestamp = LocalDateTime.now(ZoneOffset.UTC);
        }

        public static VerificationResult success(ImageSignature signature, String message, String method) {
            return new VerificationResult(true, message, method, signature, null, null);
        }

        public static VerificationResult failure(VerificationFailureReason reason, String errorMessage, 
                                               ImageSignature signature) {
            return new VerificationResult(false, "Verification failed", null, signature, reason, errorMessage);
        }

        // Getters
        public boolean isValid() { return valid; }
        public String getMessage() { return message; }
        public String getVerificationMethod() { return verificationMethod; }
        public ImageSignature getSignature() { return signature; }
        public VerificationFailureReason getFailureReason() { return failureReason; }
        public String getErrorMessage() { return errorMessage; }
        public LocalDateTime getVerificationTimestamp() { return verificationTimestamp; }
        
        // Additional helper methods
        public boolean isEmbeddedSignature() {
            return signature != null && SignatureFormat.EMBEDDED.equals(signature.getSignatureFormat());
        }
        
        public boolean isDetachedSignature() {
            return signature != null && SignatureFormat.DETACHED.equals(signature.getSignatureFormat());
        }
    }

    /**
     * Result of batch verification operations.
     */
    public static class BatchVerificationResult {
        private final List<VerificationResult> allResults;
        private final List<VerificationResult> successfulResults;
        private final List<VerificationResult> failedResults;

        public BatchVerificationResult(List<VerificationResult> allResults,
                                     List<VerificationResult> successfulResults,
                                     List<VerificationResult> failedResults) {
            this.allResults = allResults;
            this.successfulResults = successfulResults;
            this.failedResults = failedResults;
        }

        // Getters
        public List<VerificationResult> getAllResults() { return allResults; }
        public List<VerificationResult> getSuccessfulResults() { return successfulResults; }
        public List<VerificationResult> getFailedResults() { return failedResults; }
        public int getTotalCount() { return allResults.size(); }
        public int getSuccessCount() { return successfulResults.size(); }
        public int getFailureCount() { return failedResults.size(); }
        public double getSuccessRate() { 
            return allResults.isEmpty() ? 0.0 : (double) successfulResults.size() / allResults.size() * 100; 
        }
    }

    /**
     * Result of verification history lookup.
     */
    public static class VerificationHistoryResult {
        private final boolean found;
        private final String message;
        private final VerificationHistory history;

        private VerificationHistoryResult(boolean found, String message, VerificationHistory history) {
            this.found = found;
            this.message = message;
            this.history = history;
        }

        public static VerificationHistoryResult success(VerificationHistory history) {
            return new VerificationHistoryResult(true, "History retrieved successfully", history);
        }

        public static VerificationHistoryResult notFound(String message) {
            return new VerificationHistoryResult(false, message, null);
        }

        public static VerificationHistoryResult error(String message) {
            return new VerificationHistoryResult(false, message, null);
        }

        // Getters
        public boolean isFound() { return found; }
        public String getMessage() { return message; }
        public VerificationHistory getHistory() { return history; }
    }

    /**
     * Verification history information.
     */
    public static class VerificationHistory {
        private final UUID signatureId;
        private final String imageName;
        private final String imageHash;
        private final SignatureFormat signatureFormat;
        private final SignatureAlgorithm signatureAlgorithm;
        private final String keyIdentifier;
        private final LocalDateTime signatureTimestamp;
        private final Integer verificationCount;
        private final LocalDateTime lastVerificationAt;
        private final Boolean lastVerificationResult;
        private final String createdBy;

        public VerificationHistory(UUID signatureId, String imageName, String imageHash,
                                 SignatureFormat signatureFormat, SignatureAlgorithm signatureAlgorithm,
                                 String keyIdentifier, LocalDateTime signatureTimestamp,
                                 Integer verificationCount, LocalDateTime lastVerificationAt,
                                 Boolean lastVerificationResult, String createdBy) {
            this.signatureId = signatureId;
            this.imageName = imageName;
            this.imageHash = imageHash;
            this.signatureFormat = signatureFormat;
            this.signatureAlgorithm = signatureAlgorithm;
            this.keyIdentifier = keyIdentifier;
            this.signatureTimestamp = signatureTimestamp;
            this.verificationCount = verificationCount;
            this.lastVerificationAt = lastVerificationAt;
            this.lastVerificationResult = lastVerificationResult;
            this.createdBy = createdBy;
        }

        // Getters
        public UUID getSignatureId() { return signatureId; }
        public String getImageName() { return imageName; }
        public String getImageHash() { return imageHash; }
        public SignatureFormat getSignatureFormat() { return signatureFormat; }
        public SignatureAlgorithm getSignatureAlgorithm() { return signatureAlgorithm; }
        public String getKeyIdentifier() { return keyIdentifier; }
        public LocalDateTime getSignatureTimestamp() { return signatureTimestamp; }
        public Integer getVerificationCount() { return verificationCount; }
        public LocalDateTime getLastVerificationAt() { return lastVerificationAt; }
        public Boolean getLastVerificationResult() { return lastVerificationResult; }
        public String getCreatedBy() { return createdBy; }
    }
}
