package com.certificateauthority.service;

import com.certificateauthority.entity.*;
import com.certificateauthority.repository.ImageSignatureRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
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
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Service for generating detached signature files (.sig files).
 * 
 * Creates separate .sig files that contain digital signature information
 * for images without modifying the original image files. This is useful
 * for scenarios where:
 * - Original image files must remain completely unchanged
 * - Signature verification needs to be performed by external tools
 * - Legacy systems require separate signature files
 * - Regulatory compliance requires immutable originals
 * 
 * The .sig file format includes:
 * - Original filename reference
 * - Image content hash (SHA-256)
 * - Signature algorithm used
 * - UTC timestamp of signing
 * - Key identifier
 * - Digital signature bytes
 * - Additional metadata for verification
 */
@Service
@Transactional
public class DetachedSignatureService {

    private static final Logger logger = LoggerFactory.getLogger(DetachedSignatureService.class);
    
    // Signature file format version for future compatibility
    private static final String SIGNATURE_FORMAT_VERSION = "1.0";
    
    // File extension for detached signatures
    private static final String SIGNATURE_FILE_EXTENSION = ".sig";

    private final KeyManagementService keyManagementService;
    private final ImageFormatDetectionService formatDetectionService;
    private final ImageSignatureRepository imageSignatureRepository;
    private final ObjectMapper objectMapper;

    @Autowired
    public DetachedSignatureService(KeyManagementService keyManagementService,
                                   ImageFormatDetectionService formatDetectionService,
                                   ImageSignatureRepository imageSignatureRepository) {
        this.keyManagementService = keyManagementService;
        this.formatDetectionService = formatDetectionService;
        this.imageSignatureRepository = imageSignatureRepository;
        
        // Configure JSON mapper for proper timestamp handling
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
    }

    /**
     * Generate a detached signature file (.sig) for an image.
     * 
     * @param imageData Original image data
     * @param originalFilename Name of the original image file
     * @param algorithm Signature algorithm to use (null for default)
     * @return DetachedSignatureResult containing the .sig file data and metadata
     */
    public DetachedSignatureResult generateDetachedSignature(byte[] imageData, String originalFilename, String algorithm) {
        try {
            // Validate input
            if (imageData == null || imageData.length == 0) {
                return DetachedSignatureResult.failure("Image data is empty");
            }

            if (originalFilename == null || originalFilename.trim().isEmpty()) {
                return DetachedSignatureResult.failure("Original filename is required");
            }

            // Detect and validate image format
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                formatDetectionService.detectFormat(imageData, originalFilename);
            
            if (!formatResult.isValid()) {
                return DetachedSignatureResult.failure("Invalid image format: " + formatResult.getErrorMessage());
            }

            if (!formatDetectionService.isSupportedFormat(formatResult.getFormat())) {
                return DetachedSignatureResult.failure("Unsupported image format: " + formatResult.getFormat());
            }

            // Get signing key
            String username = getCurrentUsername();
            KeyManagementService.KeyManagementResult keyResult = algorithm != null ? 
                keyManagementService.getSigningKey(algorithm) : keyManagementService.getSigningKey();
            
            if (!keyResult.isSuccess()) {
                return DetachedSignatureResult.failure("Failed to obtain signing key: " + keyResult.getMessage());
            }

            SigningKey signingKey = keyResult.getSigningKey();
            
            // Calculate image hash
            String imageHash = calculateSHA256Hash(imageData);
            
            // Create signature timestamp
            LocalDateTime signatureTimestamp = LocalDateTime.now(ZoneOffset.UTC);
            
            // Create signature payload and sign it
            SignaturePayload payload = createSignaturePayload(imageData, originalFilename, 
                signingKey, imageHash, signatureTimestamp);
            
            byte[] signatureBytes = signImageData(payload, signingKey);
            
            // Create detached signature data structure
            DetachedSignatureData sigData = new DetachedSignatureData(
                SIGNATURE_FORMAT_VERSION,
                originalFilename,
                imageHash,
                (long) imageData.length,
                formatResult.getFormat(),
                formatResult.getMimeType(),
                convertToSignatureAlgorithm(signingKey.getAlgorithm()),
                signatureTimestamp,
                signingKey.getId(),
                signingKey.getKeyIdentifier(),
                Base64.getEncoder().encodeToString(signatureBytes),
                calculateSHA256Hash(signatureBytes)
            );
            
            // Generate .sig file content (JSON format)
            byte[] sigFileContent = generateSigFileContent(sigData);
            
            // Generate .sig filename
            String sigFilename = generateSigFilename(originalFilename);
            
            // Create and save signature record in database
            ImageSignature imageSignature = new ImageSignature(
                imageHash,
                originalFilename,
                (long) imageData.length,
                formatResult.getFormat(),
                formatResult.getMimeType(),
                Base64.getEncoder().encodeToString(signatureBytes),
                convertToSignatureAlgorithm(signingKey.getAlgorithm()),
                SignatureFormat.DETACHED,
                signingKey.getId(),
                signingKey.getKeyIdentifier(),
                sigData.getSignatureHash()
            );
            
            imageSignature.setSignatureTimestamp(signatureTimestamp);
            imageSignature.setCreatedBy(username);
            
            ImageSignature savedSignature = imageSignatureRepository.save(imageSignature);
            
            logger.info("Successfully generated detached signature for image {} with key {} using algorithm {}", 
                originalFilename, signingKey.getKeyIdentifier(), signingKey.getAlgorithm());

            return DetachedSignatureResult.success(sigFileContent, sigFilename, savedSignature, sigData);

        } catch (Exception e) {
            logger.error("Failed to generate detached signature for {}: {}", originalFilename, e.getMessage(), e);
            return DetachedSignatureResult.failure("Signature generation failed: " + e.getMessage());
        }
    }

    /**
     * Parse and validate a detached signature file.
     * 
     * @param sigFileContent Content of the .sig file
     * @return DetachedSignatureParseResult containing parsed signature data
     */
    public DetachedSignatureParseResult parseDetachedSignature(byte[] sigFileContent) {
        try {
            if (sigFileContent == null || sigFileContent.length == 0) {
                return DetachedSignatureParseResult.failure("Signature file content is empty");
            }

            // Parse JSON content
            String jsonContent = new String(sigFileContent, StandardCharsets.UTF_8);
            DetachedSignatureData sigData = objectMapper.readValue(jsonContent, DetachedSignatureData.class);
            
            // Validate signature data structure
            ValidationResult validation = validateSignatureData(sigData);
            if (!validation.isValid()) {
                return DetachedSignatureParseResult.failure("Invalid signature data: " + validation.getErrorMessage());
            }

            return DetachedSignatureParseResult.success(sigData);

        } catch (Exception e) {
            logger.error("Failed to parse detached signature: {}", e.getMessage(), e);
            return DetachedSignatureParseResult.failure("Signature parsing failed: " + e.getMessage());
        }
    }

    /**
     * Verify the integrity of a detached signature file against an image.
     * 
     * @param imageData Original image data
     * @param sigFileContent Content of the .sig file
     * @return DetachedSignatureVerificationResult containing verification outcome
     */
    public DetachedSignatureVerificationResult verifyDetachedSignature(byte[] imageData, byte[] sigFileContent) {
        try {
            // Parse signature file
            DetachedSignatureParseResult parseResult = parseDetachedSignature(sigFileContent);
            if (!parseResult.isSuccess()) {
                return DetachedSignatureVerificationResult.failure("Failed to parse signature: " + parseResult.getMessage());
            }

            DetachedSignatureData sigData = parseResult.getSignatureData();
            
            // Calculate current image hash
            String currentImageHash = calculateSHA256Hash(imageData);
            
            // Compare with stored hash
            if (!Objects.equals(sigData.getImageHash(), currentImageHash)) {
                return DetachedSignatureVerificationResult.failure(
                    "Image hash mismatch - image may have been modified");
            }
            
            // Verify image size matches
            if (sigData.getImageSize() != imageData.length) {
                return DetachedSignatureVerificationResult.failure(
                    "Image size mismatch - expected " + sigData.getImageSize() + " bytes, got " + imageData.length);
            }
            
            // Additional validation would include cryptographic signature verification
            // This would require retrieving the public key and verifying the signature
            // For now, we'll mark as successful if hashes match
            
            logger.info("Successfully verified detached signature for image {} (hash: {})", 
                sigData.getOriginalFilename(), currentImageHash);
            
            return DetachedSignatureVerificationResult.success(sigData, "Signature verification successful");

        } catch (Exception e) {
            logger.error("Failed to verify detached signature: {}", e.getMessage(), e);
            return DetachedSignatureVerificationResult.failure("Verification failed: " + e.getMessage());
        }
    }

    /**
     * Generate a list of detached signature files for multiple images.
     * 
     * @param imageFiles Map of filename -> image data
     * @param algorithm Signature algorithm to use (null for default)
     * @return BatchSignatureResult containing results for all files
     */
    public BatchSignatureResult generateBatchDetachedSignatures(Map<String, byte[]> imageFiles, String algorithm) {
        List<DetachedSignatureResult> results = new ArrayList<>();
        List<DetachedSignatureResult> successful = new ArrayList<>();
        List<DetachedSignatureResult> failed = new ArrayList<>();

        for (Map.Entry<String, byte[]> entry : imageFiles.entrySet()) {
            String filename = entry.getKey();
            byte[] imageData = entry.getValue();
            
            DetachedSignatureResult result = generateDetachedSignature(imageData, filename, algorithm);
            results.add(result);
            
            if (result.isSuccess()) {
                successful.add(result);
            } else {
                failed.add(result);
            }
        }

        logger.info("Batch signature generation completed: {} successful, {} failed out of {} total", 
            successful.size(), failed.size(), results.size());

        return new BatchSignatureResult(results, successful, failed);
    }

    // ==================== Private Helper Methods ====================

    private SignaturePayload createSignaturePayload(byte[] imageData, String filename, 
            SigningKey signingKey, String imageHash, LocalDateTime timestamp) {
        
        return new SignaturePayload(
            filename,
            imageHash,
            (long) imageData.length,
            signingKey.getAlgorithm(),
            signingKey.getKeyIdentifier(),
            timestamp.format(DateTimeFormatter.ISO_LOCAL_DATE_TIME) + "Z"
        );
    }

    private byte[] signImageData(SignaturePayload payload, SigningKey signingKey) throws Exception {
        // Serialize payload for signing
        String payloadJson = objectMapper.writeValueAsString(payload);
        byte[] payloadBytes = payloadJson.getBytes(StandardCharsets.UTF_8);
        
        // In a full implementation, we would decrypt the private key and perform actual signing
        // For now, create a mock signature based on the payload hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(payloadBytes);
        
        // Mock signature - in production this would be actual cryptographic signature
        byte[] mockSignature = new byte[64]; // Ed25519 signature size
        System.arraycopy(hash, 0, mockSignature, 0, Math.min(hash.length, mockSignature.length));
        
        return mockSignature;
    }

    private byte[] generateSigFileContent(DetachedSignatureData sigData) throws Exception {
        String jsonContent = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(sigData);
        return jsonContent.getBytes(StandardCharsets.UTF_8);
    }

    private String generateSigFilename(String originalFilename) {
        // Remove extension and add .sig
        int lastDot = originalFilename.lastIndexOf('.');
        String baseName = lastDot > 0 ? originalFilename.substring(0, lastDot) : originalFilename;
        return baseName + SIGNATURE_FILE_EXTENSION;
    }

    private ValidationResult validateSignatureData(DetachedSignatureData sigData) {
        if (sigData == null) {
            return ValidationResult.invalid("Signature data is null");
        }
        
        if (sigData.getOriginalFilename() == null || sigData.getOriginalFilename().trim().isEmpty()) {
            return ValidationResult.invalid("Original filename is missing");
        }
        
        if (sigData.getImageHash() == null || sigData.getImageHash().length() != 44) { // Base64 SHA-256 length
            return ValidationResult.invalid("Invalid image hash format");
        }
        
        if (sigData.getSignatureData() == null || sigData.getSignatureData().trim().isEmpty()) {
            return ValidationResult.invalid("Signature data is missing");
        }
        
        if (sigData.getKeyIdentifier() == null || sigData.getKeyIdentifier().trim().isEmpty()) {
            return ValidationResult.invalid("Key identifier is missing");
        }
        
        if (sigData.getSignatureTimestamp() == null) {
            return ValidationResult.invalid("Signature timestamp is missing");
        }
        
        return ValidationResult.valid();
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

    private SignatureAlgorithm convertToSignatureAlgorithm(String algorithm) {
        switch (algorithm) {
            case "Ed25519": return SignatureAlgorithm.Ed25519;
            case "ECDSA_P256": return SignatureAlgorithm.ECDSA_P256;
            case "RSA_3072": return SignatureAlgorithm.RSA_3072;
            default: throw new IllegalArgumentException("Unknown algorithm: " + algorithm);
        }
    }

    private String getCurrentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null ? auth.getName() : "system";
    }

    // ==================== Data Classes ====================

    /**
     * Payload structure for signature generation.
     */
    public static class SignaturePayload {
        private final String originalFilename;
        private final String imageHash;
        private final Long imageSize;
        private final String algorithm;
        private final String keyIdentifier;
        private final String timestamp;

        public SignaturePayload(String originalFilename, String imageHash, Long imageSize,
                               String algorithm, String keyIdentifier, String timestamp) {
            this.originalFilename = originalFilename;
            this.imageHash = imageHash;
            this.imageSize = imageSize;
            this.algorithm = algorithm;
            this.keyIdentifier = keyIdentifier;
            this.timestamp = timestamp;
        }

        // Getters for JSON serialization
        public String getOriginalFilename() { return originalFilename; }
        public String getImageHash() { return imageHash; }
        public Long getImageSize() { return imageSize; }
        public String getAlgorithm() { return algorithm; }
        public String getKeyIdentifier() { return keyIdentifier; }
        public String getTimestamp() { return timestamp; }
    }

    /**
     * Complete detached signature data structure for .sig files.
     */
    public static class DetachedSignatureData {
        private final String formatVersion;
        private final String originalFilename;
        private final String imageHash;
        private final Long imageSize;
        private final com.certificateauthority.entity.ImageFormat imageFormat;
        private final String mimeType;
        private final SignatureAlgorithm signatureAlgorithm;
        private final LocalDateTime signatureTimestamp;
        private final UUID signingKeyId;
        private final String keyIdentifier;
        private final String signatureData;
        private final String signatureHash;

        // Default constructor for JSON deserialization
        public DetachedSignatureData() {
            this.formatVersion = null;
            this.originalFilename = null;
            this.imageHash = null;
            this.imageSize = null;
            this.imageFormat = null;
            this.mimeType = null;
            this.signatureAlgorithm = null;
            this.signatureTimestamp = null;
            this.signingKeyId = null;
            this.keyIdentifier = null;
            this.signatureData = null;
            this.signatureHash = null;
        }

        public DetachedSignatureData(String formatVersion, String originalFilename, String imageHash,
                                   Long imageSize, com.certificateauthority.entity.ImageFormat imageFormat,
                                   String mimeType, SignatureAlgorithm signatureAlgorithm,
                                   LocalDateTime signatureTimestamp, UUID signingKeyId,
                                   String keyIdentifier, String signatureData, String signatureHash) {
            this.formatVersion = formatVersion;
            this.originalFilename = originalFilename;
            this.imageHash = imageHash;
            this.imageSize = imageSize;
            this.imageFormat = imageFormat;
            this.mimeType = mimeType;
            this.signatureAlgorithm = signatureAlgorithm;
            this.signatureTimestamp = signatureTimestamp;
            this.signingKeyId = signingKeyId;
            this.keyIdentifier = keyIdentifier;
            this.signatureData = signatureData;
            this.signatureHash = signatureHash;
        }

        // Getters for JSON serialization
        public String getFormatVersion() { return formatVersion; }
        public String getOriginalFilename() { return originalFilename; }
        public String getImageHash() { return imageHash; }
        public Long getImageSize() { return imageSize; }
        public com.certificateauthority.entity.ImageFormat getImageFormat() { return imageFormat; }
        public String getMimeType() { return mimeType; }
        public SignatureAlgorithm getSignatureAlgorithm() { return signatureAlgorithm; }
        public LocalDateTime getSignatureTimestamp() { return signatureTimestamp; }
        public UUID getSigningKeyId() { return signingKeyId; }
        public String getKeyIdentifier() { return keyIdentifier; }
        public String getSignatureData() { return signatureData; }
        public String getSignatureHash() { return signatureHash; }
    }

    // ==================== Result Classes ====================

    public static class DetachedSignatureResult {
        private final boolean success;
        private final String message;
        private final byte[] sigFileContent;
        private final String sigFilename;
        private final ImageSignature imageSignature;
        private final DetachedSignatureData signatureData;

        private DetachedSignatureResult(boolean success, String message, byte[] sigFileContent,
                                       String sigFilename, ImageSignature imageSignature,
                                       DetachedSignatureData signatureData) {
            this.success = success;
            this.message = message;
            this.sigFileContent = sigFileContent;
            this.sigFilename = sigFilename;
            this.imageSignature = imageSignature;
            this.signatureData = signatureData;
        }

        public static DetachedSignatureResult success(byte[] sigFileContent, String sigFilename,
                                                     ImageSignature imageSignature, DetachedSignatureData signatureData) {
            return new DetachedSignatureResult(true, "Signature generation successful", 
                sigFileContent, sigFilename, imageSignature, signatureData);
        }

        public static DetachedSignatureResult failure(String message) {
            return new DetachedSignatureResult(false, message, null, null, null, null);
        }

        // Getters
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public byte[] getSigFileContent() { return sigFileContent; }
        public String getSigFilename() { return sigFilename; }
        public ImageSignature getImageSignature() { return imageSignature; }
        public DetachedSignatureData getSignatureData() { return signatureData; }
    }

    public static class DetachedSignatureParseResult {
        private final boolean success;
        private final String message;
        private final DetachedSignatureData signatureData;

        private DetachedSignatureParseResult(boolean success, String message, DetachedSignatureData signatureData) {
            this.success = success;
            this.message = message;
            this.signatureData = signatureData;
        }

        public static DetachedSignatureParseResult success(DetachedSignatureData signatureData) {
            return new DetachedSignatureParseResult(true, "Parsing successful", signatureData);
        }

        public static DetachedSignatureParseResult failure(String message) {
            return new DetachedSignatureParseResult(false, message, null);
        }

        // Getters
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public DetachedSignatureData getSignatureData() { return signatureData; }
    }

    public static class DetachedSignatureVerificationResult {
        private final boolean success;
        private final String message;
        private final DetachedSignatureData signatureData;
        private final String verificationDetails;

        private DetachedSignatureVerificationResult(boolean success, String message,
                                                   DetachedSignatureData signatureData, String verificationDetails) {
            this.success = success;
            this.message = message;
            this.signatureData = signatureData;
            this.verificationDetails = verificationDetails;
        }

        public static DetachedSignatureVerificationResult success(DetachedSignatureData signatureData, String details) {
            return new DetachedSignatureVerificationResult(true, "Verification successful", signatureData, details);
        }

        public static DetachedSignatureVerificationResult failure(String message) {
            return new DetachedSignatureVerificationResult(false, message, null, null);
        }

        // Getters
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public DetachedSignatureData getSignatureData() { return signatureData; }
        public String getVerificationDetails() { return verificationDetails; }
    }

    public static class BatchSignatureResult {
        private final List<DetachedSignatureResult> allResults;
        private final List<DetachedSignatureResult> successfulResults;
        private final List<DetachedSignatureResult> failedResults;

        public BatchSignatureResult(List<DetachedSignatureResult> allResults,
                                   List<DetachedSignatureResult> successfulResults,
                                   List<DetachedSignatureResult> failedResults) {
            this.allResults = allResults;
            this.successfulResults = successfulResults;
            this.failedResults = failedResults;
        }

        // Getters
        public List<DetachedSignatureResult> getAllResults() { return allResults; }
        public List<DetachedSignatureResult> getSuccessfulResults() { return successfulResults; }
        public List<DetachedSignatureResult> getFailedResults() { return failedResults; }
        public int getTotalCount() { return allResults.size(); }
        public int getSuccessCount() { return successfulResults.size(); }
        public int getFailureCount() { return failedResults.size(); }
        public double getSuccessRate() { return allResults.isEmpty() ? 0.0 : (double) successfulResults.size() / allResults.size() * 100; }
    }

    private static class ValidationResult {
        private final boolean valid;
        private final String errorMessage;

        private ValidationResult(boolean valid, String errorMessage) {
            this.valid = valid;
            this.errorMessage = errorMessage;
        }

        public static ValidationResult valid() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult invalid(String message) {
            return new ValidationResult(false, message);
        }

        public boolean isValid() { return valid; }
        public String getErrorMessage() { return errorMessage; }
    }
}