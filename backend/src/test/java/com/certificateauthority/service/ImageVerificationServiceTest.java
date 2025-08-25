package com.certificateauthority.service;

import com.certificateauthority.entity.*;
import com.certificateauthority.repository.ImageSignatureRepository;
import com.certificateauthority.repository.SigningKeyRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.LocalDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.lenient;

/**
 * Unit tests for ImageVerificationService.
 * Tests comprehensive signature verification functionality for both embedded and detached signatures.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ImageVerificationService Tests")
class ImageVerificationServiceTest {

    @Mock
    private ImageSigningService imageSigningService;
    
    @Mock
    private DetachedSignatureService detachedSignatureService;
    
    @Mock
    private ImageFormatDetectionService formatDetectionService;
    
    @Mock
    private KeyManagementService keyManagementService;
    
    @Mock
    private ImageSignatureRepository imageSignatureRepository;
    
    @Mock
    private SigningKeyRepository signingKeyRepository;

    @InjectMocks
    private ImageVerificationService imageVerificationService;

    private byte[] mockImageData;
    private byte[] mockSigFileData;
    private ImageSignature mockEmbeddedSignature;
    private ImageSignature mockDetachedSignature;
    private SigningKey mockSigningKey;
    private String testImageHash;

    @BeforeEach
    void setUp() {
        // Clear security context
        SecurityContextHolder.clearContext();
        
        // Set up authentication
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
            "testuser", "password", List.of(new SimpleGrantedAuthority("ROLE_VERIFIER")));
        SecurityContextHolder.getContext().setAuthentication(auth);

        // Create mock data
        mockImageData = createMockImageData();
        mockSigFileData = "mock signature file content".getBytes();
        testImageHash = "nq9myyq5OJ9CdEYXAV39v6mjgiIVExSSQas1WivTLqQ="; // Known hash for mock data
        
        // Create mock signatures
        mockEmbeddedSignature = createMockImageSignature(SignatureFormat.EMBEDDED);
        mockDetachedSignature = createMockImageSignature(SignatureFormat.DETACHED);
        
        // Create mock signing key
        mockSigningKey = createMockSigningKey();
    }

    @Nested
    @DisplayName("Embedded Signature Verification Tests")
    class EmbeddedSignatureVerificationTests {

        @Test
        @DisplayName("Should successfully verify valid embedded signature")
        void shouldSuccessfullyVerifyValidEmbeddedSignature() {
            // Arrange
            String filename = "test.png";
            
            setupValidImageFormat(filename);
            setupSuccessfulEmbeddedExtraction();
            setupValidSignatureRecord(mockEmbeddedSignature);
            setupValidSigningKey();

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyEmbeddedSignature(mockImageData, filename);

            // Assert
            assertTrue(result.isValid());
            assertEquals("Embedded signature verification successful", result.getMessage());
            assertTrue(result.isEmbeddedSignature());
            assertNotNull(result.getSignature());
            assertEquals(mockEmbeddedSignature.getId(), result.getSignature().getId());
            
            // Verify signature was updated with verification result
            verify(imageSignatureRepository).save(any(ImageSignature.class));
        }

        @Test
        @DisplayName("Should fail when image data is empty")
        void shouldFailWhenImageDataIsEmpty() {
            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyEmbeddedSignature(new byte[0], "test.png");

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.INVALID_INPUT, 
                result.getFailureReason());
            assertEquals("Image data is empty", result.getErrorMessage());
        }

        @Test
        @DisplayName("Should fail when image format is invalid")
        void shouldFailWhenImageFormatIsInvalid() {
            // Arrange
            String filename = "test.txt";
            
            ImageFormatDetectionService.ImageFormatResult invalidFormat = 
                ImageFormatDetectionService.ImageFormatResult.invalid("Not an image file");
            when(formatDetectionService.detectFormat(mockImageData, filename))
                .thenReturn(invalidFormat);

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyEmbeddedSignature(mockImageData, filename);

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.UNSUPPORTED_FORMAT, 
                result.getFailureReason());
            assertTrue(result.getErrorMessage().contains("Invalid image format"));
        }

        @Test
        @DisplayName("Should fail when no embedded signature is found")
        void shouldFailWhenNoEmbeddedSignatureFound() {
            // Arrange
            String filename = "test.png";
            
            setupValidImageFormat(filename);
            
            ImageSigningService.SignatureExtractionResult failedExtraction = 
                ImageSigningService.SignatureExtractionResult.failure("No signature found in metadata");
            when(imageSigningService.extractSignature(mockImageData))
                .thenReturn(failedExtraction);

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyEmbeddedSignature(mockImageData, filename);

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.NO_SIGNATURE_FOUND, 
                result.getFailureReason());
            assertTrue(result.getErrorMessage().contains("Failed to extract embedded signature"));
        }

        @Test
        @DisplayName("Should fail when signature record not found in database")
        void shouldFailWhenSignatureRecordNotFound() {
            // Arrange
            String filename = "test.png";
            
            setupValidImageFormat(filename);
            setupSuccessfulEmbeddedExtraction();
            when(imageSignatureRepository.findByImageHash(anyString()))
                .thenReturn(Optional.empty());

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyEmbeddedSignature(mockImageData, filename);

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.SIGNATURE_NOT_FOUND, 
                result.getFailureReason());
            assertEquals("No signature record found for image hash", result.getErrorMessage());
        }

        @Test
        @DisplayName("Should fail when signature format mismatch")
        void shouldFailWhenSignatureFormatMismatch() {
            // Arrange
            String filename = "test.png";
            
            setupValidImageFormat(filename);
            setupSuccessfulEmbeddedExtraction();
            // Return detached signature when expecting embedded
            setupValidSignatureRecord(mockDetachedSignature);

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyEmbeddedSignature(mockImageData, filename);

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.SIGNATURE_FORMAT_MISMATCH, 
                result.getFailureReason());
            assertTrue(result.getErrorMessage().contains("Expected embedded signature but found DETACHED"));
        }

        @Test
        @DisplayName("Should fail when image hash does not match")
        void shouldFailWhenImageHashMismatch() {
            // Arrange
            String filename = "test.png";
            
            setupValidImageFormat(filename);
            setupSuccessfulEmbeddedExtraction();
            
            // Create signature with different hash
            ImageSignature differentHashSignature = createMockImageSignature(SignatureFormat.EMBEDDED);
            differentHashSignature.setImageHash("different-hash");
            setupValidSignatureRecord(differentHashSignature);
            setupValidSigningKey();

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyEmbeddedSignature(mockImageData, filename);

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.IMAGE_HASH_MISMATCH, 
                result.getFailureReason());
            assertTrue(result.getErrorMessage().contains("Image hash mismatch"));
        }

        @Test
        @DisplayName("Should fail when signing key is expired")
        void shouldFailWhenSigningKeyExpired() {
            // Arrange
            String filename = "test.png";
            
            setupValidImageFormat(filename);
            setupSuccessfulEmbeddedExtraction();
            setupValidSignatureRecord(mockEmbeddedSignature);
            
            // Create expired signing key
            SigningKey expiredKey = createMockSigningKey();
            expiredKey.setExpiresAt(LocalDateTime.now().minusDays(1)); // Expired yesterday
            when(signingKeyRepository.findById(mockEmbeddedSignature.getSigningKeyId()))
                .thenReturn(Optional.of(expiredKey));

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyEmbeddedSignature(mockImageData, filename);

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.KEY_EXPIRED, 
                result.getFailureReason());
            assertEquals("Signing key has expired", result.getErrorMessage());
        }
    }

    @Nested
    @DisplayName("Detached Signature Verification Tests")
    class DetachedSignatureVerificationTests {

        @Test
        @DisplayName("Should successfully verify valid detached signature")
        void shouldSuccessfullyVerifyValidDetachedSignature() {
            // Arrange
            String filename = "test.png";
            
            setupSuccessfulDetachedVerification();
            setupValidSignatureRecord(mockDetachedSignature);
            setupValidSigningKey();

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyDetachedSignature(mockImageData, mockSigFileData, filename);

            // Assert
            assertTrue(result.isValid());
            assertEquals("Detached signature verification successful", result.getMessage());
            assertTrue(result.isDetachedSignature());
            assertNotNull(result.getSignature());
            assertEquals(mockDetachedSignature.getId(), result.getSignature().getId());
            
            // Verify signature was updated
            verify(imageSignatureRepository).save(any(ImageSignature.class));
        }

        @Test
        @DisplayName("Should fail when image data is empty")
        void shouldFailWhenImageDataIsEmpty() {
            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyDetachedSignature(new byte[0], mockSigFileData, "test.png");

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.INVALID_INPUT, 
                result.getFailureReason());
            assertEquals("Image data is empty", result.getErrorMessage());
        }

        @Test
        @DisplayName("Should fail when signature file data is empty")
        void shouldFailWhenSignatureFileDataIsEmpty() {
            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyDetachedSignature(mockImageData, new byte[0], "test.png");

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.INVALID_INPUT, 
                result.getFailureReason());
            assertEquals("Signature file data is empty", result.getErrorMessage());
        }

        @Test
        @DisplayName("Should fail when detached signature verification fails")
        void shouldFailWhenDetachedSignatureVerificationFails() {
            // Arrange
            String filename = "test.png";
            
            DetachedSignatureService.DetachedSignatureVerificationResult failedResult = 
                DetachedSignatureService.DetachedSignatureVerificationResult.failure("Signature verification failed");
            when(detachedSignatureService.verifyDetachedSignature(mockImageData, mockSigFileData))
                .thenReturn(failedResult);

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyDetachedSignature(mockImageData, mockSigFileData, filename);

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.SIGNATURE_INVALID, 
                result.getFailureReason());
            assertTrue(result.getErrorMessage().contains("Detached signature verification failed"));
        }

        @Test
        @DisplayName("Should fail when detached signature format mismatch")
        void shouldFailWhenDetachedSignatureFormatMismatch() {
            // Arrange
            String filename = "test.png";
            
            setupSuccessfulDetachedVerification();
            // Return embedded signature when expecting detached
            setupValidSignatureRecord(mockEmbeddedSignature);

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifyDetachedSignature(mockImageData, mockSigFileData, filename);

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.SIGNATURE_FORMAT_MISMATCH, 
                result.getFailureReason());
            assertTrue(result.getErrorMessage().contains("Expected detached signature but found EMBEDDED"));
        }
    }

    @Nested
    @DisplayName("Auto-Detection Verification Tests")
    class AutoDetectionVerificationTests {

        @Test
        @DisplayName("Should prefer embedded signature when both are available")
        void shouldPreferEmbeddedSignatureWhenBothAvailable() {
            // Arrange
            String filename = "test.png";
            
            setupValidImageFormat(filename);
            setupSuccessfulEmbeddedExtraction();
            setupValidSignatureRecord(mockEmbeddedSignature);
            setupValidSigningKey();
            
            // Setup detached verification (but it shouldn't be called)
            setupSuccessfulDetachedVerification();

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifySignature(mockImageData, filename, mockSigFileData);

            // Assert
            assertTrue(result.isValid());
            assertTrue(result.isEmbeddedSignature());
            assertEquals("Embedded signature verification successful", result.getMessage());
            
            // Verify detached verification was not called
            verify(detachedSignatureService, never()).verifyDetachedSignature(any(), any());
        }

        @Test
        @DisplayName("Should fallback to detached signature when embedded fails")
        void shouldFallbackToDetachedSignatureWhenEmbeddedFails() {
            // Arrange
            String filename = "test.png";
            
            // Setup embedded verification to fail
            setupValidImageFormat(filename);
            ImageSigningService.SignatureExtractionResult failedExtraction = 
                ImageSigningService.SignatureExtractionResult.failure("No embedded signature");
            when(imageSigningService.extractSignature(mockImageData))
                .thenReturn(failedExtraction);

            // Setup detached verification to succeed
            setupSuccessfulDetachedVerification();
            setupValidSignatureRecord(mockDetachedSignature);
            setupValidSigningKey();

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifySignature(mockImageData, filename, mockSigFileData);

            // Assert
            assertTrue(result.isValid());
            assertTrue(result.isDetachedSignature());
            assertEquals("Detached signature verification successful", result.getMessage());
        }

        @Test
        @DisplayName("Should fail when both embedded and detached verification fail")
        void shouldFailWhenBothEmbeddedAndDetachedFail() {
            // Arrange
            String filename = "test.png";
            
            // Setup both verifications to fail
            setupValidImageFormat(filename);
            ImageSigningService.SignatureExtractionResult failedExtraction = 
                ImageSigningService.SignatureExtractionResult.failure("No embedded signature");
            when(imageSigningService.extractSignature(mockImageData))
                .thenReturn(failedExtraction);

            DetachedSignatureService.DetachedSignatureVerificationResult failedDetached = 
                DetachedSignatureService.DetachedSignatureVerificationResult.failure("Invalid detached signature");
            when(detachedSignatureService.verifyDetachedSignature(mockImageData, mockSigFileData))
                .thenReturn(failedDetached);

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifySignature(mockImageData, filename, mockSigFileData);

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.VERIFICATION_FAILED, 
                result.getFailureReason());
            assertTrue(result.getErrorMessage().contains("Both embedded and detached signature verification failed"));
        }

        @Test
        @DisplayName("Should fail when embedded fails and no detached signature provided")
        void shouldFailWhenEmbeddedFailsAndNoDetachedProvided() {
            // Arrange
            String filename = "test.png";
            
            setupValidImageFormat(filename);
            ImageSigningService.SignatureExtractionResult failedExtraction = 
                ImageSigningService.SignatureExtractionResult.failure("No embedded signature");
            when(imageSigningService.extractSignature(mockImageData))
                .thenReturn(failedExtraction);

            // Act
            ImageVerificationService.VerificationResult result = 
                imageVerificationService.verifySignature(mockImageData, filename, null);

            // Assert
            assertFalse(result.isValid());
            assertEquals(ImageVerificationService.VerificationFailureReason.NO_SIGNATURE_FOUND, 
                result.getFailureReason());
            assertTrue(result.getErrorMessage().contains("No valid signature found"));
        }
    }

    @Nested
    @DisplayName("Batch Verification Tests")
    class BatchVerificationTests {

        @Test
        @DisplayName("Should verify multiple images successfully")
        void shouldVerifyMultipleImagesSuccessfully() {
            // Arrange
            Map<String, byte[]> imageFiles = Map.of(
                "image1.png", mockImageData,
                "image2.jpg", mockImageData,
                "image3.png", mockImageData
            );
            
            Map<String, byte[]> signatureFiles = Map.of(
                "image1.png", mockSigFileData,
                "image2.jpg", mockSigFileData,
                "image3.png", mockSigFileData
            );

            setupBatchOperationMocks();

            // Act
            ImageVerificationService.BatchVerificationResult result = 
                imageVerificationService.verifyBatch(imageFiles, signatureFiles);

            // Assert
            assertEquals(3, result.getTotalCount());
            assertEquals(3, result.getSuccessCount());
            assertEquals(0, result.getFailureCount());
            assertEquals(100.0, result.getSuccessRate(), 0.01);
        }

        @Test
        @DisplayName("Should handle mixed success and failure in batch")
        void shouldHandleMixedSuccessAndFailureInBatch() {
            // Arrange
            Map<String, byte[]> imageFiles = Map.of(
                "valid.png", mockImageData,
                "invalid.png", new byte[0], // Empty data will fail
                "another.png", mockImageData
            );

            setupBatchOperationMocks();

            // Act
            ImageVerificationService.BatchVerificationResult result = 
                imageVerificationService.verifyBatch(imageFiles, null);

            // Assert
            assertEquals(3, result.getTotalCount());
            assertEquals(2, result.getSuccessCount()); // valid.png and another.png should succeed
            assertEquals(1, result.getFailureCount()); // invalid.png should fail
            assertEquals(66.67, result.getSuccessRate(), 0.01);
        }
    }

    @Nested
    @DisplayName("Verification History Tests")
    class VerificationHistoryTests {

        @Test
        @DisplayName("Should retrieve verification history successfully")
        void shouldRetrieveVerificationHistorySuccessfully() {
            // Arrange
            String imageHash = "test-hash";
            when(imageSignatureRepository.findByImageHash(imageHash))
                .thenReturn(Optional.of(mockEmbeddedSignature));

            // Act
            ImageVerificationService.VerificationHistoryResult result = 
                imageVerificationService.getVerificationHistory(imageHash);

            // Assert
            assertTrue(result.isFound());
            assertNotNull(result.getHistory());
            assertEquals(mockEmbeddedSignature.getId(), result.getHistory().getSignatureId());
            assertEquals(mockEmbeddedSignature.getImageName(), result.getHistory().getImageName());
        }

        @Test
        @DisplayName("Should handle case when signature not found")
        void shouldHandleCaseWhenSignatureNotFound() {
            // Arrange
            String imageHash = "nonexistent-hash";
            when(imageSignatureRepository.findByImageHash(imageHash))
                .thenReturn(Optional.empty());

            // Act
            ImageVerificationService.VerificationHistoryResult result = 
                imageVerificationService.getVerificationHistory(imageHash);

            // Assert
            assertFalse(result.isFound());
            assertTrue(result.getMessage().contains("No signature found for image hash"));
            assertNull(result.getHistory());
        }
    }

    // ==================== Helper Methods ====================

    private void setupValidImageFormat(String filename) {
        ImageFormatDetectionService.ImageFormatResult formatResult = 
            ImageFormatDetectionService.ImageFormatResult.valid(ImageFormat.PNG, "image/png", filename);
        lenient().when(formatDetectionService.detectFormat(mockImageData, filename))
            .thenReturn(formatResult);
    }

    private void setupSuccessfulEmbeddedExtraction() {
        Map<String, Object> mockMetadata = new HashMap<>();
        mockMetadata.put("algorithm", "Ed25519");
        mockMetadata.put("key_id", "test-key-123");
        
        ImageSigningService.SignatureExtractionResult extractionResult = 
            ImageSigningService.SignatureExtractionResult.success(mockMetadata, "PNG iTXt extraction");
        lenient().when(imageSigningService.extractSignature(mockImageData))
            .thenReturn(extractionResult);
    }

    private void setupSuccessfulDetachedVerification() {
        // Create mock signature data using the full constructor
        String actualHash = calculateActualImageHash();
        DetachedSignatureService.DetachedSignatureData mockSigData = 
            new DetachedSignatureService.DetachedSignatureData(
                "1.0", // formatVersion
                "test.png", // originalFilename
                actualHash, // imageHash - use calculated hash
                (long) mockImageData.length, // imageSize
                ImageFormat.PNG, // imageFormat
                "image/png", // mimeType
                SignatureAlgorithm.Ed25519, // signatureAlgorithm
                LocalDateTime.now(java.time.ZoneOffset.UTC).minusMinutes(10), // signatureTimestamp - past time in UTC
                UUID.randomUUID(), // signingKeyId
                "test-key-123", // keyIdentifier
                "mock-signature-data", // signatureData
                "mock-signature-hash" // signatureHash
            );
        
        DetachedSignatureService.DetachedSignatureVerificationResult verificationResult = 
            DetachedSignatureService.DetachedSignatureVerificationResult.success(mockSigData, "Verification successful");
        lenient().when(detachedSignatureService.verifyDetachedSignature(mockImageData, mockSigFileData))
            .thenReturn(verificationResult);
        lenient().when(detachedSignatureService.verifyDetachedSignature(any(), any()))
            .thenReturn(verificationResult);
    }

    private void setupValidSignatureRecord(ImageSignature signature) {
        lenient().when(imageSignatureRepository.findByImageHash(anyString()))
            .thenReturn(Optional.of(signature));
        lenient().when(imageSignatureRepository.save(any(ImageSignature.class)))
            .thenReturn(signature);
    }

    private void setupValidSigningKey() {
        lenient().when(signingKeyRepository.findById(any(UUID.class)))
            .thenReturn(Optional.of(mockSigningKey));
    }

    private void setupBatchOperationMocks() {
        // Setup format detection for all files
        lenient().when(formatDetectionService.detectFormat(any(), anyString()))
            .thenReturn(ImageFormatDetectionService.ImageFormatResult.valid(ImageFormat.PNG, "image/png", "test.png"));
        
        // Setup successful embedded extraction
        Map<String, Object> mockMetadata = new HashMap<>();
        ImageSigningService.SignatureExtractionResult extractionResult = 
            ImageSigningService.SignatureExtractionResult.success(mockMetadata, "PNG extraction");
        lenient().when(imageSigningService.extractSignature(any()))
            .thenReturn(extractionResult);
        
        // Setup valid signature records
        lenient().when(imageSignatureRepository.findByImageHash(anyString()))
            .thenReturn(Optional.of(mockEmbeddedSignature));
        lenient().when(imageSignatureRepository.save(any(ImageSignature.class)))
            .thenReturn(mockEmbeddedSignature);
        
        // Setup valid signing key
        lenient().when(signingKeyRepository.findById(any(UUID.class)))
            .thenReturn(Optional.of(mockSigningKey));
        
        // Setup successful detached verification  
        String actualHash = calculateActualImageHash();
        DetachedSignatureService.DetachedSignatureData mockSigData = 
            new DetachedSignatureService.DetachedSignatureData(
                "1.0", "test.png", actualHash, (long) mockImageData.length,
                ImageFormat.PNG, "image/png", SignatureAlgorithm.Ed25519,
                LocalDateTime.now(java.time.ZoneOffset.UTC).minusMinutes(10), UUID.randomUUID(), "test-key-123",
                "mock-signature-data", "mock-signature-hash"
            );
        DetachedSignatureService.DetachedSignatureVerificationResult detachedResult = 
            DetachedSignatureService.DetachedSignatureVerificationResult.success(mockSigData, "Success");
        lenient().when(detachedSignatureService.verifyDetachedSignature(any(), any()))
            .thenReturn(detachedResult);
    }

    private byte[] createMockImageData() {
        // Create mock PNG data with valid header
        return new byte[]{
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D, // IHDR chunk size
            0x49, 0x48, 0x44, 0x52, // "IHDR"
            0x00, 0x00, 0x00, 0x01, // Width: 1
            0x00, 0x00, 0x00, 0x01, // Height: 1
            0x08, 0x02, 0x00, 0x00, 0x00, // Bit depth, color type, compression, filter, interlace
            (byte) 0x90, 0x77, (byte) 0x53, (byte) 0xDE // CRC
        };
    }

    private ImageSignature createMockImageSignature(SignatureFormat format) {
        // Calculate the actual hash of mock image data to ensure it matches
        String actualHash = calculateActualImageHash();
        
        ImageSignature signature = new ImageSignature(
            actualHash,
            "test.png",
            (long) mockImageData.length,
            ImageFormat.PNG,
            "image/png",
            "mock-signature-data",
            SignatureAlgorithm.Ed25519,
            format,
            UUID.randomUUID(),
            "test-key-123",
            "mock-signature-hash"
        );
        signature.setId(UUID.randomUUID());
        signature.setSignatureTimestamp(LocalDateTime.now(java.time.ZoneOffset.UTC).minusMinutes(10)); // Set to past time in UTC
        signature.setCreatedBy("testuser");
        signature.setVerificationCount(0);
        return signature;
    }
    
    private String calculateActualImageHash() {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(mockImageData);
            return java.util.Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            return testImageHash; // fallback to hardcoded value
        }
    }

    private SigningKey createMockSigningKey() {
        SigningKey key = new SigningKey();
        key.setId(UUID.randomUUID());
        key.setKeyIdentifier("test-key-123");
        key.setAlgorithm("Ed25519");
        key.setKeySizeBits(256);
        key.setIsActive(true);
        key.setCreatedAt(LocalDateTime.now());
        key.setExpiresAt(LocalDateTime.now().plusDays(90)); // Valid for 90 days
        key.setUsageCount(0L);
        key.setPublicKeyData("mock-public-key");
        key.setPrivateKeyData("mock-encrypted-private-key");
        return key;
    }
}
