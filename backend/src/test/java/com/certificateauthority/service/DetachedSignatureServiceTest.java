package com.certificateauthority.service;

import com.certificateauthority.entity.*;
import com.certificateauthority.repository.ImageSignatureRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
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
 * Unit tests for DetachedSignatureService.
 * Tests detached signature generation, parsing, and verification functionality.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("DetachedSignatureService Tests")
class DetachedSignatureServiceTest {

    @Mock
    private KeyManagementService keyManagementService;
    
    @Mock
    private ImageFormatDetectionService formatDetectionService;
    
    @Mock
    private ImageSignatureRepository imageSignatureRepository;

    @InjectMocks
    private DetachedSignatureService detachedSignatureService;

    private byte[] mockImageData;
    private SigningKey mockSigningKey;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        // Clear security context
        SecurityContextHolder.clearContext();
        
        // Set up authentication
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
            "testuser", "password", List.of(new SimpleGrantedAuthority("ROLE_KEY_OPERATOR")));
        SecurityContextHolder.getContext().setAuthentication(auth);

        // Create mock image data
        mockImageData = createMockImageData();
        
        // Create mock signing key
        mockSigningKey = createMockSigningKey();
        
        // Initialize object mapper for JSON testing
        objectMapper = new ObjectMapper();
    }

    @Nested
    @DisplayName("Detached Signature Generation Tests")
    class DetachedSignatureGenerationTests {

        @Test
        @DisplayName("Should successfully generate detached signature for PNG image")
        void shouldSuccessfullyGenerateDetachedSignatureForPng() {
            // Arrange
            String filename = "test.png";
            
            setupValidImageFormatDetection(filename, ImageFormat.PNG, "image/png");
            setupValidKeyManagement();
            setupRepositoryMock();

            // Act
            DetachedSignatureService.DetachedSignatureResult result = 
                detachedSignatureService.generateDetachedSignature(mockImageData, filename, null);

            // Assert
            assertTrue(result.isSuccess());
            assertNotNull(result.getSigFileContent());
            assertEquals("test.sig", result.getSigFilename());
            assertNotNull(result.getImageSignature());
            assertNotNull(result.getSignatureData());
            assertEquals("Signature generation successful", result.getMessage());
            
            // Verify the .sig file content is valid JSON
            assertDoesNotThrow(() -> {
                String jsonContent = new String(result.getSigFileContent());
                objectMapper.readTree(jsonContent);
            });
            
            verify(imageSignatureRepository).save(any(ImageSignature.class));
        }

        @Test
        @DisplayName("Should successfully generate detached signature for JPEG image")
        void shouldSuccessfullyGenerateDetachedSignatureForJpeg() {
            // Arrange
            String filename = "test.jpg";
            
            setupValidImageFormatDetection(filename, ImageFormat.JPEG, "image/jpeg");
            setupValidKeyManagement();
            setupRepositoryMock();

            // Act
            DetachedSignatureService.DetachedSignatureResult result = 
                detachedSignatureService.generateDetachedSignature(mockImageData, filename, null);

            // Assert
            assertTrue(result.isSuccess());
            assertEquals("test.sig", result.getSigFilename());
            assertNotNull(result.getSigFileContent());
        }

        @Test
        @DisplayName("Should generate correct .sig filename from various input filenames")
        void shouldGenerateCorrectSigFilename() {
            // Test cases for different filename patterns
            Map<String, String> testCases = Map.of(
                "image.png", "image.sig",
                "document.jpeg", "document.sig",
                "file.with.dots.jpg", "file.with.dots.sig",
                "noextension", "noextension.sig"
            );

            for (Map.Entry<String, String> testCase : testCases.entrySet()) {
                String inputFilename = testCase.getKey();
                String expectedSigFilename = testCase.getValue();
                
                setupValidImageFormatDetection(inputFilename, ImageFormat.PNG, "image/png");
                setupValidKeyManagement();
                setupRepositoryMock();

                DetachedSignatureService.DetachedSignatureResult result = 
                    detachedSignatureService.generateDetachedSignature(mockImageData, inputFilename, null);

                assertTrue(result.isSuccess(), "Failed for filename: " + inputFilename);
                assertEquals(expectedSigFilename, result.getSigFilename());
            }
        }

        @Test
        @DisplayName("Should use specific algorithm when provided")
        void shouldUseSpecificAlgorithmWhenProvided() {
            // Arrange
            String filename = "test.png";
            String algorithm = "ECDSA_P256";
            
            setupValidImageFormatDetection(filename, ImageFormat.PNG, "image/png");
            
            SigningKey ecdsaKey = createMockSigningKey();
            ecdsaKey.setAlgorithm("ECDSA_P256");
            
            KeyManagementService.KeyManagementResult keyResult = 
                new KeyManagementService.KeyManagementResult(true, "Success", ecdsaKey, null, null);
            when(keyManagementService.getSigningKey(algorithm)).thenReturn(keyResult);
            
            setupRepositoryMock();

            // Act
            DetachedSignatureService.DetachedSignatureResult result = 
                detachedSignatureService.generateDetachedSignature(mockImageData, filename, algorithm);

            // Assert
            assertTrue(result.isSuccess());
            assertEquals(SignatureAlgorithm.ECDSA_P256, result.getSignatureData().getSignatureAlgorithm());
            verify(keyManagementService).getSigningKey(algorithm);
        }

        @Test
        @DisplayName("Should fail when image data is empty")
        void shouldFailWhenImageDataIsEmpty() {
            // Act
            DetachedSignatureService.DetachedSignatureResult result = 
                detachedSignatureService.generateDetachedSignature(new byte[0], "test.png", null);

            // Assert
            assertFalse(result.isSuccess());
            assertEquals("Image data is empty", result.getMessage());
        }

        @Test
        @DisplayName("Should fail when filename is null or empty")
        void shouldFailWhenFilenameIsNullOrEmpty() {
            // Test null filename
            DetachedSignatureService.DetachedSignatureResult result1 = 
                detachedSignatureService.generateDetachedSignature(mockImageData, null, null);
            assertFalse(result1.isSuccess());
            assertTrue(result1.getMessage().contains("filename is required"));

            // Test empty filename
            DetachedSignatureService.DetachedSignatureResult result2 = 
                detachedSignatureService.generateDetachedSignature(mockImageData, "", null);
            assertFalse(result2.isSuccess());
            assertTrue(result2.getMessage().contains("filename is required"));
        }

        @Test
        @DisplayName("Should fail when image format is invalid")
        void shouldFailWhenImageFormatIsInvalid() {
            // Arrange
            String filename = "test.txt";
            
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.invalid("Not an image file");
            when(formatDetectionService.detectFormat(mockImageData, filename))
                .thenReturn(formatResult);

            // Act
            DetachedSignatureService.DetachedSignatureResult result = 
                detachedSignatureService.generateDetachedSignature(mockImageData, filename, null);

            // Assert
            assertFalse(result.isSuccess());
            assertTrue(result.getMessage().contains("Invalid image format"));
        }

        @Test
        @DisplayName("Should fail when signing key is not available")
        void shouldFailWhenSigningKeyNotAvailable() {
            // Arrange
            String filename = "test.png";
            
            setupValidImageFormatDetection(filename, ImageFormat.PNG, "image/png");
            
            KeyManagementService.KeyManagementResult keyResult = 
                new KeyManagementService.KeyManagementResult(false, "No active key found", null, null, null);
            when(keyManagementService.getSigningKey()).thenReturn(keyResult);

            // Act
            DetachedSignatureService.DetachedSignatureResult result = 
                detachedSignatureService.generateDetachedSignature(mockImageData, filename, null);

            // Assert
            assertFalse(result.isSuccess());
            assertTrue(result.getMessage().contains("Failed to obtain signing key"));
        }
    }

    @Nested
    @DisplayName("Signature Parsing Tests")
    class SignatureParsingTests {

        @Test
        @DisplayName("Should successfully parse valid detached signature file")
        void shouldSuccessfullyParseValidDetachedSignatureFile() {
            // Arrange
            String filename = "test.png";
            setupValidImageFormatDetection(filename, ImageFormat.PNG, "image/png");
            setupValidKeyManagement();
            setupRepositoryMock();

            // Generate a signature first
            DetachedSignatureService.DetachedSignatureResult generateResult = 
                detachedSignatureService.generateDetachedSignature(mockImageData, filename, null);
            assertTrue(generateResult.isSuccess());

            // Act - Parse the generated signature
            DetachedSignatureService.DetachedSignatureParseResult parseResult = 
                detachedSignatureService.parseDetachedSignature(generateResult.getSigFileContent());

            // Assert
            assertTrue(parseResult.isSuccess());
            assertNotNull(parseResult.getSignatureData());
            assertEquals(filename, parseResult.getSignatureData().getOriginalFilename());
            assertEquals("Parsing successful", parseResult.getMessage());
        }

        @Test
        @DisplayName("Should fail to parse empty signature file")
        void shouldFailToParseEmptySignatureFile() {
            // Act
            DetachedSignatureService.DetachedSignatureParseResult result = 
                detachedSignatureService.parseDetachedSignature(new byte[0]);

            // Assert
            assertFalse(result.isSuccess());
            assertEquals("Signature file content is empty", result.getMessage());
        }

        @Test
        @DisplayName("Should fail to parse invalid JSON content")
        void shouldFailToParseInvalidJsonContent() {
            // Arrange
            byte[] invalidJson = "invalid json content".getBytes();

            // Act
            DetachedSignatureService.DetachedSignatureParseResult result = 
                detachedSignatureService.parseDetachedSignature(invalidJson);

            // Assert
            assertFalse(result.isSuccess());
            assertTrue(result.getMessage().contains("Signature parsing failed"));
        }

        @Test
        @DisplayName("Should validate signature data structure")
        void shouldValidateSignatureDataStructure() {
            // Arrange - Create malformed JSON with missing required fields
            String malformedJson = """
                {
                    "formatVersion": "1.0",
                    "originalFilename": "",
                    "imageHash": "invalid-hash"
                }
                """;
            byte[] malformedContent = malformedJson.getBytes();

            // Act
            DetachedSignatureService.DetachedSignatureParseResult result = 
                detachedSignatureService.parseDetachedSignature(malformedContent);

            // Assert
            assertFalse(result.isSuccess());
            assertTrue(result.getMessage().contains("Invalid signature data"));
        }
    }

    @Nested
    @DisplayName("Signature Verification Tests")
    class SignatureVerificationTests {

        @Test
        @DisplayName("Should successfully verify valid detached signature")
        void shouldSuccessfullyVerifyValidDetachedSignature() {
            // Arrange
            String filename = "test.png";
            setupValidImageFormatDetection(filename, ImageFormat.PNG, "image/png");
            setupValidKeyManagement();
            setupRepositoryMock();

            // Generate signature
            DetachedSignatureService.DetachedSignatureResult generateResult = 
                detachedSignatureService.generateDetachedSignature(mockImageData, filename, null);
            assertTrue(generateResult.isSuccess());

            // Act - Verify with original image data
            DetachedSignatureService.DetachedSignatureVerificationResult verifyResult = 
                detachedSignatureService.verifyDetachedSignature(mockImageData, generateResult.getSigFileContent());

            // Assert
            assertTrue(verifyResult.isSuccess());
            assertNotNull(verifyResult.getSignatureData());
            assertEquals("Signature verification successful", verifyResult.getVerificationDetails());
        }

        @Test
        @DisplayName("Should fail verification when image has been modified")
        void shouldFailVerificationWhenImageModified() {
            // Arrange
            String filename = "test.png";
            setupValidImageFormatDetection(filename, ImageFormat.PNG, "image/png");
            setupValidKeyManagement();
            setupRepositoryMock();

            // Generate signature with original data
            DetachedSignatureService.DetachedSignatureResult generateResult = 
                detachedSignatureService.generateDetachedSignature(mockImageData, filename, null);
            assertTrue(generateResult.isSuccess());

            // Create modified image data
            byte[] modifiedImageData = Arrays.copyOf(mockImageData, mockImageData.length);
            modifiedImageData[0] = (byte) ~modifiedImageData[0]; // Flip bits in first byte

            // Act - Verify with modified image data
            DetachedSignatureService.DetachedSignatureVerificationResult verifyResult = 
                detachedSignatureService.verifyDetachedSignature(modifiedImageData, generateResult.getSigFileContent());

            // Assert
            assertFalse(verifyResult.isSuccess());
            assertTrue(verifyResult.getMessage().contains("Image hash mismatch"));
        }

        @Test
        @DisplayName("Should fail verification when image size differs")
        void shouldFailVerificationWhenImageSizeDiffers() {
            // Arrange
            String filename = "test.png";
            setupValidImageFormatDetection(filename, ImageFormat.PNG, "image/png");
            setupValidKeyManagement();
            setupRepositoryMock();

            // Generate signature
            DetachedSignatureService.DetachedSignatureResult generateResult = 
                detachedSignatureService.generateDetachedSignature(mockImageData, filename, null);
            assertTrue(generateResult.isSuccess());

            // Modify the signature data to have wrong image size but same hash
            // (This would happen if someone tampered with the .sig file)
            try {
                String sigContent = new String(generateResult.getSigFileContent());
                // Replace the image size in the JSON with a different value
                String modifiedSigContent = sigContent.replaceFirst(
                    "\"imageSize\"\\s*:\\s*\\d+", "\"imageSize\":999999");
                byte[] modifiedSigData = modifiedSigContent.getBytes();

                // Act
                DetachedSignatureService.DetachedSignatureVerificationResult verifyResult = 
                    detachedSignatureService.verifyDetachedSignature(mockImageData, modifiedSigData);

                // Assert
                assertFalse(verifyResult.isSuccess());
                assertTrue(verifyResult.getMessage().contains("Image size mismatch"));
            } catch (Exception e) {
                fail("Failed to modify signature content: " + e.getMessage());
            }
        }

        @Test
        @DisplayName("Should fail verification with corrupted signature file")
        void shouldFailVerificationWithCorruptedSignatureFile() {
            // Arrange
            byte[] corruptedSigFile = "corrupted signature file".getBytes();

            // Act
            DetachedSignatureService.DetachedSignatureVerificationResult result = 
                detachedSignatureService.verifyDetachedSignature(mockImageData, corruptedSigFile);

            // Assert
            assertFalse(result.isSuccess());
            assertTrue(result.getMessage().contains("Failed to parse signature"));
        }
    }

    @Nested
    @DisplayName("Batch Signature Generation Tests")
    class BatchSignatureGenerationTests {

        @Test
        @DisplayName("Should generate batch signatures for multiple images")
        void shouldGenerateBatchSignaturesForMultipleImages() {
            // Arrange
            Map<String, byte[]> imageFiles = Map.of(
                "image1.png", createMockImageData(),
                "image2.jpg", createMockImageData(),
                "image3.png", createMockImageData()
            );

            setupBatchOperationMocks();

            // Act
            DetachedSignatureService.BatchSignatureResult result = 
                detachedSignatureService.generateBatchDetachedSignatures(imageFiles, null);

            // Assert
            assertEquals(3, result.getTotalCount());
            assertEquals(3, result.getSuccessCount());
            assertEquals(0, result.getFailureCount());
            assertEquals(100.0, result.getSuccessRate(), 0.01);
            
            // Verify all signatures were created
            for (DetachedSignatureService.DetachedSignatureResult sigResult : result.getSuccessfulResults()) {
                assertTrue(sigResult.isSuccess());
                assertNotNull(sigResult.getSigFileContent());
                assertNotNull(sigResult.getSigFilename());
            }
        }

        @Test
        @DisplayName("Should handle mixed success and failure in batch operation")
        void shouldHandleMixedSuccessAndFailureInBatch() {
            // Arrange
            Map<String, byte[]> imageFiles = Map.of(
                "valid.png", createMockImageData(),
                "invalid.txt", createMockImageData(),
                "empty.png", new byte[0]
            );

            // Mock valid image detection for .png files only
            when(formatDetectionService.detectFormat(any(), eq("valid.png")))
                .thenReturn(ImageFormatDetectionService.ImageFormatResult.valid(ImageFormat.PNG, "image/png", "valid.png"));
            when(formatDetectionService.isSupportedFormat(ImageFormat.PNG)).thenReturn(true);
            
            when(formatDetectionService.detectFormat(any(), eq("invalid.txt")))
                .thenReturn(ImageFormatDetectionService.ImageFormatResult.invalid("Not an image"));
            
            setupValidKeyManagement();
            setupRepositoryMock();

            // Act
            DetachedSignatureService.BatchSignatureResult result = 
                detachedSignatureService.generateBatchDetachedSignatures(imageFiles, null);

            // Assert
            assertEquals(3, result.getTotalCount());
            assertEquals(1, result.getSuccessCount()); // Only valid.png should succeed
            assertEquals(2, result.getFailureCount()); // invalid.txt and empty.png should fail
            assertEquals(33.33, result.getSuccessRate(), 0.01);
        }

        @Test
        @DisplayName("Should handle empty batch gracefully")
        void shouldHandleEmptyBatchGracefully() {
            // Arrange
            Map<String, byte[]> emptyBatch = Collections.emptyMap();

            // Act
            DetachedSignatureService.BatchSignatureResult result = 
                detachedSignatureService.generateBatchDetachedSignatures(emptyBatch, null);

            // Assert
            assertEquals(0, result.getTotalCount());
            assertEquals(0, result.getSuccessCount());
            assertEquals(0, result.getFailureCount());
            assertEquals(0.0, result.getSuccessRate(), 0.01);
        }
    }

    // ==================== Helper Methods ====================

    private void setupValidImageFormatDetection(String filename, ImageFormat format, String mimeType) {
        ImageFormatDetectionService.ImageFormatResult formatResult = 
            ImageFormatDetectionService.ImageFormatResult.valid(format, mimeType, filename);
        when(formatDetectionService.detectFormat(mockImageData, filename)).thenReturn(formatResult);
        when(formatDetectionService.isSupportedFormat(format)).thenReturn(true);
    }

    private void setupValidKeyManagement() {
        KeyManagementService.KeyManagementResult keyResult = 
            new KeyManagementService.KeyManagementResult(true, "Success", mockSigningKey, null, null);
        lenient().when(keyManagementService.getSigningKey()).thenReturn(keyResult);
        lenient().when(keyManagementService.getSigningKey(anyString())).thenReturn(keyResult);
    }

    private void setupRepositoryMock() {
        ImageSignature savedSignature = new ImageSignature();
        savedSignature.setId(UUID.randomUUID());
        when(imageSignatureRepository.save(any(ImageSignature.class))).thenReturn(savedSignature);
    }

    private void setupBatchOperationMocks() {
        // Mock format detection for various files
        when(formatDetectionService.detectFormat(any(), contains(".png")))
            .thenReturn(ImageFormatDetectionService.ImageFormatResult.valid(ImageFormat.PNG, "image/png", "test.png"));
        when(formatDetectionService.detectFormat(any(), contains(".jpg")))
            .thenReturn(ImageFormatDetectionService.ImageFormatResult.valid(ImageFormat.JPEG, "image/jpeg", "test.jpg"));
        
        when(formatDetectionService.isSupportedFormat(ImageFormat.PNG)).thenReturn(true);
        when(formatDetectionService.isSupportedFormat(ImageFormat.JPEG)).thenReturn(true);
        
        setupValidKeyManagement();
        setupRepositoryMock();
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

    private SigningKey createMockSigningKey() {
        SigningKey key = new SigningKey();
        key.setId(UUID.randomUUID());
        key.setKeyIdentifier("test-key-" + System.currentTimeMillis());
        key.setAlgorithm("Ed25519");
        key.setKeySizeBits(256);
        key.setIsActive(true);
        key.setCreatedAt(LocalDateTime.now());
        key.setExpiresAt(LocalDateTime.now().plusDays(90));
        key.setUsageCount(0L);
        key.setPublicKeyData("mock-public-key");
        key.setPrivateKeyData("mock-encrypted-private-key");
        return key;
    }
}