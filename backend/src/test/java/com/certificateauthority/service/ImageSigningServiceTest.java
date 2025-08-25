package com.certificateauthority.service;

import com.certificateauthority.entity.*;
import com.certificateauthority.repository.ImageSignatureRepository;
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
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for ImageSigningService.
 * Tests image signature embedding functionality for PNG and JPEG formats.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("ImageSigningService Tests")
class ImageSigningServiceTest {

    @Mock
    private KeyManagementService keyManagementService;
    
    @Mock
    private ImageFormatDetectionService formatDetectionService;
    
    @Mock
    private ImageSignatureRepository imageSignatureRepository;

    @InjectMocks
    private ImageSigningService imageSigningService;

    private byte[] mockPngImageData;
    private byte[] mockJpegImageData;
    private SigningKey mockSigningKey;

    @BeforeEach
    void setUp() {
        // Clear security context
        SecurityContextHolder.clearContext();
        
        // Set up authentication
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
            "testuser", "password", List.of(new SimpleGrantedAuthority("ROLE_KEY_OPERATOR")));
        SecurityContextHolder.getContext().setAuthentication(auth);

        // Create mock image data
        mockPngImageData = createMockPngData();
        mockJpegImageData = createMockJpegData();
        
        // Create mock signing key
        mockSigningKey = createMockSigningKey();
    }

    @Nested
    @DisplayName("Image Signing Tests")
    class ImageSigningTests {

        @Test
        @DisplayName("Should successfully sign PNG image")
        void shouldSuccessfullySignPngImage() {
            // Arrange
            String imageName = "test.png";
            
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.valid(
                    com.certificateauthority.entity.ImageFormat.PNG, "image/png", imageName);
            when(formatDetectionService.detectFormat(mockPngImageData, imageName))
                .thenReturn(formatResult);
            when(formatDetectionService.isSupportedFormat(com.certificateauthority.entity.ImageFormat.PNG))
                .thenReturn(true);

            KeyManagementService.KeyManagementResult keyResult = 
                new KeyManagementService.KeyManagementResult(true, "Success", mockSigningKey, null, null);
            when(keyManagementService.getSigningKey()).thenReturn(keyResult);

            ImageSignature savedSignature = new ImageSignature();
            savedSignature.setId(UUID.randomUUID());
            when(imageSignatureRepository.save(any(ImageSignature.class))).thenReturn(savedSignature);

            // Act
            ImageSigningService.SigningResult result = imageSigningService.signImage(
                mockPngImageData, imageName, null);

            // Assert
            assertTrue(result.isSuccess());
            assertNotNull(result.getSignedImageData());
            assertNotNull(result.getImageSignature());
            assertEquals("Signing successful", result.getMessage());
            
            verify(formatDetectionService).detectFormat(mockPngImageData, imageName);
            verify(keyManagementService).getSigningKey();
            verify(imageSignatureRepository).save(any(ImageSignature.class));
        }

        @Test
        @DisplayName("Should successfully sign JPEG image")
        void shouldSuccessfullySignJpegImage() {
            // Arrange
            String imageName = "test.jpg";
            
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.valid(
                    com.certificateauthority.entity.ImageFormat.JPEG, "image/jpeg", imageName);
            when(formatDetectionService.detectFormat(mockJpegImageData, imageName))
                .thenReturn(formatResult);
            when(formatDetectionService.isSupportedFormat(com.certificateauthority.entity.ImageFormat.JPEG))
                .thenReturn(true);

            KeyManagementService.KeyManagementResult keyResult = 
                new KeyManagementService.KeyManagementResult(true, "Success", mockSigningKey, null, null);
            when(keyManagementService.getSigningKey()).thenReturn(keyResult);

            ImageSignature savedSignature = new ImageSignature();
            savedSignature.setId(UUID.randomUUID());
            when(imageSignatureRepository.save(any(ImageSignature.class))).thenReturn(savedSignature);

            // Act
            ImageSigningService.SigningResult result = imageSigningService.signImage(
                mockJpegImageData, imageName, null);

            // Assert
            assertTrue(result.isSuccess());
            assertNotNull(result.getSignedImageData());
            assertNotNull(result.getImageSignature());
            assertEquals("Signing successful", result.getMessage());
        }

        @Test
        @DisplayName("Should sign with specific algorithm")
        void shouldSignWithSpecificAlgorithm() {
            // Arrange
            String imageName = "test.png";
            String algorithm = "ECDSA_P256";
            
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.valid(
                    com.certificateauthority.entity.ImageFormat.PNG, "image/png", imageName);
            when(formatDetectionService.detectFormat(mockPngImageData, imageName))
                .thenReturn(formatResult);
            when(formatDetectionService.isSupportedFormat(com.certificateauthority.entity.ImageFormat.PNG))
                .thenReturn(true);

            SigningKey ecdsaKey = createMockSigningKey();
            ecdsaKey.setAlgorithm("ECDSA_P256");
            
            KeyManagementService.KeyManagementResult keyResult = 
                new KeyManagementService.KeyManagementResult(true, "Success", ecdsaKey, null, null);
            when(keyManagementService.getSigningKey(algorithm)).thenReturn(keyResult);

            ImageSignature savedSignature = new ImageSignature();
            savedSignature.setId(UUID.randomUUID());
            when(imageSignatureRepository.save(any(ImageSignature.class))).thenReturn(savedSignature);

            // Act
            ImageSigningService.SigningResult result = imageSigningService.signImage(
                mockPngImageData, imageName, algorithm);

            // Assert
            assertTrue(result.isSuccess());
            verify(keyManagementService).getSigningKey(algorithm);
        }

        @Test
        @DisplayName("Should fail when image data is empty")
        void shouldFailWhenImageDataIsEmpty() {
            // Act
            ImageSigningService.SigningResult result = imageSigningService.signImage(
                new byte[0], "test.png", null);

            // Assert
            assertFalse(result.isSuccess());
            assertEquals("Image data is empty", result.getMessage());
        }

        @Test
        @DisplayName("Should fail when image format is invalid")
        void shouldFailWhenImageFormatIsInvalid() {
            // Arrange
            String imageName = "test.txt";
            
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.invalid("Not an image file");
            when(formatDetectionService.detectFormat(any(), eq(imageName)))
                .thenReturn(formatResult);

            // Act
            ImageSigningService.SigningResult result = imageSigningService.signImage(
                mockPngImageData, imageName, null);

            // Assert
            assertFalse(result.isSuccess());
            assertTrue(result.getMessage().contains("Invalid image format"));
        }

        @Test
        @DisplayName("Should fail when format is not supported")
        void shouldFailWhenFormatNotSupported() {
            // Arrange
            String imageName = "test.gif";
            
            // Simulate GIF detection (not supported)
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.valid(
                    com.certificateauthority.entity.ImageFormat.PNG, "image/gif", imageName);
            when(formatDetectionService.detectFormat(any(), eq(imageName)))
                .thenReturn(formatResult);
            when(formatDetectionService.isSupportedFormat(com.certificateauthority.entity.ImageFormat.PNG))
                .thenReturn(false);

            // Act
            ImageSigningService.SigningResult result = imageSigningService.signImage(
                mockPngImageData, imageName, null);

            // Assert
            assertFalse(result.isSuccess());
            assertTrue(result.getMessage().contains("Unsupported image format"));
        }

        @Test
        @DisplayName("Should fail when signing key is not available")
        void shouldFailWhenSigningKeyNotAvailable() {
            // Arrange
            String imageName = "test.png";
            
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.valid(
                    com.certificateauthority.entity.ImageFormat.PNG, "image/png", imageName);
            when(formatDetectionService.detectFormat(mockPngImageData, imageName))
                .thenReturn(formatResult);
            when(formatDetectionService.isSupportedFormat(com.certificateauthority.entity.ImageFormat.PNG))
                .thenReturn(true);

            KeyManagementService.KeyManagementResult keyResult = 
                new KeyManagementService.KeyManagementResult(false, "No active key found", null, null, null);
            when(keyManagementService.getSigningKey()).thenReturn(keyResult);

            // Act
            ImageSigningService.SigningResult result = imageSigningService.signImage(
                mockPngImageData, imageName, null);

            // Assert
            assertFalse(result.isSuccess());
            assertTrue(result.getMessage().contains("Failed to obtain signing key"));
        }
    }

    @Nested
    @DisplayName("Signature Extraction Tests")
    class SignatureExtractionTests {

        @Test
        @DisplayName("Should extract signature from PNG image")
        void shouldExtractSignatureFromPngImage() {
            // Arrange
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.valid(
                    com.certificateauthority.entity.ImageFormat.PNG, "image/png", "test.png");
            when(formatDetectionService.detectFormat(mockPngImageData, null))
                .thenReturn(formatResult);

            // Act
            ImageSigningService.SignatureExtractionResult result = 
                imageSigningService.extractSignature(mockPngImageData);

            // Assert
            assertTrue(result.isSuccess());
            assertEquals("Extraction successful", result.getMessage());
            assertEquals("PNG iTXt extraction", result.getExtractionMethod());
        }

        @Test
        @DisplayName("Should extract signature from JPEG image")
        void shouldExtractSignatureFromJpegImage() {
            // Arrange
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.valid(
                    com.certificateauthority.entity.ImageFormat.JPEG, "image/jpeg", "test.jpg");
            when(formatDetectionService.detectFormat(mockJpegImageData, null))
                .thenReturn(formatResult);

            // Act
            ImageSigningService.SignatureExtractionResult result = 
                imageSigningService.extractSignature(mockJpegImageData);

            // Assert
            assertTrue(result.isSuccess());
            assertEquals("Extraction successful", result.getMessage());
            assertEquals("JPEG COM extraction", result.getExtractionMethod());
        }

        @Test
        @DisplayName("Should fail extraction for invalid format")
        void shouldFailExtractionForInvalidFormat() {
            // Arrange
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.invalid("Invalid format");
            when(formatDetectionService.detectFormat(any(), isNull()))
                .thenReturn(formatResult);

            // Act
            ImageSigningService.SignatureExtractionResult result = 
                imageSigningService.extractSignature(mockPngImageData);

            // Assert
            assertFalse(result.isSuccess());
            assertTrue(result.getMessage().contains("Invalid image format"));
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle large image within size limits")
        void shouldHandleLargeImageWithinSizeLimits() {
            // Arrange
            byte[] largeImageData = new byte[50 * 1024 * 1024]; // 50MB
            // Fill with PNG header
            System.arraycopy(createMockPngData(), 0, largeImageData, 0, 8);
            
            String imageName = "large.png";
            
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.valid(
                    com.certificateauthority.entity.ImageFormat.PNG, "image/png", imageName);
            when(formatDetectionService.detectFormat(largeImageData, imageName))
                .thenReturn(formatResult);
            when(formatDetectionService.isSupportedFormat(com.certificateauthority.entity.ImageFormat.PNG))
                .thenReturn(true);

            KeyManagementService.KeyManagementResult keyResult = 
                new KeyManagementService.KeyManagementResult(true, "Success", mockSigningKey, null, null);
            when(keyManagementService.getSigningKey()).thenReturn(keyResult);

            ImageSignature savedSignature = new ImageSignature();
            savedSignature.setId(UUID.randomUUID());
            when(imageSignatureRepository.save(any(ImageSignature.class))).thenReturn(savedSignature);

            // Act
            ImageSigningService.SigningResult result = imageSigningService.signImage(
                largeImageData, imageName, null);

            // Assert
            assertTrue(result.isSuccess());
            assertNotNull(result.getSignedImageData());
        }

        @Test
        @DisplayName("Should preserve image data integrity")
        void shouldPreserveImageDataIntegrity() {
            // Arrange
            String imageName = "test.png";
            
            ImageFormatDetectionService.ImageFormatResult formatResult = 
                ImageFormatDetectionService.ImageFormatResult.valid(
                    com.certificateauthority.entity.ImageFormat.PNG, "image/png", imageName);
            when(formatDetectionService.detectFormat(mockPngImageData, imageName))
                .thenReturn(formatResult);
            when(formatDetectionService.isSupportedFormat(com.certificateauthority.entity.ImageFormat.PNG))
                .thenReturn(true);

            KeyManagementService.KeyManagementResult keyResult = 
                new KeyManagementService.KeyManagementResult(true, "Success", mockSigningKey, null, null);
            when(keyManagementService.getSigningKey()).thenReturn(keyResult);

            ImageSignature savedSignature = new ImageSignature();
            savedSignature.setId(UUID.randomUUID());
            when(imageSignatureRepository.save(any(ImageSignature.class))).thenReturn(savedSignature);

            // Act
            ImageSigningService.SigningResult result = imageSigningService.signImage(
                mockPngImageData, imageName, null);

            // Assert
            assertTrue(result.isSuccess());
            
            // Verify core image data is preserved (in this mock implementation, it's the same)
            // In a real implementation, you'd verify the image can still be opened by image viewers
            assertNotNull(result.getSignedImageData());
            assertTrue(result.getSignedImageData().length >= mockPngImageData.length);
        }
    }

    // ==================== Helper Methods ====================

    private byte[] createMockPngData() {
        // PNG magic bytes + minimal data
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

    private byte[] createMockJpegData() {
        // JPEG magic bytes + minimal data
        return new byte[]{
            (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, // JPEG signature + APP0
            0x00, 0x10, // APP0 segment length
            0x4A, 0x46, 0x49, 0x46, 0x00, // "JFIF\0"
            0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, // JFIF data
            (byte) 0xFF, (byte) 0xD9 // EOI marker
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