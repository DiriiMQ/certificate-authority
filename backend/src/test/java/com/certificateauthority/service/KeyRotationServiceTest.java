package com.certificateauthority.service;

import com.certificateauthority.entity.KeyRotationLog;
import com.certificateauthority.entity.SigningKey;
import com.certificateauthority.repository.KeyRotationLogRepository;
import com.certificateauthority.repository.SigningKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive unit tests for KeyRotationService
 * Tests key rotation policies, scheduling, and lifecycle management
 */
@SpringBootTest
@ActiveProfiles("test")
class KeyRotationServiceTest {

    @MockBean
    private KeyGenerationService keyGenerationService;

    @MockBean
    private KeyStorageService keyStorageService;

    @MockBean
    private SigningKeyRepository signingKeyRepository;

    @MockBean
    private KeyRotationLogRepository keyRotationLogRepository;

    private KeyRotationService keyRotationService;

    @BeforeEach
    void setUp() {
        keyRotationService = new KeyRotationService(
            keyGenerationService, keyStorageService, 
            signingKeyRepository, keyRotationLogRepository
        );
        
        // Set test configuration values
        ReflectionTestUtils.setField(keyRotationService, "defaultKeyLifetimeDays", 90);
        ReflectionTestUtils.setField(keyRotationService, "usageThreshold", 10000L);
        ReflectionTestUtils.setField(keyRotationService, "overlapPeriodHours", 24);
        ReflectionTestUtils.setField(keyRotationService, "autoRotationEnabled", true);
        ReflectionTestUtils.setField(keyRotationService, "emergencyDeactivationDelayHours", 1);
    }

    @Test
    @DisplayName("Should rotate key successfully")
    void testRotateKeySuccess() throws Exception {
        // Given
        UUID keyId = UUID.randomUUID();
        SigningKey oldKey = createMockSigningKey("old-key", true);
        oldKey.setId(keyId);
        
        KeyGenerationService.KeyPairResult newKeyPair = createMockKeyPairResult();
        SigningKey newKey = createMockSigningKey("new-key", true);
        KeyRotationLog rotationLog = createMockRotationLog(oldKey, newKey);

        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.of(oldKey));
        when(keyGenerationService.generateKeyPair("Ed25519")).thenReturn(newKeyPair);
        when(keyStorageService.storeKey(anyString(), anyString(), anyString(), anyString(), 
            anyInt(), anyString(), anyInt())).thenReturn(newKey);
        when(keyRotationLogRepository.save(any(KeyRotationLog.class))).thenReturn(rotationLog);

        // When
        KeyRotationService.RotationResult result = keyRotationService.rotateKey(
            keyId, "admin", KeyRotationLog.RotationReason.ADMINISTRATOR_REQUEST, "Manual rotation test"
        );

        // Then
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getMessage()).contains("Key rotated successfully");
        assertThat(result.getOldKey()).isEqualTo(oldKey);
        assertThat(result.getNewKey()).isEqualTo(newKey);
        assertThat(result.getRotationLog()).isEqualTo(rotationLog);

        verify(signingKeyRepository).findById(keyId);
        verify(keyGenerationService).generateKeyPair("Ed25519");
        verify(keyStorageService).storeKey(anyString(), eq("Ed25519"), 
            anyString(), anyString(), eq(255), eq("admin"), eq(90 * 24));
        verify(keyRotationLogRepository, atLeast(1)).save(any(KeyRotationLog.class));
    }

    @Test
    @DisplayName("Should fail to rotate non-existent key")
    void testRotateNonExistentKey() {
        // Given
        UUID keyId = UUID.randomUUID();
        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.empty());

        // When
        KeyRotationService.RotationResult result = keyRotationService.rotateKey(
            keyId, "admin", KeyRotationLog.RotationReason.ADMINISTRATOR_REQUEST, "Test"
        );

        // Then
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getMessage()).contains("Key not found with ID: " + keyId);
        verify(signingKeyRepository).findById(keyId);
        verifyNoInteractions(keyGenerationService, keyStorageService);
    }

    @Test
    @DisplayName("Should fail to rotate inactive key")
    void testRotateInactiveKey() {
        // Given
        UUID keyId = UUID.randomUUID();
        SigningKey inactiveKey = createMockSigningKey("inactive-key", false);
        inactiveKey.setId(keyId);
        
        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.of(inactiveKey));

        // When
        KeyRotationService.RotationResult result = keyRotationService.rotateKey(
            keyId, "admin", KeyRotationLog.RotationReason.ADMINISTRATOR_REQUEST, "Test"
        );

        // Then
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getMessage()).contains("Cannot rotate inactive key: " + keyId);
        verify(signingKeyRepository).findById(keyId);
        verifyNoInteractions(keyGenerationService, keyStorageService);
    }

    @Test
    @DisplayName("Should handle key generation failure during rotation")
    void testRotateKeyGenerationFailure() throws Exception {
        // Given
        UUID keyId = UUID.randomUUID();
        SigningKey oldKey = createMockSigningKey("old-key", true);
        oldKey.setId(keyId);
        
        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.of(oldKey));
        when(keyGenerationService.generateKeyPair("Ed25519"))
            .thenThrow(new RuntimeException("Key generation failed"));

        // When
        KeyRotationService.RotationResult result = keyRotationService.rotateKey(
            keyId, "admin", KeyRotationLog.RotationReason.ADMINISTRATOR_REQUEST, "Test"
        );

        // Then
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getMessage()).contains("Key rotation failed");
        assertThat(result.getMessage()).contains("Key generation failed");
        verify(signingKeyRepository).findById(keyId);
        verify(keyGenerationService).generateKeyPair("Ed25519");
        verifyNoInteractions(keyStorageService);
    }

    @Test
    @DisplayName("Should perform emergency key rotation")
    void testEmergencyRotateKey() throws Exception {
        // Given
        UUID keyId = UUID.randomUUID();
        SigningKey oldKey = createMockSigningKey("old-key", true);
        oldKey.setId(keyId);
        
        KeyGenerationService.KeyPairResult newKeyPair = createMockKeyPairResult();
        SigningKey newKey = createMockSigningKey("new-key", true);
        KeyRotationLog rotationLog = createMockRotationLog(oldKey, newKey);

        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.of(oldKey));
        when(keyGenerationService.generateKeyPair("Ed25519")).thenReturn(newKeyPair);
        when(keyStorageService.storeKey(anyString(), anyString(), anyString(), anyString(), 
            anyInt(), anyString(), anyInt())).thenReturn(newKey);
        when(keyRotationLogRepository.save(any(KeyRotationLog.class))).thenReturn(rotationLog);
        when(signingKeyRepository.save(any(SigningKey.class))).thenReturn(oldKey);

        // When
        KeyRotationService.RotationResult result = keyRotationService.emergencyRotateKey(
            keyId, "admin", "Security incident detected"
        );

        // Then
        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getMessage()).contains("Emergency rotation completed successfully");
        assertThat(result.getOldKey()).isEqualTo(oldKey);
        assertThat(result.getNewKey()).isEqualTo(newKey);

        verify(signingKeyRepository).findById(keyId);
        verify(keyGenerationService).generateKeyPair("Ed25519");
        verify(keyStorageService).storeKey(anyString(), eq("Ed25519"), 
            anyString(), anyString(), eq(255), eq("admin"), eq(90 * 24));
        verify(keyRotationLogRepository, atLeast(1)).save(any(KeyRotationLog.class));
        verify(signingKeyRepository).save(oldKey); // For immediate deactivation
    }

    @Test
    @DisplayName("Should rotate keys by algorithm")
    void testRotateKeysByAlgorithm() throws Exception {
        // Given
        String algorithm = "Ed25519";
        SigningKey key1 = createMockSigningKey("key1", true);
        SigningKey key2 = createMockSigningKey("key2", true);
        List<SigningKey> keysToRotate = List.of(key1, key2);

        KeyGenerationService.KeyPairResult newKeyPair = createMockKeyPairResult();
        SigningKey newKey1 = createMockSigningKey("new-key1", true);
        SigningKey newKey2 = createMockSigningKey("new-key2", true);
        KeyRotationLog rotationLog1 = createMockRotationLog(key1, newKey1);
        KeyRotationLog rotationLog2 = createMockRotationLog(key2, newKey2);

        when(signingKeyRepository.findUsableKeysByAlgorithm(eq(algorithm), any(LocalDateTime.class)))
            .thenReturn(keysToRotate);
        when(signingKeyRepository.findById(key1.getId())).thenReturn(Optional.of(key1));
        when(signingKeyRepository.findById(key2.getId())).thenReturn(Optional.of(key2));
        when(keyGenerationService.generateKeyPair(algorithm)).thenReturn(newKeyPair);
        when(keyStorageService.storeKey(anyString(), anyString(), anyString(), anyString(), 
            anyInt(), anyString(), anyInt())).thenReturn(newKey1).thenReturn(newKey2);
        when(keyRotationLogRepository.save(any(KeyRotationLog.class)))
            .thenReturn(rotationLog1).thenReturn(rotationLog2);

        // When
        List<KeyRotationService.RotationResult> results = keyRotationService.rotateKeysByAlgorithm(
            algorithm, "admin", KeyRotationLog.RotationReason.ALGORITHM_UPDATE
        );

        // Then
        assertThat(results).hasSize(2);
        assertThat(results.get(0).isSuccess()).isTrue();
        assertThat(results.get(1).isSuccess()).isTrue();

        verify(signingKeyRepository).findUsableKeysByAlgorithm(eq(algorithm), any(LocalDateTime.class));
        verify(keyGenerationService, times(2)).generateKeyPair(algorithm);
        verify(keyStorageService, times(2)).storeKey(anyString(), eq(algorithm), 
            anyString(), anyString(), eq(255), eq("admin"), eq(90 * 24));
    }

    @Test
    @DisplayName("Should validate key lifecycle")
    void testValidateKeyLifecycle() {
        // Given
        UUID keyId = UUID.randomUUID();
        SigningKey key = createMockSigningKey("test-key", true);
        key.setId(keyId);
        key.setCreatedAt(LocalDateTime.now().minusDays(80)); // Old but not expired
        key.setUsageCount(8000L); // High usage but below threshold
        key.setExpiresAt(LocalDateTime.now().plusDays(5)); // Expires soon

        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.of(key));

        // When
        KeyRotationService.KeyLifecycleValidation validation = 
            keyRotationService.validateKeyLifecycle(keyId);

        // Then
        assertThat(validation.getKey()).isEqualTo(key);
        assertThat(validation.getAgeDays()).isEqualTo(80);
        assertThat(validation.getDaysToExpiration()).isEqualTo(5);
        assertThat(validation.hasRecommendations()).isTrue();
        assertThat(validation.getRecommendations()).anyMatch(r -> r.contains("approaching"));

        verify(signingKeyRepository).findById(keyId);
    }

    @Test
    @DisplayName("Should recommend rotation for old key")
    void testValidateKeyLifecycleOldKey() {
        // Given
        UUID keyId = UUID.randomUUID();
        SigningKey key = createMockSigningKey("old-key", true);
        key.setId(keyId);
        key.setCreatedAt(LocalDateTime.now().minusDays(95)); // Older than default lifetime
        key.setUsageCount(15000L); // Above usage threshold

        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.of(key));

        // When
        KeyRotationService.KeyLifecycleValidation validation = 
            keyRotationService.validateKeyLifecycle(keyId);

        // Then
        assertThat(validation.hasRecommendations()).isTrue();
        assertThat(validation.getRecommendations()).anyMatch(r -> r.contains("exceeded recommended lifetime"));
        assertThat(validation.getRecommendations()).anyMatch(r -> r.contains("exceeded usage threshold"));
    }

    @Test
    @DisplayName("Should handle validation of non-existent key")
    void testValidateKeyLifecycleNonExistent() {
        // Given
        UUID keyId = UUID.randomUUID();
        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.empty());

        // When
        KeyRotationService.KeyLifecycleValidation validation = 
            keyRotationService.validateKeyLifecycle(keyId);

        // Then
        assertThat(validation.getKey()).isNull();
        assertThat(validation.hasRecommendations()).isTrue();
        assertThat(validation.getRecommendations()).anyMatch(r -> r.contains("Error validating key"));
    }

    @Test
    @DisplayName("Should get rotation statistics")
    void testGetRotationStatistics() {
        // Given
        long totalRotations = 100L;
        long successfulRotations = 95L;
        long failedRotations = 5L;
        long recentRotations = 10L;
        
        List<Object[]> typeStats = List.of(
            new Object[]{"MANUAL_ROTATION", 50L},
            new Object[]{"SCHEDULED_ROTATION", 45L}
        );
        
        List<Object[]> reasonStats = List.of(
            new Object[]{"MANUAL", 30L},
            new Object[]{"TIME_BASED", 40L},
            new Object[]{"USAGE_BASED", 25L}
        );

        when(keyRotationLogRepository.count()).thenReturn(totalRotations);
        when(keyRotationLogRepository.countBySuccessTrue()).thenReturn(successfulRotations);
        when(keyRotationLogRepository.countBySuccessFalse()).thenReturn(failedRotations);
        when(keyRotationLogRepository.countByRotationTimestampBetween(any(), any()))
            .thenReturn(recentRotations);
        when(keyRotationLogRepository.getRotationTypeStatistics()).thenReturn(typeStats);
        when(keyRotationLogRepository.getRotationReasonStatistics()).thenReturn(reasonStats);

        // When
        KeyRotationService.RotationStatistics stats = keyRotationService.getRotationStatistics();

        // Then
        assertThat(stats.getTotalRotations()).isEqualTo(totalRotations);
        assertThat(stats.getSuccessfulRotations()).isEqualTo(successfulRotations);
        assertThat(stats.getFailedRotations()).isEqualTo(failedRotations);
        assertThat(stats.getRecentRotations()).isEqualTo(recentRotations);
        assertThat(stats.getSuccessRate()).isEqualTo(95.0);
        assertThat(stats.getRotationTypeStats()).isEqualTo(typeStats);
        assertThat(stats.getRotationReasonStats()).isEqualTo(reasonStats);
    }

    @Test
    @DisplayName("Should calculate success rate correctly")
    void testRotationStatisticsSuccessRate() {
        // Create statistics with known values
        KeyRotationService.RotationStatistics stats = new KeyRotationService.RotationStatistics();
        
        // Test with normal values
        stats.setTotalRotations(100);
        stats.setSuccessfulRotations(80);
        assertThat(stats.getSuccessRate()).isEqualTo(80.0);
        
        // Test with zero total (edge case)
        stats.setTotalRotations(0);
        stats.setSuccessfulRotations(0);
        assertThat(stats.getSuccessRate()).isEqualTo(0.0);
        
        // Test with perfect success rate
        stats.setTotalRotations(50);
        stats.setSuccessfulRotations(50);
        assertThat(stats.getSuccessRate()).isEqualTo(100.0);
    }

    @Test
    @DisplayName("Should test RotationResult class functionality")
    void testRotationResultClass() {
        // Given
        SigningKey oldKey = createMockSigningKey("old", true);
        SigningKey newKey = createMockSigningKey("new", true);
        KeyRotationLog log = createMockRotationLog(oldKey, newKey);
        Exception error = new RuntimeException("Test error");

        // When
        KeyRotationService.RotationResult successResult = new KeyRotationService.RotationResult(
            true, "Success", oldKey, newKey, log, null
        );
        
        KeyRotationService.RotationResult failureResult = new KeyRotationService.RotationResult(
            false, "Failed", null, null, null, error
        );

        // Then
        assertThat(successResult.isSuccess()).isTrue();
        assertThat(successResult.getMessage()).isEqualTo("Success");
        assertThat(successResult.getOldKey()).isEqualTo(oldKey);
        assertThat(successResult.getNewKey()).isEqualTo(newKey);
        assertThat(successResult.getRotationLog()).isEqualTo(log);
        assertThat(successResult.getError()).isNull();

        assertThat(failureResult.isSuccess()).isFalse();
        assertThat(failureResult.getMessage()).isEqualTo("Failed");
        assertThat(failureResult.getOldKey()).isNull();
        assertThat(failureResult.getNewKey()).isNull();
        assertThat(failureResult.getRotationLog()).isNull();
        assertThat(failureResult.getError()).isEqualTo(error);
    }

    @Test
    @DisplayName("Should test KeyLifecycleValidation class functionality")
    void testKeyLifecycleValidationClass() {
        // Given
        SigningKey key = createMockSigningKey("test", true);

        // When
        KeyRotationService.KeyLifecycleValidation validation = 
            new KeyRotationService.KeyLifecycleValidation(key);
        
        validation.setAgeDays(30);
        validation.setDaysToExpiration(60);
        validation.addRecommendation("Test recommendation 1");
        validation.addRecommendation("Test recommendation 2");

        // Then
        assertThat(validation.getKey()).isEqualTo(key);
        assertThat(validation.getAgeDays()).isEqualTo(30);
        assertThat(validation.getDaysToExpiration()).isEqualTo(60);
        assertThat(validation.hasRecommendations()).isTrue();
        assertThat(validation.getRecommendations()).hasSize(2);
        assertThat(validation.getRecommendations()).containsExactly(
            "Test recommendation 1", "Test recommendation 2"
        );
    }

    // Helper methods

    private SigningKey createMockSigningKey(String identifier, boolean isActive) {
        SigningKey key = new SigningKey(
            identifier, "Ed25519", "publicKey", "privateKey", 255, "test_user"
        );
        key.setId(UUID.randomUUID());
        key.setCreatedAt(LocalDateTime.now());
        key.setUpdatedAt(LocalDateTime.now());
        if (!isActive) {
            key.deactivate("system", "Test deactivation");
        }
        return key;
    }

    private KeyGenerationService.KeyPairResult createMockKeyPairResult() {
        return new KeyGenerationService.KeyPairResult(
            "Ed25519", 255, "newPublicKey", "newPrivateKey"
        );
    }

    private KeyRotationLog createMockRotationLog(SigningKey oldKey, SigningKey newKey) {
        KeyRotationLog log = new KeyRotationLog(
            oldKey, newKey, 
            KeyRotationLog.RotationType.MANUAL_ROTATION,
            KeyRotationLog.RotationReason.ADMINISTRATOR_REQUEST,
            "admin", "Test rotation"
        );
        log.setId(UUID.randomUUID());
        log.setRotationTimestamp(LocalDateTime.now());
        return log;
    }
}
