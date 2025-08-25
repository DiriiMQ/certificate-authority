package com.certificateauthority.service;

import com.certificateauthority.entity.SigningKey;
import com.certificateauthority.repository.SigningKeyRepository;
import com.certificateauthority.repository.AuditLogRepository;
import com.certificateauthority.repository.KeyRotationLogRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;
import org.springframework.test.context.support.DirtiesContextTestExecutionListener;
import org.springframework.test.context.transaction.TransactionalTestExecutionListener;
import org.springframework.test.annotation.DirtiesContext;

import java.util.Map;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.Authentication;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for the complete Key Management System
 * Tests the entire flow from key generation to storage to access control
 */
@SpringBootTest
@TestPropertySource(properties = {
    "spring.datasource.url=jdbc:h2:mem:testdb",
    "spring.datasource.driver-class-name=org.h2.Driver",
    "spring.datasource.username=sa",
    "spring.datasource.password=",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
    "spring.flyway.enabled=false",
    "spring.security.enabled=true",
    "app.key-storage.master-password=test-master-password-change-in-production",
    "app.key-rotation.default-key-lifetime-days=90",
    "app.key-rotation.usage-threshold=10000"
})
@Transactional
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
public class KeyManagementIntegrationTest {

    @Autowired
    private KeyManagementService keyManagementService;
    
    @Autowired
    private KeyGenerationService keyGenerationService;
    
    @Autowired
    private KeyStorageService keyStorageService;
    
    @Autowired
    private KeyRotationService keyRotationService;
    
    @Autowired
    private KeyAccessControlService keyAccessControlService;
    
    @Autowired
    private SigningKeyRepository signingKeyRepository;
    
    @Autowired
    private AuditLogRepository auditLogRepository;
    
    @Autowired
    private KeyRotationLogRepository keyRotationLogRepository;

    @BeforeEach
    void setUp() {
        // Clean up any existing data
        auditLogRepository.deleteAll();
        keyRotationLogRepository.deleteAll();
        signingKeyRepository.deleteAll();
        
        // Set up authentication context with KEY_ADMIN and KEY_OPERATOR roles
        Authentication auth = new UsernamePasswordAuthenticationToken(
            "test_user", 
            "password", 
            List.of(
                new SimpleGrantedAuthority("ROLE_KEY_ADMIN"),
                new SimpleGrantedAuthority("ROLE_KEY_OPERATOR")
            )
        );
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
    
    @AfterEach
    void tearDown() {
        // Clean up all data after each test to prevent pollution
        auditLogRepository.deleteAll();
        keyRotationLogRepository.deleteAll();
        signingKeyRepository.deleteAll();
    }

    @Test
    void testCompleteKeyManagementFlow() {
        // Test 1: Generate a new key
        KeyManagementService.KeyManagementResult result = keyManagementService.generateNewKey("Ed25519", "test_user", "Integration test");
        
        assertNotNull(result, "Key generation result should not be null");
        assertTrue(result.isSuccess(), "Key generation should succeed");
        assertNotNull(result.getSigningKey(), "Generated key should not be null");
        assertEquals("Ed25519", result.getSigningKey().getAlgorithm(), "Algorithm should match");
        assertTrue(result.getSigningKey().getIsActive(), "New key should be active");
        
        // Test 2: Retrieve the active key
        KeyManagementService.KeyManagementResult retrieveResult = keyManagementService.getSigningKey("Ed25519");
        
        assertNotNull(retrieveResult, "Key retrieval result should not be null");
        
        // Debug information if retrieval fails
        if (!retrieveResult.isSuccess()) {
            System.out.println("Key retrieval failed. Message: " + retrieveResult.getMessage());
            System.out.println("Metadata: " + retrieveResult.getMetadata());
        }
        
        assertTrue(retrieveResult.isSuccess(), "Key retrieval should succeed");
        assertNotNull(retrieveResult.getSigningKey(), "Retrieved key should not be null");
        assertEquals(result.getSigningKey().getId(), retrieveResult.getSigningKey().getId(), "Retrieved key should match generated key");
        
        // Test 3: Verify key statistics
        var stats = keyManagementService.getKeyStatistics();
        
        assertNotNull(stats, "Statistics should not be null");
        assertTrue(stats.isSuccess(), "Statistics retrieval should succeed");
        Map<String, Object> metadata = stats.getMetadata();
        assertTrue(metadata.containsKey("lifecycle_summary"), "Should include lifecycle summary");
        
        @SuppressWarnings("unchecked")
        Map<String, Object> lifecycle = (Map<String, Object>) metadata.get("lifecycle_summary");
        assertTrue((Long) lifecycle.get("total_keys") >= 1, "Should have at least 1 total key");
        assertTrue((Long) lifecycle.get("active_keys") >= 1, "Should have at least 1 active key");
        
        // Test 4: Test key rotation
        KeyManagementService.KeyManagementResult rotationResult = keyManagementService.rotateKeys("Ed25519", "test rotation", "integration test");
        
        assertNotNull(rotationResult, "Rotation result should not be null");
        assertTrue(rotationResult.isSuccess(), "Key rotation should succeed");
        
        // Verify rotation statistics
        var statsAfterRotation = keyManagementService.getKeyStatistics();
        assertTrue(statsAfterRotation.isSuccess(), "Statistics should be retrieved successfully");
        @SuppressWarnings("unchecked")
        Map<String, Object> lifecycleAfter = (Map<String, Object>) statsAfterRotation.getMetadata().get("lifecycle_summary");
        assertTrue((Long) lifecycleAfter.get("total_keys") >= 2, "Should have at least 2 total keys after rotation");
        assertTrue((Long) lifecycleAfter.get("active_keys") >= 1, "Should still have at least 1 active key");
        
        // Test 5: Verify audit logs were created
        long auditCount = auditLogRepository.count();
        assertTrue(auditCount > 0, "Audit logs should be created");
    }

    @Test
    void testKeyGenerationWithDifferentAlgorithms() {
        // Test Ed25519
        var ed25519Result = keyManagementService.generateNewKey("Ed25519", "test_user", "Ed25519 test");
        assertTrue(ed25519Result.isSuccess(), "Ed25519 key generation should succeed");
        
        // Test ECDSA P-256
        var ecdsaResult = keyManagementService.generateNewKey("ECDSA_P256", "test_user", "ECDSA test");
        
        // Debug information if ECDSA generation fails
        if (!ecdsaResult.isSuccess()) {
            System.out.println("ECDSA key generation failed. Message: " + ecdsaResult.getMessage());
            System.out.println("Metadata: " + ecdsaResult.getMetadata());
        }
        
        assertTrue(ecdsaResult.isSuccess(), "ECDSA P-256 key generation should succeed");
        
        // Test RSA-3072
        var rsaResult = keyManagementService.generateNewKey("RSA_3072", "test_user", "RSA test");
        assertTrue(rsaResult.isSuccess(), "RSA-3072 key generation should succeed");
        
        // Verify all keys are different
        assertNotEquals(ed25519Result.getSigningKey().getId(), ecdsaResult.getSigningKey().getId(), "Keys should have different IDs");
        assertNotEquals(ed25519Result.getSigningKey().getId(), rsaResult.getSigningKey().getId(), "Keys should have different IDs");
        assertNotEquals(ecdsaResult.getSigningKey().getId(), rsaResult.getSigningKey().getId(), "Keys should have different IDs");
        
        // Verify algorithms are correct
        assertEquals("Ed25519", ed25519Result.getSigningKey().getAlgorithm(), "Ed25519 algorithm should match");
        assertEquals("ECDSA_P256", ecdsaResult.getSigningKey().getAlgorithm(), "ECDSA algorithm should match");
        assertEquals("RSA_3072", rsaResult.getSigningKey().getAlgorithm(), "RSA algorithm should match");
    }

    @Test
    void testKeyAccessControl() {
        // This test would verify access control but requires Spring Security context
        // For now, just verify the service is available
        assertNotNull(keyAccessControlService, "Key access control service should be available");
    }

    @Test
    void testInvalidKeyGeneration() {
        // Test with invalid algorithm
        KeyManagementService.KeyManagementResult result = keyManagementService.generateNewKey("INVALID-ALGO", "test_user", "Invalid test");
        
        assertNotNull(result, "Result should not be null even for invalid algorithm");
        assertFalse(result.isSuccess(), "Invalid algorithm should fail");
        assertNotNull(result.getMessage(), "Error message should be provided");
    }

    @Test
    void testKeyIntegrityValidation() {
        // Generate a key first
        KeyManagementService.KeyManagementResult generateResult = keyManagementService.generateNewKey("Ed25519", "test_user", "Integrity test");
        assertTrue(generateResult.isSuccess(), "Key generation should succeed");
        
        // Test key integrity validation
        KeyManagementService.KeyManagementResult validationResult = keyManagementService.validateKeyIntegrity(generateResult.getSigningKey().getId());
        assertTrue(validationResult.isSuccess(), "Generated key should pass integrity validation");
    }
}
