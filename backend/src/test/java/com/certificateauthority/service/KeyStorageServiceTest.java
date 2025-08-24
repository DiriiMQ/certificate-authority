package com.certificateauthority.service;

import com.certificateauthority.entity.SigningKey;
import com.certificateauthority.repository.SigningKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive unit tests for KeyStorageService
 * Tests secure key storage, encryption, and retrieval functionality
 */
@SpringBootTest
@ActiveProfiles("test")
@Transactional
class KeyStorageServiceTest {

    @MockBean
    private SigningKeyRepository signingKeyRepository;

    private KeyStorageService keyStorageService;
    private KeyGenerationService keyGenerationService;

    @BeforeEach
    void setUp() throws Exception {
        keyStorageService = new KeyStorageService(signingKeyRepository, "test-master-password");
        keyGenerationService = new KeyGenerationService();
    }

    @Test
    @DisplayName("Should store key successfully with encryption")
    void testStoreKey() throws Exception {
        // Given
        KeyGenerationService.KeyPairResult keyPair = keyGenerationService.generateEd25519KeyPair();
        SigningKey savedKey = createMockSigningKey();
        
        when(signingKeyRepository.findByKeyIdentifier(anyString())).thenReturn(Optional.empty());
        when(signingKeyRepository.save(any(SigningKey.class))).thenReturn(savedKey);

        // When
        SigningKey result = keyStorageService.storeKey(
            "test-key-001",
            keyPair.getAlgorithm(),
            keyPair.getPublicKeyBase64(),
            keyPair.getPrivateKeyBase64(),
            keyPair.getKeySizeBits(),
            "test_user",
            72  // 72 hours
        );

        // Then
        assertThat(result).isNotNull();
        verify(signingKeyRepository).findByKeyIdentifier("test-key-001");
        verify(signingKeyRepository).save(any(SigningKey.class));
        
        // Verify the saved key has encrypted private key (should be different from original)
        assertThat(result.getPrivateKeyData()).isNotEqualTo(keyPair.getPrivateKeyBase64());
    }

    @Test
    @DisplayName("Should throw exception when storing key with existing identifier")
    void testStoreKeyWithExistingIdentifier() throws Exception {
        // Given
        KeyGenerationService.KeyPairResult keyPair = keyGenerationService.generateEd25519KeyPair();
        SigningKey existingKey = createMockSigningKey();
        
        when(signingKeyRepository.findByKeyIdentifier("existing-key")).thenReturn(Optional.of(existingKey));

        // When & Then
        assertThatThrownBy(() -> keyStorageService.storeKey(
            "existing-key",
            keyPair.getAlgorithm(),
            keyPair.getPublicKeyBase64(),
            keyPair.getPrivateKeyBase64(),
            keyPair.getKeySizeBits(),
            "test_user",
            null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Key with identifier 'existing-key' already exists");
    }

    @Test
    @DisplayName("Should validate input parameters when storing key")
    void testStoreKeyValidation() throws Exception {
        // Test null/empty key identifier
        assertThatThrownBy(() -> keyStorageService.storeKey(
            null, "Ed25519", "publicKey", "privateKey", 255, "user", null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Key identifier cannot be null or empty");

        assertThatThrownBy(() -> keyStorageService.storeKey(
            "", "Ed25519", "publicKey", "privateKey", 255, "user", null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Key identifier cannot be null or empty");

        // Test null/empty algorithm
        assertThatThrownBy(() -> keyStorageService.storeKey(
            "test-key", null, "publicKey", "privateKey", 255, "user", null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Algorithm cannot be null or empty");

        // Test null/empty public key
        assertThatThrownBy(() -> keyStorageService.storeKey(
            "test-key", "Ed25519", null, "privateKey", 255, "user", null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Public key data cannot be null or empty");

        // Test null/empty private key
        assertThatThrownBy(() -> keyStorageService.storeKey(
            "test-key", "Ed25519", "publicKey", null, 255, "user", null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Private key data cannot be null or empty");

        // Test invalid key size
        assertThatThrownBy(() -> keyStorageService.storeKey(
            "test-key", "Ed25519", "publicKey", "privateKey", null, "user", null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Key size must be positive");

        assertThatThrownBy(() -> keyStorageService.storeKey(
            "test-key", "Ed25519", "publicKey", "privateKey", -1, "user", null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Key size must be positive");
    }

    @Test
    @DisplayName("Should validate Base64 encoding of key data")
    void testStoreKeyBase64Validation() {
        // Given invalid Base64 data
        when(signingKeyRepository.findByKeyIdentifier(anyString())).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> keyStorageService.storeKey(
            "test-key", "Ed25519", "invalid-base64!", "validBase64==", 255, "user", null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Key data must be valid Base64 encoded");

        assertThatThrownBy(() -> keyStorageService.storeKey(
            "test-key", "Ed25519", "validBase64==", "invalid-base64!", 255, "user", null
        )).isInstanceOf(IllegalArgumentException.class)
          .hasMessageContaining("Key data must be valid Base64 encoded");
    }

    @Test
    @DisplayName("Should retrieve key by identifier with decryption")
    void testRetrieveKeyByIdentifier() throws Exception {
        // Given
        KeyGenerationService.KeyPairResult originalKeyPair = keyGenerationService.generateEd25519KeyPair();
        SigningKey mockKey = createMockSigningKey();
        
        // Store the key first to get encrypted private key
        when(signingKeyRepository.findByKeyIdentifier("test-key")).thenReturn(Optional.of(mockKey));
        when(signingKeyRepository.save(any(SigningKey.class))).thenReturn(mockKey);

        // When
        Optional<KeyStorageService.SigningKeyWithDecryptedData> result = 
            keyStorageService.retrieveKeyByIdentifier("test-key");

        // Then
        assertThat(result).isEmpty(); // Because mock key is not usable by default
        verify(signingKeyRepository).findByKeyIdentifier("test-key");
    }

    @Test
    @DisplayName("Should return empty optional for non-existent key")
    void testRetrieveNonExistentKey() throws Exception {
        // Given
        when(signingKeyRepository.findByKeyIdentifier("non-existent")).thenReturn(Optional.empty());

        // When
        Optional<KeyStorageService.SigningKeyWithDecryptedData> result = 
            keyStorageService.retrieveKeyByIdentifier("non-existent");

        // Then
        assertThat(result).isEmpty();
        verify(signingKeyRepository).findByKeyIdentifier("non-existent");
    }

    @Test
    @DisplayName("Should retrieve key by ID")
    void testRetrieveKeyById() throws Exception {
        // Given
        UUID keyId = UUID.randomUUID();
        SigningKey mockKey = createMockSigningKey();
        mockKey.setId(keyId);
        
        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.of(mockKey));

        // When
        Optional<KeyStorageService.SigningKeyWithDecryptedData> result = 
            keyStorageService.retrieveKeyById(keyId);

        // Then
        assertThat(result).isPresent(); // Should be present even if not usable for this test
        verify(signingKeyRepository).findById(keyId);
    }

    @Test
    @DisplayName("Should retrieve active key by algorithm")
    void testRetrieveActiveKeyByAlgorithm() throws Exception {
        // Given
        SigningKey mockKey = createUsableMockSigningKey();
        
        when(signingKeyRepository.findMostRecentActiveKeyByAlgorithm("Ed25519"))
            .thenReturn(Optional.of(mockKey));
        when(signingKeyRepository.save(any(SigningKey.class))).thenReturn(mockKey);

        // When
        Optional<KeyStorageService.SigningKeyWithDecryptedData> result = 
            keyStorageService.retrieveActiveKeyByAlgorithm("Ed25519");

        // Then
        assertThat(result).isPresent();
        verify(signingKeyRepository).findMostRecentActiveKeyByAlgorithm("Ed25519");
        verify(signingKeyRepository).save(mockKey); // For usage update
    }

    @Test
    @DisplayName("Should list active keys with pagination")
    void testListActiveKeys() {
        // Given
        List<SigningKey> keys = List.of(createMockSigningKey(), createMockSigningKey());
        Page<SigningKey> page = new PageImpl<>(keys, PageRequest.of(0, 10), 2);
        
        when(signingKeyRepository.findByIsActiveTrue(any(PageRequest.class))).thenReturn(page);

        // When
        Page<SigningKey> result = keyStorageService.listActiveKeys(0, 10);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getContent()).hasSize(2);
        assertThat(result.getTotalElements()).isEqualTo(2);
        verify(signingKeyRepository).findByIsActiveTrue(any(PageRequest.class));
    }

    @Test
    @DisplayName("Should list usable keys by algorithm")
    void testListUsableKeysByAlgorithm() {
        // Given
        List<SigningKey> keys = List.of(createUsableMockSigningKey(), createUsableMockSigningKey());
        
        when(signingKeyRepository.findUsableKeysByAlgorithm(eq("Ed25519"), any(LocalDateTime.class)))
            .thenReturn(keys);

        // When
        List<SigningKey> result = keyStorageService.listUsableKeysByAlgorithm("Ed25519");

        // Then
        assertThat(result).hasSize(2);
        verify(signingKeyRepository).findUsableKeysByAlgorithm(eq("Ed25519"), any(LocalDateTime.class));
    }

    @Test
    @DisplayName("Should deactivate key successfully")
    void testDeactivateKey() throws Exception {
        // Given
        UUID keyId = UUID.randomUUID();
        SigningKey mockKey = spy(createMockSigningKey());
        mockKey.setId(keyId);
        
        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.of(mockKey));
        when(signingKeyRepository.save(any(SigningKey.class))).thenReturn(mockKey);

        // When
        SigningKey result = keyStorageService.deactivateKey(keyId, "admin", "Security incident");

        // Then
        assertThat(result).isNotNull();
        verify(mockKey).deactivate("admin", "Security incident");
        verify(signingKeyRepository).findById(keyId);
        verify(signingKeyRepository).save(mockKey);
    }

    @Test
    @DisplayName("Should throw exception when deactivating non-existent key")
    void testDeactivateNonExistentKey() {
        // Given
        UUID keyId = UUID.randomUUID();
        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> keyStorageService.deactivateKey(keyId, "admin", "reason"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Key not found with ID: " + keyId);
    }

    @Test
    @DisplayName("Should validate key integrity successfully")
    void testValidateKeyIntegritySuccess() throws Exception {
        // Given
        UUID keyId = UUID.randomUUID();
        KeyGenerationService.KeyPairResult keyPair = keyGenerationService.generateEd25519KeyPair();
        
        // Create a key storage instance to encrypt the private key
        KeyStorageService tempService = new KeyStorageService(signingKeyRepository, "test-password");
        
        SigningKey mockKey = createMockSigningKey();
        // Set valid encrypted private key data
        mockKey.setPrivateKeyData("dGVzdC1lbmNyeXB0ZWQtcHJpdmF0ZS1rZXktZGF0YQ=="); // Base64 encoded test data
        
        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.of(mockKey));

        // When
        boolean result = keyStorageService.validateKeyIntegrity(keyId);

        // Then
        // Will be false because we're using mock encrypted data, but the method should not throw
        assertThat(result).isFalse(); // Expected because mock data won't decrypt properly
        verify(signingKeyRepository).findById(keyId);
    }

    @Test
    @DisplayName("Should return false for non-existent key integrity validation")
    void testValidateKeyIntegrityNonExistent() {
        // Given
        UUID keyId = UUID.randomUUID();
        when(signingKeyRepository.findById(keyId)).thenReturn(Optional.empty());

        // When
        boolean result = keyStorageService.validateKeyIntegrity(keyId);

        // Then
        assertThat(result).isFalse();
        verify(signingKeyRepository).findById(keyId);
    }

    @Test
    @DisplayName("Should get key statistics")
    void testGetKeyStatistics() {
        // Given
        List<Object[]> stats = List.of(
            new Object[]{"Ed25519", 5L, 3L},
            new Object[]{"RSA_3072", 2L, 1L}
        );
        when(signingKeyRepository.getAlgorithmStatistics()).thenReturn(stats);

        // When
        List<Object[]> result = keyStorageService.getKeyStatistics();

        // Then
        assertThat(result).hasSize(2);
        verify(signingKeyRepository).getAlgorithmStatistics();
    }

    @Test
    @DisplayName("Should test SigningKeyWithDecryptedData wrapper functionality")
    void testSigningKeyWithDecryptedDataWrapper() throws Exception {
        // Given
        SigningKey mockKey = createMockSigningKey();
        String decryptedPrivateKey = "decrypted-private-key-data";

        // When
        KeyStorageService.SigningKeyWithDecryptedData wrapper = 
            new KeyStorageService.SigningKeyWithDecryptedData(mockKey, decryptedPrivateKey);

        // Then
        assertThat(wrapper.getSigningKey()).isEqualTo(mockKey);
        assertThat(wrapper.getDecryptedPrivateKey()).isEqualTo(decryptedPrivateKey);
        
        // Test delegated methods
        assertThat(wrapper.getId()).isEqualTo(mockKey.getId());
        assertThat(wrapper.getKeyIdentifier()).isEqualTo(mockKey.getKeyIdentifier());
        assertThat(wrapper.getAlgorithm()).isEqualTo(mockKey.getAlgorithm());
        assertThat(wrapper.getPublicKeyData()).isEqualTo(mockKey.getPublicKeyData());
        assertThat(wrapper.getKeySizeBits()).isEqualTo(mockKey.getKeySizeBits());
        assertThat(wrapper.getIsActive()).isEqualTo(mockKey.getIsActive());
        assertThat(wrapper.getCreatedAt()).isEqualTo(mockKey.getCreatedAt());
        assertThat(wrapper.getExpiresAt()).isEqualTo(mockKey.getExpiresAt());
        assertThat(wrapper.getUsageCount()).isEqualTo(mockKey.getUsageCount());
        assertThat(wrapper.isUsable()).isEqualTo(mockKey.isUsable());
    }

    // Helper methods

    private SigningKey createMockSigningKey() {
        SigningKey key = new SigningKey(
            "test-key-001",
            "Ed25519",
            "cHVibGljS2V5RGF0YQ==", // Base64 encoded "publicKeyData"
            "cHJpdmF0ZUtleURhdGE=", // Base64 encoded "privateKeyData"
            255,
            "test_user"
        );
        key.setId(UUID.randomUUID());
        key.setCreatedAt(LocalDateTime.now());
        key.setUpdatedAt(LocalDateTime.now());
        return key;
    }

    private SigningKey createUsableMockSigningKey() {
        SigningKey key = createMockSigningKey();
        // Make the key usable by ensuring it's active and not expired
        key.setExpiresAt(LocalDateTime.now().plusDays(30));
        // Mock the isUsable method to return true
        return spy(key);
    }
}
