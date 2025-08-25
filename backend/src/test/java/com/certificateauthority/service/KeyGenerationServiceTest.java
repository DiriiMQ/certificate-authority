package com.certificateauthority.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

/**
 * Comprehensive unit tests for KeyGenerationService
 * Tests cryptographic key generation for all supported algorithms
 */
@SpringBootTest
@ActiveProfiles("test")
class KeyGenerationServiceTest {

    private KeyGenerationService keyGenerationService;

    @BeforeEach
    void setUp() throws Exception {
        keyGenerationService = new KeyGenerationService();
    }
    
    @AfterEach
    void tearDown() {
        // Clean up any resources (KeyGenerationService doesn't use database)
        keyGenerationService = null;
    }

    @Test
    @DisplayName("Should generate Ed25519 key pair successfully")
    void testGenerateEd25519KeyPair() throws Exception {
        // When
        KeyGenerationService.KeyPairResult result = keyGenerationService.generateEd25519KeyPair();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getAlgorithm()).isEqualTo("Ed25519");
        assertThat(result.getKeySizeBits()).isEqualTo(255);
        assertThat(result.getPublicKeyBase64()).isNotEmpty();
        assertThat(result.getPrivateKeyBase64()).isNotEmpty();
        
        // Verify Base64 encoding is valid
        assertThatCode(() -> Base64.getDecoder().decode(result.getPublicKeyBase64()))
            .doesNotThrowAnyException();
        assertThatCode(() -> Base64.getDecoder().decode(result.getPrivateKeyBase64()))
            .doesNotThrowAnyException();
        
        // Verify keys are different
        assertThat(result.getPublicKeyBase64()).isNotEqualTo(result.getPrivateKeyBase64());
    }

    @Test
    @DisplayName("Should generate ECDSA P-256 key pair successfully")
    void testGenerateEcdsaP256KeyPair() throws Exception {
        // When
        KeyGenerationService.KeyPairResult result = keyGenerationService.generateEcdsaP256KeyPair();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getAlgorithm()).isEqualTo("ECDSA_P256");
        assertThat(result.getKeySizeBits()).isEqualTo(256);
        assertThat(result.getPublicKeyBase64()).isNotEmpty();
        assertThat(result.getPrivateKeyBase64()).isNotEmpty();
        
        // Verify Base64 encoding is valid
        assertThatCode(() -> Base64.getDecoder().decode(result.getPublicKeyBase64()))
            .doesNotThrowAnyException();
        assertThatCode(() -> Base64.getDecoder().decode(result.getPrivateKeyBase64()))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Should generate RSA-3072 key pair successfully")
    void testGenerateRsa3072KeyPair() throws Exception {
        // When
        KeyGenerationService.KeyPairResult result = keyGenerationService.generateRsa3072KeyPair();

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getAlgorithm()).isEqualTo("RSA_3072");
        assertThat(result.getKeySizeBits()).isEqualTo(3072);
        assertThat(result.getPublicKeyBase64()).isNotEmpty();
        assertThat(result.getPrivateKeyBase64()).isNotEmpty();
        
        // Verify Base64 encoding is valid
        assertThatCode(() -> Base64.getDecoder().decode(result.getPublicKeyBase64()))
            .doesNotThrowAnyException();
        assertThatCode(() -> Base64.getDecoder().decode(result.getPrivateKeyBase64()))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Should generate key pair by algorithm name - Ed25519")
    void testGenerateKeyPairByAlgorithmEd25519() throws Exception {
        // When
        KeyGenerationService.KeyPairResult result = keyGenerationService.generateKeyPair("Ed25519");

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getAlgorithm()).isEqualTo("Ed25519");
        assertThat(result.getKeySizeBits()).isEqualTo(255);
    }

    @Test
    @DisplayName("Should generate key pair by algorithm name - ECDSA variants")
    void testGenerateKeyPairByAlgorithmECDSA() throws Exception {
        // Test different ECDSA algorithm name variants
        String[] ecdsaVariants = {"ECDSA_P256", "ECDSA", "P256"};
        
        for (String algorithm : ecdsaVariants) {
            // When
            KeyGenerationService.KeyPairResult result = keyGenerationService.generateKeyPair(algorithm);

            // Then
            assertThat(result).isNotNull();
            assertThat(result.getAlgorithm()).isEqualTo("ECDSA_P256");
            assertThat(result.getKeySizeBits()).isEqualTo(256);
        }
    }

    @Test
    @DisplayName("Should generate key pair by algorithm name - RSA variants")
    void testGenerateKeyPairByAlgorithmRSA() throws Exception {
        // Test different RSA algorithm name variants
        String[] rsaVariants = {"RSA_3072", "RSA"};
        
        for (String algorithm : rsaVariants) {
            // When
            KeyGenerationService.KeyPairResult result = keyGenerationService.generateKeyPair(algorithm);

            // Then
            assertThat(result).isNotNull();
            assertThat(result.getAlgorithm()).isEqualTo("RSA_3072");
            assertThat(result.getKeySizeBits()).isEqualTo(3072);
        }
    }

    @Test
    @DisplayName("Should throw exception for unsupported algorithm")
    void testGenerateKeyPairUnsupportedAlgorithm() {
        // When & Then
        assertThatThrownBy(() -> keyGenerationService.generateKeyPair("UNSUPPORTED_ALGO"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Unsupported algorithm: UNSUPPORTED_ALGO")
            .hasMessageContaining("Supported algorithms: Ed25519, ECDSA_P256, RSA_3072");
    }

    @Test
    @DisplayName("Should handle case insensitive algorithm names")
    void testGenerateKeyPairCaseInsensitive() throws Exception {
        // When
        KeyGenerationService.KeyPairResult result1 = keyGenerationService.generateKeyPair("ed25519");
        KeyGenerationService.KeyPairResult result2 = keyGenerationService.generateKeyPair("ED25519");
        KeyGenerationService.KeyPairResult result3 = keyGenerationService.generateKeyPair("Ed25519");

        // Then
        assertThat(result1.getAlgorithm()).isEqualTo("Ed25519");
        assertThat(result2.getAlgorithm()).isEqualTo("Ed25519");
        assertThat(result3.getAlgorithm()).isEqualTo("Ed25519");
    }

    @Test
    @DisplayName("Should validate supported algorithms correctly")
    void testIsAlgorithmSupported() {
        // Supported algorithms
        assertThat(keyGenerationService.isAlgorithmSupported("Ed25519")).isTrue();
        assertThat(keyGenerationService.isAlgorithmSupported("ECDSA_P256")).isTrue();
        assertThat(keyGenerationService.isAlgorithmSupported("ECDSA")).isTrue();
        assertThat(keyGenerationService.isAlgorithmSupported("P256")).isTrue();
        assertThat(keyGenerationService.isAlgorithmSupported("RSA_3072")).isTrue();
        assertThat(keyGenerationService.isAlgorithmSupported("RSA")).isTrue();
        
        // Case insensitive
        assertThat(keyGenerationService.isAlgorithmSupported("ed25519")).isTrue();
        assertThat(keyGenerationService.isAlgorithmSupported("rsa")).isTrue();
        
        // Unsupported algorithms
        assertThat(keyGenerationService.isAlgorithmSupported("AES")).isFalse();
        assertThat(keyGenerationService.isAlgorithmSupported("DSA")).isFalse();
        assertThat(keyGenerationService.isAlgorithmSupported("INVALID")).isFalse();
        assertThat(keyGenerationService.isAlgorithmSupported("")).isFalse();
        assertThat(keyGenerationService.isAlgorithmSupported(null)).isFalse();
    }

    @Test
    @DisplayName("Should return correct recommended key sizes")
    void testGetRecommendedKeySize() {
        assertThat(keyGenerationService.getRecommendedKeySize("Ed25519")).isEqualTo(255);
        assertThat(keyGenerationService.getRecommendedKeySize("ECDSA_P256")).isEqualTo(256);
        assertThat(keyGenerationService.getRecommendedKeySize("ECDSA")).isEqualTo(256);
        assertThat(keyGenerationService.getRecommendedKeySize("P256")).isEqualTo(256);
        assertThat(keyGenerationService.getRecommendedKeySize("RSA_3072")).isEqualTo(3072);
        assertThat(keyGenerationService.getRecommendedKeySize("RSA")).isEqualTo(3072);
        
        // Case insensitive
        assertThat(keyGenerationService.getRecommendedKeySize("ed25519")).isEqualTo(255);
        assertThat(keyGenerationService.getRecommendedKeySize("rsa")).isEqualTo(3072);
    }

    @Test
    @DisplayName("Should throw exception for unsupported algorithm in getRecommendedKeySize")
    void testGetRecommendedKeySizeUnsupportedAlgorithm() {
        assertThatThrownBy(() -> keyGenerationService.getRecommendedKeySize("UNSUPPORTED"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Unsupported algorithm: UNSUPPORTED");
    }

    @Test
    @DisplayName("Should generate different key pairs on each call")
    void testKeyPairUniqueness() throws Exception {
        // Generate multiple Ed25519 key pairs
        KeyGenerationService.KeyPairResult result1 = keyGenerationService.generateEd25519KeyPair();
        KeyGenerationService.KeyPairResult result2 = keyGenerationService.generateEd25519KeyPair();
        KeyGenerationService.KeyPairResult result3 = keyGenerationService.generateEd25519KeyPair();

        // Verify all keys are different
        assertThat(result1.getPublicKeyBase64()).isNotEqualTo(result2.getPublicKeyBase64());
        assertThat(result1.getPublicKeyBase64()).isNotEqualTo(result3.getPublicKeyBase64());
        assertThat(result2.getPublicKeyBase64()).isNotEqualTo(result3.getPublicKeyBase64());
        
        assertThat(result1.getPrivateKeyBase64()).isNotEqualTo(result2.getPrivateKeyBase64());
        assertThat(result1.getPrivateKeyBase64()).isNotEqualTo(result3.getPrivateKeyBase64());
        assertThat(result2.getPrivateKeyBase64()).isNotEqualTo(result3.getPrivateKeyBase64());
    }

    @Test
    @DisplayName("Should validate KeyPairResult toString method")
    void testKeyPairResultToString() throws Exception {
        // When
        KeyGenerationService.KeyPairResult result = keyGenerationService.generateEd25519KeyPair();

        // Then
        String toString = result.toString();
        assertThat(toString).contains("KeyPairResult{");
        assertThat(toString).contains("algorithm='Ed25519'");
        assertThat(toString).contains("keySizeBits=255");
        assertThat(toString).contains("publicKeyLength=");
        assertThat(toString).contains("privateKeyLength=");
    }

    @Test
    @DisplayName("Should handle multiple concurrent key generations")
    void testConcurrentKeyGeneration() throws Exception {
        // This test verifies that the SecureRandom is thread-safe
        int numberOfThreads = 10;
        KeyGenerationService.KeyPairResult[] results = new KeyGenerationService.KeyPairResult[numberOfThreads];
        Thread[] threads = new Thread[numberOfThreads];

        // Create threads that generate keys concurrently
        for (int i = 0; i < numberOfThreads; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try {
                    results[index] = keyGenerationService.generateEd25519KeyPair();
                } catch (Exception e) {
                    fail("Key generation failed in thread " + index + ": " + e.getMessage());
                }
            });
        }

        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // Verify all key generations succeeded and produced unique keys
        for (int i = 0; i < numberOfThreads; i++) {
            assertThat(results[i]).isNotNull();
            assertThat(results[i].getPublicKeyBase64()).isNotEmpty();
            assertThat(results[i].getPrivateKeyBase64()).isNotEmpty();
            
            // Verify uniqueness against all other keys
            for (int j = i + 1; j < numberOfThreads; j++) {
                assertThat(results[i].getPublicKeyBase64())
                    .isNotEqualTo(results[j].getPublicKeyBase64());
                assertThat(results[i].getPrivateKeyBase64())
                    .isNotEqualTo(results[j].getPrivateKeyBase64());
            }
        }
    }

    @Test
    @DisplayName("Should validate key data integrity")
    void testKeyDataIntegrity() throws Exception {
        // Generate keys for all algorithms
        KeyGenerationService.KeyPairResult ed25519 = keyGenerationService.generateKeyPair("Ed25519");
        KeyGenerationService.KeyPairResult ecdsa = keyGenerationService.generateKeyPair("ECDSA_P256");
        KeyGenerationService.KeyPairResult rsa = keyGenerationService.generateKeyPair("RSA_3072");

        // Verify Base64 decoding produces reasonable key lengths
        byte[] ed25519PubKey = Base64.getDecoder().decode(ed25519.getPublicKeyBase64());
        byte[] ed25519PrivKey = Base64.getDecoder().decode(ed25519.getPrivateKeyBase64());
        
        byte[] ecdsaPubKey = Base64.getDecoder().decode(ecdsa.getPublicKeyBase64());
        byte[] ecdsaPrivKey = Base64.getDecoder().decode(ecdsa.getPrivateKeyBase64());
        
        byte[] rsaPubKey = Base64.getDecoder().decode(rsa.getPublicKeyBase64());
        byte[] rsaPrivKey = Base64.getDecoder().decode(rsa.getPrivateKeyBase64());

        // Ed25519 keys should be around 32 bytes for private, 44 for public (DER encoded)
        assertThat(ed25519PubKey.length).isGreaterThan(30);
        assertThat(ed25519PrivKey.length).isGreaterThan(30);
        
        // ECDSA P-256 should be similar sizes
        assertThat(ecdsaPubKey.length).isGreaterThan(40);
        assertThat(ecdsaPrivKey.length).isGreaterThan(30);
        
        // RSA-3072 should be much larger
        assertThat(rsaPubKey.length).isGreaterThan(300);
        assertThat(rsaPrivKey.length).isGreaterThan(1000);
    }
}
