package com.certificateauthority.service;

import com.certificateauthority.entity.SigningKey;
import com.certificateauthority.repository.SigningKeyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Service for secure storage and retrieval of cryptographic signing keys.
 * 
 * Features:
 * - AES-256-GCM encryption for private key data at rest
 * - Key lifecycle management and validation
 * - Integration with SigningKey JPA entity
 * - Comprehensive key integrity checks
 * - Performance-optimized key retrieval
 * 
 * Security measures:
 * - Private keys are encrypted before database storage
 * - Separate encryption key derived from master password
 * - Authenticated encryption with GCM mode
 * - Secure key derivation using SHA-256
 */
@Service
@Transactional
public class KeyStorageService {

    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 16; // 128 bits
    private static final int AES_KEY_LENGTH = 256; // bits

    private final SigningKeyRepository signingKeyRepository;
    private final SecretKey encryptionKey;
    private final SecureRandom secureRandom;

    @Autowired
    public KeyStorageService(
            SigningKeyRepository signingKeyRepository,
            @Value("${app.key-storage.master-password:default-change-in-production}") String masterPassword) 
            throws Exception {
        this.signingKeyRepository = signingKeyRepository;
        this.secureRandom = SecureRandom.getInstanceStrong();
        this.encryptionKey = deriveEncryptionKey(masterPassword);
    }

    /**
     * Store a newly generated key pair securely in the database.
     * Private key data is encrypted before storage.
     * 
     * @param keyIdentifier Unique identifier for the key
     * @param algorithm Algorithm used for key generation
     * @param publicKeyData Base64-encoded public key
     * @param privateKeyData Base64-encoded private key (will be encrypted)
     * @param keySizeBits Key size in bits
     * @param createdBy Username of the key creator
     * @param expirationHours Hours until key expiration (null for no expiration)
     * @return Stored SigningKey entity
     * @throws Exception if encryption or storage fails
     */
    public SigningKey storeKey(String keyIdentifier, String algorithm, String publicKeyData, 
                              String privateKeyData, Integer keySizeBits, String createdBy, 
                              Integer expirationHours) throws Exception {
        
        // Validate inputs
        validateKeyData(keyIdentifier, algorithm, publicKeyData, privateKeyData, keySizeBits);
        
        // Check for existing key with same identifier
        if (signingKeyRepository.findByKeyIdentifier(keyIdentifier).isPresent()) {
            throw new IllegalArgumentException("Key with identifier '" + keyIdentifier + "' already exists");
        }
        
        // Encrypt private key data
        String encryptedPrivateKey = encryptPrivateKey(privateKeyData);
        
        // Calculate expiration date
        LocalDateTime expiresAt = expirationHours != null ? 
            LocalDateTime.now().plusHours(expirationHours) : null;
        
        // Create and save entity
        SigningKey signingKey = new SigningKey(
            keyIdentifier, 
            algorithm, 
            publicKeyData, 
            encryptedPrivateKey, 
            keySizeBits, 
            createdBy
        );
        signingKey.setExpiresAt(expiresAt);
        
        return signingKeyRepository.save(signingKey);
    }

    /**
     * Retrieve an active key by its unique identifier.
     * Decrypts private key data before returning.
     * 
     * @param keyIdentifier The unique key identifier
     * @return Optional SigningKey with decrypted private key
     * @throws Exception if decryption fails
     */
    public Optional<SigningKeyWithDecryptedData> retrieveKeyByIdentifier(String keyIdentifier) throws Exception {
        Optional<SigningKey> keyOpt = signingKeyRepository.findByKeyIdentifier(keyIdentifier);
        
        if (keyOpt.isEmpty()) {
            return Optional.empty();
        }
        
        SigningKey key = keyOpt.get();
        
        // Check if key is usable
        if (!key.isUsable()) {
            return Optional.empty();
        }
        
        // Decrypt private key and update usage
        String decryptedPrivateKey = decryptPrivateKey(key.getPrivateKeyData());
        updateKeyUsage(key);
        
        return Optional.of(new SigningKeyWithDecryptedData(key, decryptedPrivateKey));
    }

    /**
     * Retrieve a key by its UUID.
     * 
     * @param keyId The key UUID
     * @return Optional SigningKey with decrypted private key
     * @throws Exception if decryption fails
     */
    public Optional<SigningKeyWithDecryptedData> retrieveKeyById(UUID keyId) throws Exception {
        Optional<SigningKey> keyOpt = signingKeyRepository.findById(keyId);
        
        if (keyOpt.isEmpty()) {
            return Optional.empty();
        }
        
        SigningKey key = keyOpt.get();
        String decryptedPrivateKey = decryptPrivateKey(key.getPrivateKeyData());
        
        return Optional.of(new SigningKeyWithDecryptedData(key, decryptedPrivateKey));
    }

    /**
     * Retrieve the most recent active key for a specific algorithm.
     * 
     * @param algorithm The cryptographic algorithm
     * @return Optional SigningKey with decrypted private key
     * @throws Exception if decryption fails
     */
    public Optional<SigningKeyWithDecryptedData> retrieveActiveKeyByAlgorithm(String algorithm) throws Exception {
        Optional<SigningKey> keyOpt = signingKeyRepository.findMostRecentActiveKeyByAlgorithm(algorithm);
        
        if (keyOpt.isEmpty()) {
            return Optional.empty();
        }
        
        SigningKey key = keyOpt.get();
        
        // Double-check key is still usable
        if (!key.isUsable()) {
            return Optional.empty();
        }
        
        String decryptedPrivateKey = decryptPrivateKey(key.getPrivateKeyData());
        updateKeyUsage(key);
        
        return Optional.of(new SigningKeyWithDecryptedData(key, decryptedPrivateKey));
    }

    /**
     * List all active keys with pagination.
     * Note: Private keys are NOT decrypted in list operations for security.
     * 
     * @param page Page number (0-based)
     * @param size Page size
     * @return Page of active SigningKey entities (with encrypted private keys)
     */
    public Page<SigningKey> listActiveKeys(int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        return signingKeyRepository.findByIsActiveTrue(pageable);
    }

    /**
     * List all usable (active and not expired) keys for a specific algorithm.
     * 
     * @param algorithm The cryptographic algorithm
     * @return List of usable SigningKey entities (with encrypted private keys)
     */
    public List<SigningKey> listUsableKeysByAlgorithm(String algorithm) {
        return signingKeyRepository.findUsableKeysByAlgorithm(algorithm, LocalDateTime.now());
    }

    /**
     * Deactivate a key with reason.
     * 
     * @param keyId Key UUID to deactivate
     * @param deactivatedBy Username performing deactivation
     * @param reason Reason for deactivation
     * @return Updated SigningKey entity
     * @throws Exception if key not found
     */
    public SigningKey deactivateKey(UUID keyId, String deactivatedBy, String reason) throws Exception {
        SigningKey key = signingKeyRepository.findById(keyId)
            .orElseThrow(() -> new IllegalArgumentException("Key not found with ID: " + keyId));
        
        key.deactivate(deactivatedBy, reason);
        return signingKeyRepository.save(key);
    }

    /**
     * Validate key integrity by checking if it can be decrypted successfully.
     * 
     * @param keyId Key UUID to validate
     * @return true if key is valid and can be decrypted
     */
    public boolean validateKeyIntegrity(UUID keyId) {
        try {
            Optional<SigningKey> keyOpt = signingKeyRepository.findById(keyId);
            if (keyOpt.isEmpty()) {
                return false;
            }
            
            // Try to decrypt the private key
            decryptPrivateKey(keyOpt.get().getPrivateKeyData());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get key statistics by algorithm.
     * 
     * @return List of algorithm statistics
     */
    public List<Object[]> getKeyStatistics() {
        return signingKeyRepository.getAlgorithmStatistics();
    }

    // ==================== Private Helper Methods ====================

    /**
     * Derive AES encryption key from master password using SHA-256.
     */
    private SecretKey deriveEncryptionKey(String masterPassword) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(masterPassword.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
    }

    /**
     * Encrypt private key data using AES-256-GCM.
     */
    private String encryptPrivateKey(String privateKeyData) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, parameterSpec);
        
        byte[] encryptedData = cipher.doFinal(privateKeyData.getBytes(StandardCharsets.UTF_8));
        
        // Combine IV and encrypted data
        byte[] encryptedWithIv = new byte[iv.length + encryptedData.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encryptedData, 0, encryptedWithIv, iv.length, encryptedData.length);
        
        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }

    /**
     * Decrypt private key data using AES-256-GCM.
     */
    private String decryptPrivateKey(String encryptedPrivateKeyData) throws Exception {
        byte[] encryptedWithIv = Base64.getDecoder().decode(encryptedPrivateKeyData);
        
        // Extract IV and encrypted data
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encryptedData = new byte[encryptedWithIv.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedWithIv, 0, iv, 0, iv.length);
        System.arraycopy(encryptedWithIv, iv.length, encryptedData, 0, encryptedData.length);
        
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, parameterSpec);
        
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    /**
     * Update key usage statistics.
     */
    private void updateKeyUsage(SigningKey key) {
        key.incrementUsage();
        signingKeyRepository.save(key);
    }

    /**
     * Validate key data before storage.
     */
    private void validateKeyData(String keyIdentifier, String algorithm, String publicKeyData, 
                                String privateKeyData, Integer keySizeBits) {
        if (keyIdentifier == null || keyIdentifier.trim().isEmpty()) {
            throw new IllegalArgumentException("Key identifier cannot be null or empty");
        }
        if (algorithm == null || algorithm.trim().isEmpty()) {
            throw new IllegalArgumentException("Algorithm cannot be null or empty");
        }
        if (publicKeyData == null || publicKeyData.trim().isEmpty()) {
            throw new IllegalArgumentException("Public key data cannot be null or empty");
        }
        if (privateKeyData == null || privateKeyData.trim().isEmpty()) {
            throw new IllegalArgumentException("Private key data cannot be null or empty");
        }
        if (keySizeBits == null || keySizeBits <= 0) {
            throw new IllegalArgumentException("Key size must be positive");
        }
        
        // Validate Base64 encoding
        try {
            Base64.getDecoder().decode(publicKeyData);
            Base64.getDecoder().decode(privateKeyData);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Key data must be valid Base64 encoded", e);
        }
    }

    /**
     * Wrapper class for SigningKey with decrypted private key data.
     * Used to safely return decrypted keys without modifying the entity.
     */
    public static class SigningKeyWithDecryptedData {
        private final SigningKey signingKey;
        private final String decryptedPrivateKey;

        public SigningKeyWithDecryptedData(SigningKey signingKey, String decryptedPrivateKey) {
            this.signingKey = signingKey;
            this.decryptedPrivateKey = decryptedPrivateKey;
        }

        public SigningKey getSigningKey() {
            return signingKey;
        }

        public String getDecryptedPrivateKey() {
            return decryptedPrivateKey;
        }

        // Delegate common methods to the underlying entity
        public UUID getId() { return signingKey.getId(); }
        public String getKeyIdentifier() { return signingKey.getKeyIdentifier(); }
        public String getAlgorithm() { return signingKey.getAlgorithm(); }
        public String getPublicKeyData() { return signingKey.getPublicKeyData(); }
        public Integer getKeySizeBits() { return signingKey.getKeySizeBits(); }
        public Boolean getIsActive() { return signingKey.getIsActive(); }
        public LocalDateTime getCreatedAt() { return signingKey.getCreatedAt(); }
        public LocalDateTime getExpiresAt() { return signingKey.getExpiresAt(); }
        public Long getUsageCount() { return signingKey.getUsageCount(); }
        public boolean isUsable() { return signingKey.isUsable(); }
    }
}
