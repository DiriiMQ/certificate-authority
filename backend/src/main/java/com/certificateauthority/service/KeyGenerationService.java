package com.certificateauthority.service;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service for generating cryptographic key pairs using industry-standard algorithms.
 * 
 * Supports:
 * - Ed25519 (EdDSA) - Modern elliptic curve signature algorithm (default)
 * - ECDSA P-256 (secp256r1) - NIST-approved elliptic curve
 * - RSA-3072 - RSA with 3072-bit key size for enhanced security
 * 
 * All key generation uses NIST-certified secure random number generators
 * and follows current cryptographic best practices (2024).
 */
@Service
public class KeyGenerationService {

    private static final int RSA_KEY_SIZE = 3072;
    private static final BigInteger RSA_PUBLIC_EXPONENT = BigInteger.valueOf(65537); // F4
    private static final String EC_CURVE_NAME = "secp256r1"; // P-256
    
    private final SecureRandom secureRandom;

    public KeyGenerationService() throws NoSuchAlgorithmException {
        // Use NIST-certified strong random number generator
        this.secureRandom = SecureRandom.getInstanceStrong();
        
        // Register Bouncy Castle as security provider
        if (java.security.Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generate Ed25519 key pair (EdDSA algorithm).
     * Ed25519 is the recommended default algorithm due to its security,
     * performance, and small signature size.
     * 
     * @return KeyPairResult containing Base64-encoded public and private keys
     * @throws Exception if key generation fails
     */
    public KeyPairResult generateEd25519KeyPair() throws Exception {
        Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
        generator.init(new Ed25519KeyGenerationParameters(secureRandom));
        
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        
        Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
        Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();
        
        // Encode keys to Base64 for database storage
        String publicKeyBase64 = Base64.getEncoder().encodeToString(
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey).getEncoded()
        );
        String privateKeyBase64 = Base64.getEncoder().encodeToString(
            PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey).getEncoded()
        );
        
        return new KeyPairResult(
            "Ed25519", 
            255, // Ed25519 uses 255-bit keys (effectively 256-bit security)
            publicKeyBase64, 
            privateKeyBase64
        );
    }

    /**
     * Generate ECDSA P-256 key pair (secp256r1 curve).
     * NIST-approved elliptic curve providing 128-bit security level.
     * 
     * @return KeyPairResult containing Base64-encoded public and private keys
     * @throws Exception if key generation fails
     */
    public KeyPairResult generateEcdsaP256KeyPair() throws Exception {
        ECNamedCurveParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec(EC_CURVE_NAME);
        ECDomainParameters domainParams = new ECDomainParameters(
            curveSpec.getCurve(), 
            curveSpec.getG(), 
            curveSpec.getN(), 
            curveSpec.getH()
        );
        
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(domainParams, secureRandom));
        
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        
        // Encode keys to Base64 for database storage
        String publicKeyBase64 = Base64.getEncoder().encodeToString(
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey).getEncoded()
        );
        String privateKeyBase64 = Base64.getEncoder().encodeToString(
            PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey).getEncoded()
        );
        
        return new KeyPairResult(
            "ECDSA_P256", 
            256, 
            publicKeyBase64, 
            privateKeyBase64
        );
    }

    /**
     * Generate RSA-3072 key pair.
     * RSA with 3072-bit key size provides 128-bit security level
     * and is suitable for long-term use cases.
     * 
     * @return KeyPairResult containing Base64-encoded public and private keys
     * @throws Exception if key generation fails
     */
    public KeyPairResult generateRsa3072KeyPair() throws Exception {
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(
            RSA_PUBLIC_EXPONENT, 
            secureRandom, 
            RSA_KEY_SIZE, 
            100 // certainty parameter for prime generation
        ));
        
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        
        RSAPrivateCrtKeyParameters privateKey = (RSAPrivateCrtKeyParameters) keyPair.getPrivate();
        RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
        
        // Encode keys to Base64 for database storage
        String publicKeyBase64 = Base64.getEncoder().encodeToString(
            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey).getEncoded()
        );
        String privateKeyBase64 = Base64.getEncoder().encodeToString(
            PrivateKeyInfoFactory.createPrivateKeyInfo(privateKey).getEncoded()
        );
        
        return new KeyPairResult(
            "RSA_3072", 
            RSA_KEY_SIZE, 
            publicKeyBase64, 
            privateKeyBase64
        );
    }

    /**
     * Generate key pair based on algorithm name.
     * Convenience method for dynamic algorithm selection.
     * 
     * @param algorithm The algorithm name: "Ed25519", "ECDSA_P256", or "RSA_3072"
     * @return KeyPairResult containing the generated key pair
     * @throws Exception if algorithm is unsupported or key generation fails
     */
    public KeyPairResult generateKeyPair(String algorithm) throws Exception {
        return switch (algorithm.toUpperCase()) {
            case "ED25519" -> generateEd25519KeyPair();
            case "ECDSA_P256", "ECDSA", "P256" -> generateEcdsaP256KeyPair();
            case "RSA_3072", "RSA" -> generateRsa3072KeyPair();
            default -> throw new IllegalArgumentException(
                "Unsupported algorithm: " + algorithm + 
                ". Supported algorithms: Ed25519, ECDSA_P256, RSA_3072"
            );
        };
    }

    /**
     * Validate that an algorithm is supported by this service.
     * 
     * @param algorithm The algorithm name to validate
     * @return true if algorithm is supported, false otherwise
     */
    public boolean isAlgorithmSupported(String algorithm) {
        try {
            return switch (algorithm.toUpperCase()) {
                case "ED25519", "ECDSA_P256", "ECDSA", "P256", "RSA_3072", "RSA" -> true;
                default -> false;
            };
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get the recommended key size for a given algorithm.
     * 
     * @param algorithm The algorithm name
     * @return The recommended key size in bits
     */
    public int getRecommendedKeySize(String algorithm) {
        return switch (algorithm.toUpperCase()) {
            case "ED25519" -> 255;
            case "ECDSA_P256", "ECDSA", "P256" -> 256;
            case "RSA_3072", "RSA" -> RSA_KEY_SIZE;
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        };
    }

    /**
     * Result class for generated key pairs.
     * Contains algorithm information and Base64-encoded key data.
     */
    public static class KeyPairResult {
        private final String algorithm;
        private final int keySizeBits;
        private final String publicKeyBase64;
        private final String privateKeyBase64;

        public KeyPairResult(String algorithm, int keySizeBits, String publicKeyBase64, String privateKeyBase64) {
            this.algorithm = algorithm;
            this.keySizeBits = keySizeBits;
            this.publicKeyBase64 = publicKeyBase64;
            this.privateKeyBase64 = privateKeyBase64;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public int getKeySizeBits() {
            return keySizeBits;
        }

        public String getPublicKeyBase64() {
            return publicKeyBase64;
        }

        public String getPrivateKeyBase64() {
            return privateKeyBase64;
        }

        @Override
        public String toString() {
            return "KeyPairResult{" +
                    "algorithm='" + algorithm + '\'' +
                    ", keySizeBits=" + keySizeBits +
                    ", publicKeyLength=" + (publicKeyBase64 != null ? publicKeyBase64.length() : 0) +
                    ", privateKeyLength=" + (privateKeyBase64 != null ? privateKeyBase64.length() : 0) +
                    '}';
        }
    }
}
