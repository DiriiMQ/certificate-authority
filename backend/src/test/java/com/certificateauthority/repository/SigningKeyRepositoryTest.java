package com.certificateauthority.repository;

import com.certificateauthority.entity.SigningKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for SigningKeyRepository
 * Tests JPA entity mapping, repository methods, and custom queries
 */
@DataJpaTest
@ActiveProfiles("test")
class SigningKeyRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private SigningKeyRepository signingKeyRepository;

    @Test
    void testSaveAndFindSigningKey() {
        // Given
        SigningKey signingKey = new SigningKey(
                "test-key-001",
                "Ed25519",
                "publicKeyData123",
                "privateKeyData456",
                256,
                "test_user"
        );
        signingKey.setExpiresAt(LocalDateTime.now().plusDays(90));

        // When
        SigningKey saved = signingKeyRepository.save(signingKey);
        entityManager.flush();
        Optional<SigningKey> found = signingKeyRepository.findById(saved.getId());

        // Then
        assertThat(found).isPresent();
        assertThat(found.get().getKeyIdentifier()).isEqualTo("test-key-001");
        assertThat(found.get().getAlgorithm()).isEqualTo("Ed25519");
        assertThat(found.get().getPublicKeyData()).isEqualTo("publicKeyData123");
        assertThat(found.get().getPrivateKeyData()).isEqualTo("privateKeyData456");
        assertThat(found.get().getKeySizeBits()).isEqualTo(256);
        assertThat(found.get().getCreatedBy()).isEqualTo("test_user");
        assertThat(found.get().getIsActive()).isTrue();
        assertThat(found.get().getUsageCount()).isEqualTo(0);
        
        // Verify auditing fields are populated
        assertThat(found.get().getCreatedAt()).isNotNull();
        assertThat(found.get().getUpdatedAt()).isNotNull();
    }

    @Test
    void testFindByKeyIdentifier() {
        // Given
        SigningKey signingKey = new SigningKey("unique-key-001", "Ed25519", "pub", "priv", 256, "user1");
        signingKeyRepository.save(signingKey);
        entityManager.flush();

        // When
        Optional<SigningKey> found = signingKeyRepository.findByKeyIdentifier("unique-key-001");

        // Then
        assertThat(found).isPresent();
        assertThat(found.get().getKeyIdentifier()).isEqualTo("unique-key-001");
    }

    @Test
    void testFindByIsActiveTrue() {
        // Given
        SigningKey activeKey = new SigningKey("active-key", "Ed25519", "pub1", "priv1", 256, "user1");
        SigningKey inactiveKey = new SigningKey("inactive-key", "Ed25519", "pub2", "priv2", 256, "user1");
        inactiveKey.deactivate("user1", "Test deactivation");
        
        signingKeyRepository.save(activeKey);
        signingKeyRepository.save(inactiveKey);
        entityManager.flush();

        // When
        Page<SigningKey> activeKeys = signingKeyRepository.findByIsActiveTrue(PageRequest.of(0, 10));

        // Then
        assertThat(activeKeys.getTotalElements()).isEqualTo(1);
        assertThat(activeKeys.getContent().get(0).getKeyIdentifier()).isEqualTo("active-key");
        assertThat(activeKeys.getContent().get(0).getIsActive()).isTrue();
    }

    @Test
    void testFindByAlgorithm() {
        // Given
        SigningKey ed25519Key = new SigningKey("ed25519-key", "Ed25519", "pub1", "priv1", 256, "user1");
        SigningKey rsaKey = new SigningKey("rsa-key", "RSA-3072", "pub2", "priv2", 3072, "user1");
        
        signingKeyRepository.save(ed25519Key);
        signingKeyRepository.save(rsaKey);
        entityManager.flush();

        // When
        Page<SigningKey> ed25519Keys = signingKeyRepository.findByAlgorithm("Ed25519", PageRequest.of(0, 10));
        Page<SigningKey> rsaKeys = signingKeyRepository.findByAlgorithm("RSA-3072", PageRequest.of(0, 10));

        // Then
        assertThat(ed25519Keys.getTotalElements()).isEqualTo(1);
        assertThat(ed25519Keys.getContent().get(0).getAlgorithm()).isEqualTo("Ed25519");
        
        assertThat(rsaKeys.getTotalElements()).isEqualTo(1);
        assertThat(rsaKeys.getContent().get(0).getAlgorithm()).isEqualTo("RSA-3072");
    }

    @Test
    void testFindMostRecentActiveKeyByAlgorithm() {
        // Given
        SigningKey oldKey = new SigningKey("old-key", "Ed25519", "pub1", "priv1", 256, "user1");
        oldKey.setCreatedAt(LocalDateTime.now().minusDays(10));
        
        SigningKey newKey = new SigningKey("new-key", "Ed25519", "pub2", "priv2", 256, "user1");
        newKey.setCreatedAt(LocalDateTime.now().minusDays(1));
        
        SigningKey inactiveKey = new SigningKey("inactive-key", "Ed25519", "pub3", "priv3", 256, "user1");
        inactiveKey.deactivate("user1", "Test");
        
        signingKeyRepository.save(oldKey);
        signingKeyRepository.save(newKey);
        signingKeyRepository.save(inactiveKey);
        entityManager.flush();

        // When
        Optional<SigningKey> mostRecent = signingKeyRepository.findMostRecentActiveKeyByAlgorithm("Ed25519");

        // Then
        assertThat(mostRecent).isPresent();
        assertThat(mostRecent.get().getKeyIdentifier()).isEqualTo("new-key");
        assertThat(mostRecent.get().getIsActive()).isTrue();
    }

    @Test
    void testFindUsableKeysByAlgorithm() {
        // Given
        LocalDateTime now = LocalDateTime.now();
        
        SigningKey activeKey = new SigningKey("active-key", "Ed25519", "pub1", "priv1", 256, "user1");
        
        SigningKey expiredKey = new SigningKey("expired-key", "Ed25519", "pub2", "priv2", 256, "user1");
        expiredKey.setExpiresAt(now.minusDays(1));
        
        SigningKey futureExpiredKey = new SigningKey("future-expired-key", "Ed25519", "pub3", "priv3", 256, "user1");
        futureExpiredKey.setExpiresAt(now.plusDays(30));
        
        SigningKey inactiveKey = new SigningKey("inactive-key", "Ed25519", "pub4", "priv4", 256, "user1");
        inactiveKey.deactivate("user1", "Test");
        
        signingKeyRepository.save(activeKey);
        signingKeyRepository.save(expiredKey);
        signingKeyRepository.save(futureExpiredKey);
        signingKeyRepository.save(inactiveKey);
        entityManager.flush();

        // When
        List<SigningKey> usableKeys = signingKeyRepository.findUsableKeysByAlgorithm("Ed25519", now);

        // Then
        assertThat(usableKeys).hasSize(2);
        assertThat(usableKeys.stream().map(SigningKey::getKeyIdentifier))
                .containsExactlyInAnyOrder("active-key", "future-expired-key");
    }

    @Test
    void testCountByAlgorithmAndIsActiveTrue() {
        // Given
        signingKeyRepository.save(new SigningKey("key1", "Ed25519", "pub1", "priv1", 256, "user1"));
        signingKeyRepository.save(new SigningKey("key2", "Ed25519", "pub2", "priv2", 256, "user1"));
        
        SigningKey inactiveKey = new SigningKey("key3", "Ed25519", "pub3", "priv3", 256, "user1");
        inactiveKey.deactivate("user1", "Test");
        signingKeyRepository.save(inactiveKey);
        
        signingKeyRepository.save(new SigningKey("key4", "RSA-3072", "pub4", "priv4", 3072, "user1"));
        entityManager.flush();

        // When
        long ed25519ActiveCount = signingKeyRepository.countByAlgorithmAndIsActiveTrue("Ed25519");
        long rsaActiveCount = signingKeyRepository.countByAlgorithmAndIsActiveTrue("RSA-3072");

        // Then
        assertThat(ed25519ActiveCount).isEqualTo(2);
        assertThat(rsaActiveCount).isEqualTo(1);
    }

    @Test
    void testKeyLifecycleMethods() {
        // Given
        SigningKey signingKey = new SigningKey("lifecycle-key", "Ed25519", "pub", "priv", 256, "user1");
        signingKey = signingKeyRepository.save(signingKey);
        entityManager.flush();

        // Test key usage increment
        signingKey.incrementUsage();
        signingKey = signingKeyRepository.save(signingKey);
        entityManager.flush();

        // Then
        assertThat(signingKey.getUsageCount()).isEqualTo(1);
        assertThat(signingKey.getLastUsedAt()).isNotNull();
        assertThat(signingKey.isUsable()).isTrue();

        // Test key deactivation
        signingKey.deactivate("admin", "Testing deactivation");
        signingKey = signingKeyRepository.save(signingKey);
        entityManager.flush();

        // Then
        assertThat(signingKey.getIsActive()).isFalse();
        assertThat(signingKey.getDeactivatedBy()).isEqualTo("admin");
        assertThat(signingKey.getDeactivationReason()).isEqualTo("Testing deactivation");
        assertThat(signingKey.getDeactivatedAt()).isNotNull();
        assertThat(signingKey.isUsable()).isFalse();
    }

    @Test
    void testKeyExpirationLogic() {
        // Given
        LocalDateTime now = LocalDateTime.now();
        
        SigningKey expiredKey = new SigningKey("expired-key", "Ed25519", "pub1", "priv1", 256, "user1");
        expiredKey.setExpiresAt(now.minusDays(1));
        
        SigningKey validKey = new SigningKey("valid-key", "Ed25519", "pub2", "priv2", 256, "user1");
        validKey.setExpiresAt(now.plusDays(30));
        
        SigningKey neverExpiresKey = new SigningKey("never-expires-key", "Ed25519", "pub3", "priv3", 256, "user1");
        // expiresAt is null by default
        
        // When/Then
        assertThat(expiredKey.isExpired()).isTrue();
        assertThat(expiredKey.isUsable()).isFalse(); // expired and active = not usable
        
        assertThat(validKey.isExpired()).isFalse();
        assertThat(validKey.isUsable()).isTrue(); // not expired and active = usable
        
        assertThat(neverExpiresKey.isExpired()).isFalse();
        assertThat(neverExpiresKey.isUsable()).isTrue(); // never expires and active = usable
    }

    @Test
    void testFindKeysNeedingRotationByAge() {
        // Given
        LocalDateTime oldThreshold = LocalDateTime.now().minusDays(90);
        
        SigningKey oldKey = new SigningKey("old-key", "Ed25519", "pub1", "priv1", 256, "user1");
        oldKey.setCreatedAt(LocalDateTime.now().minusDays(100));
        
        SigningKey newKey = new SigningKey("new-key", "Ed25519", "pub2", "priv2", 256, "user1");
        newKey.setCreatedAt(LocalDateTime.now().minusDays(30));
        
        signingKeyRepository.save(oldKey);
        signingKeyRepository.save(newKey);
        entityManager.flush();

        // When
        Page<SigningKey> keysNeedingRotation = signingKeyRepository.findKeysNeedingRotationByAge(
                oldThreshold, PageRequest.of(0, 10));

        // Then
        assertThat(keysNeedingRotation.getTotalElements()).isEqualTo(1);
        assertThat(keysNeedingRotation.getContent().get(0).getKeyIdentifier()).isEqualTo("old-key");
    }

    @Test
    void testFindKeysNeedingRotationByUsage() {
        // Given
        SigningKey highUsageKey = new SigningKey("high-usage-key", "Ed25519", "pub1", "priv1", 256, "user1");
        highUsageKey.setUsageCount(15000L);
        
        SigningKey lowUsageKey = new SigningKey("low-usage-key", "Ed25519", "pub2", "priv2", 256, "user1");
        lowUsageKey.setUsageCount(500L);
        
        signingKeyRepository.save(highUsageKey);
        signingKeyRepository.save(lowUsageKey);
        entityManager.flush();

        // When
        Page<SigningKey> keysNeedingRotation = signingKeyRepository.findKeysNeedingRotationByUsage(
                10000L, PageRequest.of(0, 10));

        // Then
        assertThat(keysNeedingRotation.getTotalElements()).isEqualTo(1);
        assertThat(keysNeedingRotation.getContent().get(0).getKeyIdentifier()).isEqualTo("high-usage-key");
        assertThat(keysNeedingRotation.getContent().get(0).getUsageCount()).isEqualTo(15000L);
    }
}