package com.certificateauthority.repository;

import com.certificateauthority.entity.AuditLog;
import com.certificateauthority.entity.OperationType;
import com.certificateauthority.entity.ResultType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.ActiveProfiles;
import com.certificateauthority.config.JpaAuditingConfig;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for AuditLogRepository
 * Tests JPA entity mapping, repository methods, and custom queries
 */
@DataJpaTest
@ActiveProfiles("test")
@Import(JpaAuditingConfig.class)
class AuditLogRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Test
    void testSaveAndFindAuditLog() {
        // Given
        AuditLog auditLog = new AuditLog(
                OperationType.SIGN,
                "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
                "Ed25519",
                "test_user",
                ResultType.SUCCESS
        );
        auditLog.setImageFilename("test_image.png");
        auditLog.setImageSizeBytes(1024L);
        auditLog.setSignatureType("embedded");

        // When
        AuditLog saved = auditLogRepository.save(auditLog);
        entityManager.flush();
        AuditLog found = auditLogRepository.findById(saved.getId()).orElse(null);

        // Then
        assertThat(found).isNotNull();
        assertThat(found.getId()).isEqualTo(saved.getId());
        assertThat(found.getOperation()).isEqualTo(OperationType.SIGN);
        assertThat(found.getImageHash()).isEqualTo("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");
        assertThat(found.getAlgorithm()).isEqualTo("Ed25519");
        assertThat(found.getUserId()).isEqualTo("test_user");
        assertThat(found.getResult()).isEqualTo(ResultType.SUCCESS);
        assertThat(found.getImageFilename()).isEqualTo("test_image.png");
        assertThat(found.getImageSizeBytes()).isEqualTo(1024L);
        assertThat(found.getSignatureType()).isEqualTo("embedded");
        
        // Verify auditing fields are populated
        assertThat(found.getCreatedAt()).isNotNull();
        assertThat(found.getUpdatedAt()).isNotNull();
    }

    @Test
    void testFindByOperation() {
        // Given
        AuditLog signLog = new AuditLog(OperationType.SIGN, "hash1", "Ed25519", "user1", ResultType.SUCCESS);
        AuditLog verifyLog = new AuditLog(OperationType.VERIFY, "hash2", "Ed25519", "user2", ResultType.SUCCESS);
        
        auditLogRepository.save(signLog);
        auditLogRepository.save(verifyLog);
        entityManager.flush();

        // When
        Page<AuditLog> signLogs = auditLogRepository.findByOperation(OperationType.SIGN, PageRequest.of(0, 10));
        Page<AuditLog> verifyLogs = auditLogRepository.findByOperation(OperationType.VERIFY, PageRequest.of(0, 10));

        // Then
        assertThat(signLogs.getTotalElements()).isEqualTo(1);
        assertThat(signLogs.getContent().get(0).getOperation()).isEqualTo(OperationType.SIGN);
        
        assertThat(verifyLogs.getTotalElements()).isEqualTo(1);
        assertThat(verifyLogs.getContent().get(0).getOperation()).isEqualTo(OperationType.VERIFY);
    }

    @Test
    void testFindByResult() {
        // Given
        AuditLog successLog = new AuditLog(OperationType.SIGN, "hash1", "Ed25519", "user1", ResultType.SUCCESS);
        AuditLog failLog = new AuditLog(OperationType.SIGN, "hash2", "Ed25519", "user1", ResultType.FAIL);
        failLog.setErrorMessage("Invalid signature");
        
        auditLogRepository.save(successLog);
        auditLogRepository.save(failLog);
        entityManager.flush();

        // When
        Page<AuditLog> successLogs = auditLogRepository.findByResult(ResultType.SUCCESS, PageRequest.of(0, 10));
        Page<AuditLog> failLogs = auditLogRepository.findByResult(ResultType.FAIL, PageRequest.of(0, 10));

        // Then
        assertThat(successLogs.getTotalElements()).isEqualTo(1);
        assertThat(successLogs.getContent().get(0).getResult()).isEqualTo(ResultType.SUCCESS);
        
        assertThat(failLogs.getTotalElements()).isEqualTo(1);
        assertThat(failLogs.getContent().get(0).getResult()).isEqualTo(ResultType.FAIL);
        assertThat(failLogs.getContent().get(0).getErrorMessage()).isEqualTo("Invalid signature");
    }

    @Test
    void testCountByOperation() {
        // Given
        auditLogRepository.save(new AuditLog(OperationType.SIGN, "hash1", "Ed25519", "user1", ResultType.SUCCESS));
        auditLogRepository.save(new AuditLog(OperationType.SIGN, "hash2", "Ed25519", "user1", ResultType.SUCCESS));
        auditLogRepository.save(new AuditLog(OperationType.VERIFY, "hash3", "Ed25519", "user2", ResultType.SUCCESS));
        entityManager.flush();

        // When
        long signCount = auditLogRepository.countByOperation(OperationType.SIGN);
        long verifyCount = auditLogRepository.countByOperation(OperationType.VERIFY);

        // Then
        assertThat(signCount).isEqualTo(2);
        assertThat(verifyCount).isEqualTo(1);
    }

    @Test
    void testFindRecentLogs() {
        // Given
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime yesterday = now.minusDays(1);
        LocalDateTime weekAgo = now.minusDays(7);
        
        AuditLog recentLog = new AuditLog(OperationType.SIGN, "hash1", "Ed25519", "user1", ResultType.SUCCESS);
        recentLog.setTimestamp(yesterday);
        
        AuditLog oldLog = new AuditLog(OperationType.SIGN, "hash2", "Ed25519", "user1", ResultType.SUCCESS);
        oldLog.setTimestamp(weekAgo);
        
        auditLogRepository.save(recentLog);
        auditLogRepository.save(oldLog);
        entityManager.flush();

        // When
        Page<AuditLog> recentLogs = auditLogRepository.findRecentLogs(now.minusDays(3), PageRequest.of(0, 10));

        // Then
        assertThat(recentLogs.getTotalElements()).isEqualTo(1);
        assertThat(recentLogs.getContent().get(0).getTimestamp()).isAfter(now.minusDays(3));
    }
}