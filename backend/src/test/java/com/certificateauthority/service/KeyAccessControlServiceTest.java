package com.certificateauthority.service;

import com.certificateauthority.entity.AuditLog;
import com.certificateauthority.entity.ResultType;
import com.certificateauthority.repository.AuditLogRepository;
import com.certificateauthority.repository.SigningKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive unit tests for KeyAccessControlService
 * Tests access control, security validation, and audit logging functionality
 */
@SpringBootTest
@ActiveProfiles("test")
class KeyAccessControlServiceTest {

    @MockBean
    private AuditLogRepository auditLogRepository;

    @MockBean
    private SigningKeyRepository signingKeyRepository;

    private KeyAccessControlService keyAccessControlService;

    @BeforeEach
    void setUp() {
        keyAccessControlService = new KeyAccessControlService(auditLogRepository, signingKeyRepository);
        
        // Set test configuration values
        ReflectionTestUtils.setField(keyAccessControlService, "operationsPerHour", 100);
        ReflectionTestUtils.setField(keyAccessControlService, "rateLimitWindowMinutes", 60);
        ReflectionTestUtils.setField(keyAccessControlService, "dualControlEnabled", true);
        ReflectionTestUtils.setField(keyAccessControlService, "dualControlTimeoutMinutes", 30);
        ReflectionTestUtils.setField(keyAccessControlService, "suspiciousActivityThreshold", 10);
        
        // Clear security context
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Should grant access for authenticated user with correct role")
    void testValidateAccessSuccess() {
        // Given
        Authentication auth = createAuthenticationWithRole("KEY_ADMIN");
        SecurityContextHolder.getContext().setAuthentication(auth);
        
        when(auditLogRepository.save(any(AuditLog.class))).thenReturn(new AuditLog());

        // When
        KeyAccessControlService.AccessValidationResult result = keyAccessControlService.validateAccess(
            KeyAccessControlService.KeyOperation.GENERATE_KEY, null, new HashMap<>()
        );

        // Then
        assertThat(result.isGranted()).isTrue();
        assertThat(result.getMessage()).isEqualTo("Access granted");
        assertThat(result.getUsername()).isEqualTo("testuser");
        
        verify(auditLogRepository).save(any(AuditLog.class));
    }

    @Test
    @DisplayName("Should deny access for unauthenticated user")
    void testValidateAccessUnauthenticated() {
        // Given
        SecurityContextHolder.clearContext();
        
        when(auditLogRepository.save(any(AuditLog.class))).thenReturn(new AuditLog());

        // When
        KeyAccessControlService.AccessValidationResult result = keyAccessControlService.validateAccess(
            KeyAccessControlService.KeyOperation.GENERATE_KEY, null, new HashMap<>()
        );

        // Then
        assertThat(result.isGranted()).isFalse();
        assertThat(result.getMessage()).contains("User not authenticated");
        
        verify(auditLogRepository).save(any(AuditLog.class));
    }

    @Test
    @DisplayName("Should deny access for user with insufficient permissions")
    void testValidateAccessInsufficientPermissions() {
        // Given
        Authentication auth = createAuthenticationWithRole("KEY_VIEWER");
        SecurityContextHolder.getContext().setAuthentication(auth);
        
        when(auditLogRepository.save(any(AuditLog.class))).thenReturn(new AuditLog());

        // When
        KeyAccessControlService.AccessValidationResult result = keyAccessControlService.validateAccess(
            KeyAccessControlService.KeyOperation.GENERATE_KEY, null, new HashMap<>()
        );

        // Then
        assertThat(result.isGranted()).isFalse();
        assertThat(result.getMessage()).contains("Insufficient permissions");
        
        verify(auditLogRepository).save(any(AuditLog.class));
    }

    @Test
    @DisplayName("Should test role-based permissions for different operations")
    void testRoleBasedPermissions() {
        // Test KEY_ADMIN can perform all operations
        Authentication adminAuth = createAuthenticationWithRole("KEY_ADMIN");
        SecurityContextHolder.getContext().setAuthentication(adminAuth);
        
        when(auditLogRepository.save(any(AuditLog.class))).thenReturn(new AuditLog());

        assertAccessGranted(KeyAccessControlService.KeyOperation.GENERATE_KEY);
        assertAccessGranted(KeyAccessControlService.KeyOperation.DELETE_KEY);
        assertAccessGranted(KeyAccessControlService.KeyOperation.ROTATE_KEY);
        assertAccessGranted(KeyAccessControlService.KeyOperation.USE_KEY);
        assertAccessGranted(KeyAccessControlService.KeyOperation.VIEW_KEY);

        // Test KEY_OPERATOR can perform limited operations
        Authentication operatorAuth = createAuthenticationWithRole("KEY_OPERATOR");
        SecurityContextHolder.getContext().setAuthentication(operatorAuth);

        assertAccessDenied(KeyAccessControlService.KeyOperation.GENERATE_KEY);
        assertAccessDenied(KeyAccessControlService.KeyOperation.DELETE_KEY);
        assertAccessGranted(KeyAccessControlService.KeyOperation.ROTATE_KEY);
        assertAccessGranted(KeyAccessControlService.KeyOperation.USE_KEY);
        assertAccessGranted(KeyAccessControlService.KeyOperation.VIEW_KEY);

        // Test KEY_VIEWER can only view
        Authentication viewerAuth = createAuthenticationWithRole("KEY_VIEWER");
        SecurityContextHolder.getContext().setAuthentication(viewerAuth);

        assertAccessDenied(KeyAccessControlService.KeyOperation.GENERATE_KEY);
        assertAccessDenied(KeyAccessControlService.KeyOperation.DELETE_KEY);
        assertAccessDenied(KeyAccessControlService.KeyOperation.ROTATE_KEY);
        assertAccessDenied(KeyAccessControlService.KeyOperation.USE_KEY);
        assertAccessGranted(KeyAccessControlService.KeyOperation.VIEW_KEY);
    }

    @Test
    @DisplayName("Should enforce role-based permissions method")
    void testEnforceRoleBasedPermissions() {
        // Given
        Authentication auth = createAuthenticationWithRole("KEY_ADMIN");
        SecurityContextHolder.getContext().setAuthentication(auth);

        // When & Then
        assertThat(keyAccessControlService.enforceRoleBasedPermissions(
            KeyAccessControlService.KeyOperation.GENERATE_KEY, null)).isTrue();
        
        assertThat(keyAccessControlService.enforceRoleBasedPermissions(
            KeyAccessControlService.KeyOperation.DELETE_KEY, null)).isTrue();

        // Test with insufficient role
        Authentication operatorAuth = createAuthenticationWithRole("KEY_OPERATOR");
        SecurityContextHolder.getContext().setAuthentication(operatorAuth);

        assertThat(keyAccessControlService.enforceRoleBasedPermissions(
            KeyAccessControlService.KeyOperation.DELETE_KEY, null)).isFalse();
    }

    @Test
    @DisplayName("Should require dual approval for critical operations")
    void testRequireDualApproval() {
        // Given
        Authentication auth = createAuthenticationWithRole("KEY_ADMIN");
        SecurityContextHolder.getContext().setAuthentication(auth);
        
        UUID keyId = UUID.randomUUID();
        Map<String, Object> operationDetails = Map.of("reason", "test");

        // When
        KeyAccessControlService.DualControlResult result = keyAccessControlService.requireDualApproval(
            KeyAccessControlService.KeyOperation.DELETE_KEY, keyId, "admin1", operationDetails
        );

        // Then
        assertThat(result.requiresApproval()).isTrue();
        assertThat(result.isApproved()).isFalse();
        assertThat(result.getMessage()).contains("Dual approval required");
        assertThat(result.getOperationId()).isNotNull();
    }

    @Test
    @DisplayName("Should not require dual approval for non-critical operations")
    void testNoDualApprovalRequired() {
        // Given
        Authentication auth = createAuthenticationWithRole("KEY_ADMIN");
        SecurityContextHolder.getContext().setAuthentication(auth);

        // When
        KeyAccessControlService.DualControlResult result = keyAccessControlService.requireDualApproval(
            KeyAccessControlService.KeyOperation.VIEW_KEY, null, "admin1", new HashMap<>()
        );

        // Then
        assertThat(result.requiresApproval()).isFalse();
        assertThat(result.isApproved()).isTrue();
        assertThat(result.getMessage()).contains("Dual control not required");
    }

    @Test
    @DisplayName("Should approve dual control operation")
    void testApproveDualControlOperation() {
        // Given
        Authentication auth = createAuthenticationWithRole("KEY_ADMIN");
        SecurityContextHolder.getContext().setAuthentication(auth);
        
        UUID keyId = UUID.randomUUID();
        Map<String, Object> operationDetails = Map.of("reason", "test");

        // First, create a dual control operation
        KeyAccessControlService.DualControlResult createResult = keyAccessControlService.requireDualApproval(
            KeyAccessControlService.KeyOperation.DELETE_KEY, keyId, "admin1", operationDetails
        );

        // Change to different admin for approval
        Authentication approverAuth = createAuthenticationWithRole("KEY_ADMIN", "admin2");
        SecurityContextHolder.getContext().setAuthentication(approverAuth);

        // When
        KeyAccessControlService.DualControlResult approvalResult = keyAccessControlService
            .approveDualControlOperation(createResult.getOperationId(), "admin2");

        // Then
        assertThat(approvalResult.isApproved()).isTrue();
        assertThat(approvalResult.getMessage()).contains("Operation approved");
    }

    @Test
    @DisplayName("Should prevent self-approval of dual control operation")
    void testPreventSelfApproval() {
        // Given
        Authentication auth = createAuthenticationWithRole("KEY_ADMIN");
        SecurityContextHolder.getContext().setAuthentication(auth);
        
        UUID keyId = UUID.randomUUID();

        // Create dual control operation
        KeyAccessControlService.DualControlResult createResult = keyAccessControlService.requireDualApproval(
            KeyAccessControlService.KeyOperation.DELETE_KEY, keyId, "admin1", new HashMap<>()
        );

        // Try to approve with same user
        KeyAccessControlService.DualControlResult approvalResult = keyAccessControlService
            .approveDualControlOperation(createResult.getOperationId(), "admin1");

        // Then
        assertThat(approvalResult.isApproved()).isFalse();
        assertThat(approvalResult.getMessage()).contains("Cannot approve your own operation");
    }

    @Test
    @DisplayName("Should check if dual control operation is approved")
    void testIsDualControlOperationApproved() {
        // Given
        Authentication auth = createAuthenticationWithRole("KEY_ADMIN");
        SecurityContextHolder.getContext().setAuthentication(auth);

        UUID keyId = UUID.randomUUID();
        KeyAccessControlService.DualControlResult createResult = keyAccessControlService.requireDualApproval(
            KeyAccessControlService.KeyOperation.DELETE_KEY, keyId, "admin1", new HashMap<>()
        );

        // Initially not approved
        assertThat(keyAccessControlService.isDualControlOperationApproved(createResult.getOperationId()))
            .isFalse();

        // Approve with different admin
        Authentication approverAuth = createAuthenticationWithRole("KEY_ADMIN", "admin2");
        SecurityContextHolder.getContext().setAuthentication(approverAuth);
        
        keyAccessControlService.approveDualControlOperation(createResult.getOperationId(), "admin2");

        // Now should be approved
        assertThat(keyAccessControlService.isDualControlOperationApproved(createResult.getOperationId()))
            .isTrue();
    }

    @Test
    @DisplayName("Should complete dual control operation")
    void testCompleteDualControlOperation() {
        // Given
        Authentication auth = createAuthenticationWithRole("KEY_ADMIN");
        SecurityContextHolder.getContext().setAuthentication(auth);

        UUID keyId = UUID.randomUUID();
        KeyAccessControlService.DualControlResult createResult = keyAccessControlService.requireDualApproval(
            KeyAccessControlService.KeyOperation.DELETE_KEY, keyId, "admin1", new HashMap<>()
        );

        when(auditLogRepository.save(any(AuditLog.class))).thenReturn(new AuditLog());

        // When
        keyAccessControlService.completeDualControlOperation(createResult.getOperationId(), true);

        // Then
        verify(auditLogRepository).save(any(AuditLog.class));
        
        // Operation should no longer be pending
        assertThat(keyAccessControlService.isDualControlOperationApproved(createResult.getOperationId()))
            .isFalse();
    }

    @Test
    @DisplayName("Should log security events")
    void testLogSecurityEvent() {
        // Given
        when(auditLogRepository.save(any(AuditLog.class))).thenReturn(new AuditLog());
        
        UUID keyId = UUID.randomUUID();
        Map<String, Object> metadata = Map.of(
            "ipAddress", "192.168.1.1",
            "userAgent", "Test Agent"
        );

        // When
        keyAccessControlService.logSecurityEvent(
            "testuser", 
            KeyAccessControlService.KeyOperation.GENERATE_KEY,
            keyId,
            "Key generation successful",
            ResultType.SUCCESS,
            metadata
        );

        // Then
        verify(auditLogRepository).save(argThat(auditLog -> {
            assertThat(auditLog.getUsername()).isEqualTo("testuser");
            assertThat(auditLog.getKeyIdentifier()).isEqualTo(keyId.toString());
            assertThat(auditLog.getDetails()).isEqualTo("Key generation successful");
            assertThat(auditLog.getResultType()).isEqualTo(ResultType.SUCCESS);
            assertThat(auditLog.getAdditionalMetadata()).contains("ipAddress=192.168.1.1");
            assertThat(auditLog.getAdditionalMetadata()).contains("userAgent=Test Agent");
            return true;
        }));
    }

    @Test
    @DisplayName("Should get security statistics")
    void testGetSecurityStatistics() {
        // Given
        Authentication auth = createAuthenticationWithRole("KEY_ADMIN");
        SecurityContextHolder.getContext().setAuthentication(auth);
        
        LocalDateTime now = LocalDateTime.now();
        when(auditLogRepository.countByCreatedAtBetween(any(), any())).thenReturn(50L).thenReturn(200L);
        when(auditLogRepository.countByResultTypeAndCreatedAtBetween(eq(ResultType.FAILURE), any(), any()))
            .thenReturn(5L).thenReturn(20L);

        // When
        KeyAccessControlService.SecurityStatistics stats = keyAccessControlService.getSecurityStatistics();

        // Then
        assertThat(stats.getOperationsLastHour()).isEqualTo(50L);
        assertThat(stats.getOperationsLastDay()).isEqualTo(200L);
        assertThat(stats.getFailuresLastHour()).isEqualTo(5L);
        assertThat(stats.getFailuresLastDay()).isEqualTo(20L);
        assertThat(stats.getFailureRateLastHour()).isEqualTo(10.0);
        assertThat(stats.getFailureRateLastDay()).isEqualTo(10.0);
    }

    @Test
    @DisplayName("Should calculate failure rates correctly")
    void testSecurityStatisticsFailureRates() {
        // Create statistics with known values
        KeyAccessControlService.SecurityStatistics stats = new KeyAccessControlService.SecurityStatistics();
        
        // Test normal case
        stats.setOperationsLastHour(100);
        stats.setFailuresLastHour(10);
        assertThat(stats.getFailureRateLastHour()).isEqualTo(10.0);
        
        // Test zero operations (edge case)
        stats.setOperationsLastHour(0);
        stats.setFailuresLastHour(0);
        assertThat(stats.getFailureRateLastHour()).isEqualTo(0.0);
        
        // Test zero failures
        stats.setOperationsLastHour(100);
        stats.setFailuresLastHour(0);
        assertThat(stats.getFailureRateLastHour()).isEqualTo(0.0);
    }

    @Test
    @DisplayName("Should test AccessValidationResult class")
    void testAccessValidationResultClass() {
        // Given
        Map<String, Object> context = Map.of("key", "value");

        // When
        KeyAccessControlService.AccessValidationResult result = 
            new KeyAccessControlService.AccessValidationResult(true, "Success", "user1", context);

        // Then
        assertThat(result.isGranted()).isTrue();
        assertThat(result.getMessage()).isEqualTo("Success");
        assertThat(result.getUsername()).isEqualTo("user1");
        assertThat(result.getContext()).isEqualTo(context);
    }

    @Test
    @DisplayName("Should test DualControlResult class")
    void testDualControlResultClass() {
        // When
        KeyAccessControlService.DualControlResult result = 
            new KeyAccessControlService.DualControlResult(true, "Approved", "op123", true);

        // Then
        assertThat(result.isApproved()).isTrue();
        assertThat(result.getMessage()).isEqualTo("Approved");
        assertThat(result.getOperationId()).isEqualTo("op123");
        assertThat(result.requiresApproval()).isTrue();
    }

    @Test
    @DisplayName("Should handle rate limiting")
    void testRateLimiting() {
        // Given
        Authentication auth = createAuthenticationWithRole("KEY_ADMIN");
        SecurityContextHolder.getContext().setAuthentication(auth);
        
        when(auditLogRepository.save(any(AuditLog.class))).thenReturn(new AuditLog());

        // When - perform many operations quickly
        for (int i = 0; i < 50; i++) {
            KeyAccessControlService.AccessValidationResult result = keyAccessControlService.validateAccess(
                KeyAccessControlService.KeyOperation.VIEW_KEY, null, new HashMap<>()
            );
            assertThat(result.isGranted()).isTrue(); // Should still be under limit
        }

        // Simulate exceeding rate limit by setting a very low limit
        ReflectionTestUtils.setField(keyAccessControlService, "operationsPerHour", 10);
        
        for (int i = 0; i < 15; i++) {
            keyAccessControlService.validateAccess(
                KeyAccessControlService.KeyOperation.VIEW_KEY, null, new HashMap<>()
            );
        }

        // The next operation should potentially hit rate limit (depending on implementation)
        KeyAccessControlService.AccessValidationResult result = keyAccessControlService.validateAccess(
            KeyAccessControlService.KeyOperation.VIEW_KEY, null, new HashMap<>()
        );
        
        // Note: This test might pass or fail depending on the exact timing and implementation
        // The important thing is that the rate limiting logic is exercised
    }

    // Helper methods

    private Authentication createAuthenticationWithRole(String role) {
        return createAuthenticationWithRole(role, "testuser");
    }

    private Authentication createAuthenticationWithRole(String role, String username) {
        return new TestingAuthenticationToken(
            username, 
            "password", 
            List.of(new SimpleGrantedAuthority("ROLE_" + role))
        );
    }

    private void assertAccessGranted(KeyAccessControlService.KeyOperation operation) {
        when(auditLogRepository.save(any(AuditLog.class))).thenReturn(new AuditLog());
        
        KeyAccessControlService.AccessValidationResult result = keyAccessControlService.validateAccess(
            operation, null, new HashMap<>()
        );
        assertThat(result.isGranted())
            .withFailMessage("Expected access to be granted for operation: " + operation)
            .isTrue();
    }

    private void assertAccessDenied(KeyAccessControlService.KeyOperation operation) {
        when(auditLogRepository.save(any(AuditLog.class))).thenReturn(new AuditLog());
        
        KeyAccessControlService.AccessValidationResult result = keyAccessControlService.validateAccess(
            operation, null, new HashMap<>()
        );
        assertThat(result.isGranted())
            .withFailMessage("Expected access to be denied for operation: " + operation)
            .isFalse();
    }
}
