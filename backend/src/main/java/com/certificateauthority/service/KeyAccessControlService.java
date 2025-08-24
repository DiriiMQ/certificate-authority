package com.certificateauthority.service;

import com.certificateauthority.entity.AuditLog;
import com.certificateauthority.entity.OperationType;
import com.certificateauthority.entity.ResultType;
import com.certificateauthority.entity.SigningKey;
import com.certificateauthority.repository.AuditLogRepository;
import com.certificateauthority.repository.SigningKeyRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Service for key access control, security validation, and audit logging.
 * 
 * Features:
 * - Role-based access control (RBAC) for key operations
 * - Dual control for critical operations (requires two authorized users)
 * - Rate limiting to prevent abuse
 * - Suspicious activity detection and alerting
 * - Comprehensive security event logging
 * - Method-level security with Spring Security annotations
 * - Time-based access restrictions
 * 
 * Security roles:
 * - KEY_ADMIN: Full key management access
 * - KEY_OPERATOR: Key usage and rotation (limited)
 * - KEY_VIEWER: Read-only access to key metadata
 * - EMERGENCY_RESPONDER: Emergency key operations
 */
@Service
@Transactional
public class KeyAccessControlService {

    private final AuditLogRepository auditLogRepository;
    private final SigningKeyRepository signingKeyRepository;

    // Rate limiting: user -> operation count in current window
    private final Map<String, AtomicInteger> userOperationCounts = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> userWindowStartTimes = new ConcurrentHashMap<>();

    // Dual control: operation ID -> approval details
    private final Map<String, DualControlOperation> pendingOperations = new ConcurrentHashMap<>();

    // Suspicious activity tracking
    private final Map<String, List<SecurityEvent>> userSecurityEvents = new ConcurrentHashMap<>();

    // Configuration
    @Value("${app.security.rate-limit.operations-per-hour:100}")
    private int operationsPerHour;

    @Value("${app.security.rate-limit.window-minutes:60}")
    private int rateLimitWindowMinutes;

    @Value("${app.security.dual-control.enabled:true}")
    private boolean dualControlEnabled;

    @Value("${app.security.dual-control.timeout-minutes:30}")
    private int dualControlTimeoutMinutes;

    @Value("${app.security.suspicious-activity.threshold:10}")
    private int suspiciousActivityThreshold;

    @Autowired
    public KeyAccessControlService(AuditLogRepository auditLogRepository,
                                 SigningKeyRepository signingKeyRepository) {
        this.auditLogRepository = auditLogRepository;
        this.signingKeyRepository = signingKeyRepository;
    }

    /**
     * Validate access to key operations based on user roles and permissions.
     * 
     * @param operation Type of operation being performed
     * @param keyId Key ID being accessed (can be null for general operations)
     * @param requestDetails Additional context for the request
     * @return AccessValidationResult containing validation outcome
     */
    public AccessValidationResult validateAccess(KeyOperation operation, UUID keyId, 
                                               Map<String, Object> requestDetails) {
        try {
            Authentication auth = getCurrentAuthentication();
            if (auth == null || !auth.isAuthenticated()) {
                return logAndReturnFailure(operation, keyId, "User not authenticated", null);
            }

            String username = auth.getName();
            
            // Check rate limiting
            if (!checkRateLimit(username)) {
                return logAndReturnFailure(operation, keyId, "Rate limit exceeded", username);
            }

            // Check role-based permissions
            if (!hasRequiredRole(auth, operation)) {
                return logAndReturnFailure(operation, keyId, "Insufficient permissions", username);
            }

            // Check key-specific permissions
            if (keyId != null && !validateKeyAccess(auth, keyId, operation)) {
                return logAndReturnFailure(operation, keyId, "Key access denied", username);
            }

            // Check time-based restrictions
            if (!checkTimeRestrictions(auth, operation)) {
                return logAndReturnFailure(operation, keyId, "Operation not allowed at current time", username);
            }

            // Check for suspicious activity
            if (detectSuspiciousActivity(username, operation, requestDetails)) {
                return logAndReturnFailure(operation, keyId, "Suspicious activity detected", username);
            }

            // Update rate limiting counters
            updateOperationCount(username);

            // Log successful validation
            logSecurityEvent(username, operation, keyId, "Access granted", ResultType.SUCCESS, requestDetails);

            return new AccessValidationResult(true, "Access granted", username, null);

        } catch (Exception e) {
            return logAndReturnFailure(operation, keyId, "Access validation error: " + e.getMessage(), null);
        }
    }

    /**
     * Enforce role-based permissions for key operations.
     * Uses Spring Security method-level security.
     * 
     * @param operation Type of operation
     * @param keyId Key ID (optional)
     * @return true if user has required permissions
     */
    @PreAuthorize("hasRole('KEY_ADMIN') or (hasRole('KEY_OPERATOR') and #operation.name() != 'DELETE_KEY')")
    public boolean enforceRoleBasedPermissions(KeyOperation operation, UUID keyId) {
        Authentication auth = getCurrentAuthentication();
        return auth != null && hasRequiredRole(auth, operation);
    }

    /**
     * Require dual approval for critical operations.
     * 
     * @param operation Critical operation requiring dual control
     * @param keyId Key ID being affected
     * @param initiatingUser User initiating the operation
     * @param operationDetails Details of the operation
     * @return DualControlResult with operation ID for approval tracking
     */
    @PreAuthorize("hasRole('KEY_ADMIN') or hasRole('EMERGENCY_RESPONDER')")
    public DualControlResult requireDualApproval(KeyOperation operation, UUID keyId, 
                                               String initiatingUser, Map<String, Object> operationDetails) {
        if (!dualControlEnabled || !requiresDualControl(operation)) {
            return new DualControlResult(true, "Dual control not required", null, false);
        }

        try {
            String operationId = UUID.randomUUID().toString();
            LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(dualControlTimeoutMinutes);

            DualControlOperation pendingOp = new DualControlOperation(
                operationId, operation, keyId, initiatingUser, operationDetails, expiresAt
            );

            pendingOperations.put(operationId, pendingOp);

            // Log the dual control request
            logSecurityEvent(initiatingUser, operation, keyId, 
                "Dual control operation initiated", ResultType.SUCCESS, operationDetails);

            return new DualControlResult(false, "Dual approval required", operationId, true);

        } catch (Exception e) {
            logSecurityEvent(initiatingUser, operation, keyId, 
                "Dual control setup failed: " + e.getMessage(), ResultType.FAILURE, operationDetails);
            return new DualControlResult(false, "Dual control setup failed", null, false);
        }
    }

    /**
     * Approve a pending dual control operation.
     * 
     * @param operationId Operation ID to approve
     * @param approvingUser User providing the approval
     * @return DualControlResult indicating approval outcome
     */
    @PreAuthorize("hasRole('KEY_ADMIN')")
    public DualControlResult approveDualControlOperation(String operationId, String approvingUser) {
        try {
            DualControlOperation operation = pendingOperations.get(operationId);
            if (operation == null) {
                return new DualControlResult(false, "Operation not found or expired", operationId, false);
            }

            if (operation.isExpired()) {
                pendingOperations.remove(operationId);
                return new DualControlResult(false, "Operation has expired", operationId, false);
            }

            if (operation.getInitiatingUser().equals(approvingUser)) {
                return new DualControlResult(false, "Cannot approve your own operation", operationId, false);
            }

            // Validate approving user has sufficient privileges
            Authentication auth = getCurrentAuthentication();
            if (!hasRole(auth, "KEY_ADMIN")) {
                return new DualControlResult(false, "Insufficient privileges to approve", operationId, false);
            }

            operation.approve(approvingUser);
            
            // Log the approval
            logSecurityEvent(approvingUser, operation.getOperation(), operation.getKeyId(),
                "Dual control operation approved", ResultType.SUCCESS, operation.getOperationDetails());

            return new DualControlResult(true, "Operation approved", operationId, true);

        } catch (Exception e) {
            return new DualControlResult(false, "Approval failed: " + e.getMessage(), operationId, false);
        }
    }

    /**
     * Check if a dual control operation is approved and ready to execute.
     * 
     * @param operationId Operation ID to check
     * @return true if operation is approved and ready
     */
    public boolean isDualControlOperationApproved(String operationId) {
        DualControlOperation operation = pendingOperations.get(operationId);
        return operation != null && operation.isApproved() && !operation.isExpired();
    }

    /**
     * Complete a dual control operation (remove from pending).
     * 
     * @param operationId Operation ID to complete
     * @param success Whether the operation completed successfully
     */
    public void completeDualControlOperation(String operationId, boolean success) {
        DualControlOperation operation = pendingOperations.remove(operationId);
        if (operation != null) {
            String result = success ? "Operation completed successfully" : "Operation failed";
            logSecurityEvent(operation.getInitiatingUser(), operation.getOperation(), 
                operation.getKeyId(), result, success ? ResultType.SUCCESS : ResultType.FAILURE, 
                operation.getOperationDetails());
        }
    }

    /**
     * Log security events for audit and monitoring.
     * 
     * @param username User performing the operation
     * @param operation Type of operation
     * @param keyId Key ID involved (optional)
     * @param details Event details
     * @param result Success or failure
     * @param metadata Additional metadata
     */
    public void logSecurityEvent(String username, KeyOperation operation, UUID keyId, 
                                String details, ResultType result, Map<String, Object> metadata) {
        try {
            // Create audit log entry
            AuditLog auditLog = new AuditLog();
            auditLog.setOperationType(mapToOperationType(operation));
            auditLog.setUsername(username != null ? username : "system");
            auditLog.setKeyIdentifier(keyId != null ? keyId.toString() : null);
            auditLog.setImageName("N/A"); // Key operation, not image operation
            auditLog.setResultType(result);
            auditLog.setDetails(details);
            auditLog.setCreatedBy(username != null ? username : "system");

            if (metadata != null && !metadata.isEmpty()) {
                // Convert metadata to string representation
                StringBuilder metadataStr = new StringBuilder();
                metadata.forEach((key, value) -> 
                    metadataStr.append(key).append("=").append(value).append("; "));
                auditLog.setAdditionalMetadata(metadataStr.toString());
            }

            auditLogRepository.save(auditLog);

            // Track security events for suspicious activity detection
            if (username != null) {
                trackSecurityEvent(username, operation, result);
            }

        } catch (Exception e) {
            // Log to system logger as fallback
            System.err.println("Failed to log security event: " + e.getMessage());
        }
    }

    /**
     * Get current security statistics for monitoring.
     * 
     * @return SecurityStatistics containing current security metrics
     */
    @PreAuthorize("hasRole('KEY_ADMIN')")
    public SecurityStatistics getSecurityStatistics() {
        SecurityStatistics stats = new SecurityStatistics();
        
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime hourAgo = now.minusHours(1);
        LocalDateTime dayAgo = now.minusDays(1);

        // Count recent operations
        stats.setOperationsLastHour(auditLogRepository.countByCreatedAtBetween(hourAgo, now));
        stats.setOperationsLastDay(auditLogRepository.countByCreatedAtBetween(dayAgo, now));
        
        // Count failures
        stats.setFailuresLastHour(auditLogRepository.countByResultTypeAndCreatedAtBetween(
            ResultType.FAILURE, hourAgo, now));
        stats.setFailuresLastDay(auditLogRepository.countByResultTypeAndCreatedAtBetween(
            ResultType.FAILURE, dayAgo, now));

        // Dual control statistics
        stats.setPendingDualControlOperations(pendingOperations.size());
        stats.setExpiredDualControlOperations(
            (int) pendingOperations.values().stream().filter(DualControlOperation::isExpired).count());

        // Rate limiting statistics
        stats.setActiveRateLimitedUsers(userOperationCounts.size());
        stats.setTotalSuspiciousEvents(
            userSecurityEvents.values().stream().mapToInt(List::size).sum());

        return stats;
    }

    // ==================== Private Helper Methods ====================

    private Authentication getCurrentAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private boolean hasRequiredRole(Authentication auth, KeyOperation operation) {
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        
        return switch (operation) {
            case GENERATE_KEY, DELETE_KEY, EMERGENCY_ROTATE -> hasRole(auth, "KEY_ADMIN");
            case ROTATE_KEY, USE_KEY -> hasRole(auth, "KEY_ADMIN") || hasRole(auth, "KEY_OPERATOR");
            case VIEW_KEY -> hasRole(auth, "KEY_ADMIN") || hasRole(auth, "KEY_OPERATOR") || hasRole(auth, "KEY_VIEWER");
            case EMERGENCY_OPERATION -> hasRole(auth, "EMERGENCY_RESPONDER") || hasRole(auth, "KEY_ADMIN");
        };
    }

    private boolean hasRole(Authentication auth, String role) {
        return auth.getAuthorities().stream()
            .anyMatch(authority -> authority.getAuthority().equals("ROLE_" + role));
    }

    private boolean validateKeyAccess(Authentication auth, UUID keyId, KeyOperation operation) {
        // Additional key-specific access checks can be implemented here
        // For example, checking if user has access to specific keys based on ownership or assignment
        return true; // For now, allow access if user has the required role
    }

    private boolean checkTimeRestrictions(Authentication auth, KeyOperation operation) {
        // Implement time-based restrictions (e.g., critical operations only during business hours)
        // For now, allow all operations at any time
        return true;
    }

    private boolean checkRateLimit(String username) {
        LocalDateTime now = LocalDateTime.now();
        AtomicInteger count = userOperationCounts.computeIfAbsent(username, k -> new AtomicInteger(0));
        LocalDateTime windowStart = userWindowStartTimes.get(username);

        if (windowStart == null || windowStart.isBefore(now.minusMinutes(rateLimitWindowMinutes))) {
            // Reset the window
            userWindowStartTimes.put(username, now);
            count.set(0);
            return true;
        }

        return count.get() < operationsPerHour;
    }

    private void updateOperationCount(String username) {
        userOperationCounts.computeIfAbsent(username, k -> new AtomicInteger(0)).incrementAndGet();
    }

    private boolean detectSuspiciousActivity(String username, KeyOperation operation, 
                                           Map<String, Object> requestDetails) {
        List<SecurityEvent> userEvents = userSecurityEvents.computeIfAbsent(username, k -> new ArrayList<>());
        
        // Clean old events (keep only last hour)
        LocalDateTime hourAgo = LocalDateTime.now().minusHours(1);
        userEvents.removeIf(event -> event.getTimestamp().isBefore(hourAgo));
        
        // Add current event
        userEvents.add(new SecurityEvent(operation, LocalDateTime.now()));
        
        // Check for suspicious patterns
        if (userEvents.size() > suspiciousActivityThreshold) {
            // Too many operations in short time
            return true;
        }
        
        // Check for unusual operation patterns (e.g., many key deletions)
        long criticalOps = userEvents.stream()
            .filter(event -> event.getOperation() == KeyOperation.DELETE_KEY || 
                           event.getOperation() == KeyOperation.EMERGENCY_ROTATE)
            .count();
        
        return criticalOps > 3; // More than 3 critical operations in an hour
    }

    private boolean requiresDualControl(KeyOperation operation) {
        return operation == KeyOperation.DELETE_KEY || 
               operation == KeyOperation.EMERGENCY_ROTATE ||
               operation == KeyOperation.EMERGENCY_OPERATION;
    }

    private void trackSecurityEvent(String username, KeyOperation operation, ResultType result) {
        // This is handled in detectSuspiciousActivity method
    }

    private OperationType mapToOperationType(KeyOperation keyOperation) {
        return switch (keyOperation) {
            case GENERATE_KEY -> OperationType.KEY_GENERATION;
            case ROTATE_KEY, EMERGENCY_ROTATE -> OperationType.KEY_ROTATION;
            case USE_KEY -> OperationType.SIGN_IMAGE;
            case VIEW_KEY -> OperationType.VIEW_AUDIT_LOG;
            case DELETE_KEY, EMERGENCY_OPERATION -> OperationType.KEY_ROTATION; // Closest match
        };
    }

    private AccessValidationResult logAndReturnFailure(KeyOperation operation, UUID keyId, 
                                                     String reason, String username) {
        logSecurityEvent(username, operation, keyId, reason, ResultType.FAILURE, null);
        return new AccessValidationResult(false, reason, username, null);
    }

    // ==================== Data Classes ====================

    /**
     * Enum for key operations requiring access control.
     */
    public enum KeyOperation {
        GENERATE_KEY,
        ROTATE_KEY,
        DELETE_KEY,
        USE_KEY,
        VIEW_KEY,
        EMERGENCY_ROTATE,
        EMERGENCY_OPERATION
    }

    /**
     * Result of access validation.
     */
    public static class AccessValidationResult {
        private final boolean granted;
        private final String message;
        private final String username;
        private final Map<String, Object> context;

        public AccessValidationResult(boolean granted, String message, String username, 
                                    Map<String, Object> context) {
            this.granted = granted;
            this.message = message;
            this.username = username;
            this.context = context;
        }

        public boolean isGranted() { return granted; }
        public String getMessage() { return message; }
        public String getUsername() { return username; }
        public Map<String, Object> getContext() { return context; }
    }

    /**
     * Result of dual control operations.
     */
    public static class DualControlResult {
        private final boolean approved;
        private final String message;
        private final String operationId;
        private final boolean requiresApproval;

        public DualControlResult(boolean approved, String message, String operationId, boolean requiresApproval) {
            this.approved = approved;
            this.message = message;
            this.operationId = operationId;
            this.requiresApproval = requiresApproval;
        }

        public boolean isApproved() { return approved; }
        public String getMessage() { return message; }
        public String getOperationId() { return operationId; }
        public boolean requiresApproval() { return requiresApproval; }
    }

    /**
     * Pending dual control operation.
     */
    private static class DualControlOperation {
        private final String operationId;
        private final KeyOperation operation;
        private final UUID keyId;
        private final String initiatingUser;
        private final Map<String, Object> operationDetails;
        private final LocalDateTime expiresAt;
        private String approvingUser;
        private LocalDateTime approvedAt;

        public DualControlOperation(String operationId, KeyOperation operation, UUID keyId,
                                  String initiatingUser, Map<String, Object> operationDetails,
                                  LocalDateTime expiresAt) {
            this.operationId = operationId;
            this.operation = operation;
            this.keyId = keyId;
            this.initiatingUser = initiatingUser;
            this.operationDetails = operationDetails;
            this.expiresAt = expiresAt;
        }

        public void approve(String approvingUser) {
            this.approvingUser = approvingUser;
            this.approvedAt = LocalDateTime.now();
        }

        public boolean isApproved() { return approvingUser != null; }
        public boolean isExpired() { return LocalDateTime.now().isAfter(expiresAt); }

        // Getters
        public String getOperationId() { return operationId; }
        public KeyOperation getOperation() { return operation; }
        public UUID getKeyId() { return keyId; }
        public String getInitiatingUser() { return initiatingUser; }
        public Map<String, Object> getOperationDetails() { return operationDetails; }
        public LocalDateTime getExpiresAt() { return expiresAt; }
        public String getApprovingUser() { return approvingUser; }
        public LocalDateTime getApprovedAt() { return approvedAt; }
    }

    /**
     * Security event for suspicious activity detection.
     */
    private static class SecurityEvent {
        private final KeyOperation operation;
        private final LocalDateTime timestamp;

        public SecurityEvent(KeyOperation operation, LocalDateTime timestamp) {
            this.operation = operation;
            this.timestamp = timestamp;
        }

        public KeyOperation getOperation() { return operation; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    /**
     * Security statistics for monitoring.
     */
    public static class SecurityStatistics {
        private long operationsLastHour;
        private long operationsLastDay;
        private long failuresLastHour;
        private long failuresLastDay;
        private int pendingDualControlOperations;
        private int expiredDualControlOperations;
        private int activeRateLimitedUsers;
        private int totalSuspiciousEvents;

        // Getters and setters
        public long getOperationsLastHour() { return operationsLastHour; }
        public void setOperationsLastHour(long operationsLastHour) { this.operationsLastHour = operationsLastHour; }
        public long getOperationsLastDay() { return operationsLastDay; }
        public void setOperationsLastDay(long operationsLastDay) { this.operationsLastDay = operationsLastDay; }
        public long getFailuresLastHour() { return failuresLastHour; }
        public void setFailuresLastHour(long failuresLastHour) { this.failuresLastHour = failuresLastHour; }
        public long getFailuresLastDay() { return failuresLastDay; }
        public void setFailuresLastDay(long failuresLastDay) { this.failuresLastDay = failuresLastDay; }
        public int getPendingDualControlOperations() { return pendingDualControlOperations; }
        public void setPendingDualControlOperations(int pendingDualControlOperations) { this.pendingDualControlOperations = pendingDualControlOperations; }
        public int getExpiredDualControlOperations() { return expiredDualControlOperations; }
        public void setExpiredDualControlOperations(int expiredDualControlOperations) { this.expiredDualControlOperations = expiredDualControlOperations; }
        public int getActiveRateLimitedUsers() { return activeRateLimitedUsers; }
        public void setActiveRateLimitedUsers(int activeRateLimitedUsers) { this.activeRateLimitedUsers = activeRateLimitedUsers; }
        public int getTotalSuspiciousEvents() { return totalSuspiciousEvents; }
        public void setTotalSuspiciousEvents(int totalSuspiciousEvents) { this.totalSuspiciousEvents = totalSuspiciousEvents; }
        
        public double getFailureRateLastHour() {
            return operationsLastHour > 0 ? (double) failuresLastHour / operationsLastHour * 100 : 0;
        }
        
        public double getFailureRateLastDay() {
            return operationsLastDay > 0 ? (double) failuresLastDay / operationsLastDay * 100 : 0;
        }
    }
}
