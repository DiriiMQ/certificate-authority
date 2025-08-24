package com.certificateauthority.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * Configuration class for Spring Data JPA Auditing
 * Enables automatic population of @CreatedDate, @LastModifiedDate, @CreatedBy, @LastModifiedBy
 */
@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class JpaAuditingConfig {

    /**
     * Bean that provides the current auditor (user) for audit fields
     * 
     * @return AuditorAware implementation that returns current authenticated user
     */
    @Bean
    public AuditorAware<String> auditorProvider() {
        return new AuditorAwareImpl();
    }

    /**
     * Implementation of AuditorAware that retrieves current user from Spring Security context
     */
    public static class AuditorAwareImpl implements AuditorAware<String> {

        /**
         * Returns the current auditor (user) based on Spring Security context
         * 
         * @return Optional containing username or "system" as fallback
         */
        @Override
        public Optional<String> getCurrentAuditor() {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated() || 
                "anonymousUser".equals(authentication.getPrincipal())) {
                // Return system user when no authentication context is available
                return Optional.of("system");
            }
            
            // For simple authentication, principal might be a String (username)
            if (authentication.getPrincipal() instanceof String) {
                return Optional.of((String) authentication.getPrincipal());
            }
            
            // For UserDetails-based authentication
            if (authentication.getName() != null) {
                return Optional.of(authentication.getName());
            }
            
            // Fallback to system user
            return Optional.of("system");
        }
    }
}