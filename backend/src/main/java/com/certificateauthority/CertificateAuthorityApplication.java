package com.certificateauthority;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * Main Spring Boot Application class for Certificate Authority Backend
 * 
 * This application provides image signing and verification services with:
 * - JPA entities for audit logging
 * - Flyway database migrations
 * - Spring Data JPA auditing
 * - RESTful API endpoints
 * - Cryptographic operations (Ed25519, ECDSA P-256, RSA-3072)
 */
@SpringBootApplication
@EnableJpaRepositories(basePackages = "com.certificateauthority.repository")
public class CertificateAuthorityApplication {

    public static void main(String[] args) {
        SpringApplication.run(CertificateAuthorityApplication.class, args);
    }
}