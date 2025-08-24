# Database Configuration

This directory contains PostgreSQL database documentation for the Certificate Authority application.

⚠️ **IMPORTANT**: Database schema is now managed by **Spring Boot JPA entities** and **Flyway migrations** located in:
- **JPA Entities**: `backend/src/main/java/com/certificateauthority/entity/`
- **Flyway Migrations**: `backend/src/main/resources/db/migration/`

## Modern ORM Approach (Task 21)

The Certificate Authority now uses a modern Spring Boot + JPA + Flyway approach:

### 🏗️ Schema Management
- **Entity-First Development**: JPA entities define the schema
- **Flyway Migrations**: Production-ready versioned migrations  
- **Automatic Validation**: `spring.jpa.hibernate.ddl-auto=validate` prevents schema drift

### 📁 Current Structure
```
backend/src/
├── main/java/com/certificateauthority/
│   └── entity/AuditLog.java           # JPA entity with full annotations
├── main/resources/
│   ├── application.properties         # Database + Flyway configuration  
│   └── db/migration/
│       └── V1__Initial_Schema.sql     # Production migration script
└── test/java/com/certificateauthority/
    └── repository/AuditLogRepositoryTest.java  # Integration tests
```

## Database Schema (Managed by JPA)

### AuditLog Entity → audit_log Table

The database schema is now defined by the `AuditLog` JPA entity with automatic field mapping:

**Key Features:**
- **UUID Primary Key** with `@UuidGenerator`
- **Enum Types** for operation and result with `@Enumerated`
- **Automatic Auditing** with `@CreatedDate`, `@LastModifiedDate`, `@CreatedBy`, `@LastModifiedBy`
- **Comprehensive Indexing** defined in `@Table(indexes = {...})`
- **Field Validation** with JPA annotations

**Core Fields:**
- `id` (UUID) - Primary key with auto-generation
- `operation` (OperationType) - SIGN or VERIFY enum
- `image_hash` (String) - SHA-256 hash of image content
- `algorithm` (String) - Cryptographic algorithm used
- `timestamp` (LocalDateTime) - When operation occurred  
- `user_id` (String) - User who performed operation
- `result` (ResultType) - SUCCESS or FAIL enum
- Plus metadata fields for filename, size, signature type, error messages

**Automatic Indexes** (defined in JPA entity):
- Performance indexes on timestamp, user_id, operation, result, algorithm, image_hash
- Composite index for user+operation+time queries

## Environment Variables

The database service uses these environment variables from `.env`:

- `POSTGRES_DB` - Database name (default: certificate_authority)
- `POSTGRES_USER` - Database user (default: postgres)
- `POSTGRES_PASSWORD` - Database password

## Docker Integration

The database is configured in `docker-compose.yml` with:
- Volume persistence for data (`postgres_data`)
- Spring Boot application handles schema management via Flyway
- Health checks for service readiness
- Network isolation with other services

## Development Commands

```bash
# Connect to database container
docker compose exec database psql -U postgres -d certificate_authority

# View database logs
docker compose logs database

# View Spring Boot application logs (includes Flyway migration info)
docker compose logs backend

# Reset database (WARNING: destroys all data)
docker compose down -v
docker compose up

# Run Flyway migrations manually (if needed)
cd backend && mvn flyway:migrate

# Validate current schema against Flyway migrations
cd backend && mvn flyway:validate
```

## Modern Migration System

Database migrations are now managed by **Flyway** integrated with Spring Boot:

### 📁 Migration Location
- **Spring Boot**: `backend/src/main/resources/db/migration/`
- **Naming Convention**: `V1__Description.sql`, `V2__Add_feature.sql`, etc.
- **Automatic Execution**: Flyway runs migrations on application startup

### 🔄 Migration Workflow
1. **Develop**: Create/modify JPA entities in `backend/src/main/java/.../entity/`
2. **Generate**: Create Flyway migration script in `backend/src/main/resources/db/migration/`
3. **Validate**: Set `spring.jpa.hibernate.ddl-auto=validate` to ensure consistency
4. **Deploy**: Migrations run automatically on application startup

### 📊 Migration Tracking
- Flyway tracks applied migrations in `flyway_schema_history` table
- Spring Boot Actuator provides migration status at `/actuator/flyway`
- No manual tracking required - fully automated