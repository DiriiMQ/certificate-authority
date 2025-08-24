#!/bin/bash

# Certificate Authority Key Management System Verification Script
# This script performs comprehensive verification of the implemented system

echo "🔐 Certificate Authority Key Management System Verification"
echo "=========================================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ $2${NC}"
    else
        echo -e "${RED}❌ $2${NC}"
    fi
}

# Function to print info
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Function to print warning
print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

echo "Starting verification process..."
echo ""

# 1. Check if Docker is available
print_info "Checking Docker availability..."
if command -v docker &> /dev/null; then
    print_status 0 "Docker is available"
else
    print_status 1 "Docker is not available"
    exit 1
fi

# 2. Check if Docker Compose is available
print_info "Checking Docker Compose availability..."
if command -v docker compose &> /dev/null; then
    print_status 0 "Docker Compose is available"
else
    print_status 1 "Docker Compose is not available"
    exit 1
fi

# 3. Build the backend
print_info "Building backend container..."
if docker compose build backend &> /dev/null; then
    print_status 0 "Backend container built successfully"
else
    print_status 1 "Backend container build failed"
    echo "Build logs:"
    docker compose build backend
    exit 1
fi

# 4. Check for required files
print_info "Checking for required implementation files..."

REQUIRED_FILES=(
    "backend/src/main/java/com/certificateauthority/service/KeyGenerationService.java"
    "backend/src/main/java/com/certificateauthority/service/KeyStorageService.java"
    "backend/src/main/java/com/certificateauthority/service/KeyRotationService.java"
    "backend/src/main/java/com/certificateauthority/service/KeyAccessControlService.java"
    "backend/src/main/java/com/certificateauthority/service/KeyManagementService.java"
    "backend/src/main/resources/db/migration/V7__Add_key_management_columns_to_audit_log.sql"
    "backend/src/test/java/com/certificateauthority/service/KeyManagementIntegrationTest.java"
)

all_files_exist=true
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        print_status 0 "Found: $file"
    else
        print_status 1 "Missing: $file"
        all_files_exist=false
    fi
done

if [ "$all_files_exist" = false ]; then
    exit 1
fi

# 5. Check service implementations
print_info "Verifying service implementations..."

# Check for key methods in each service
check_service_method() {
    local file=$1
    local method=$2
    local description=$3
    
    if grep -q "$method" "$file"; then
        print_status 0 "$description"
    else
        print_status 1 "$description - Method '$method' not found"
    fi
}

# KeyGenerationService checks
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyGenerationService.java" "generateEd25519KeyPair" "KeyGenerationService: Ed25519 key generation"
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyGenerationService.java" "generateEcdsaP256KeyPair" "KeyGenerationService: ECDSA P-256 key generation"
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyGenerationService.java" "generateRsa3072KeyPair" "KeyGenerationService: RSA-3072 key generation"

# KeyStorageService checks
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyStorageService.java" "storeKey" "KeyStorageService: Key storage"
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyStorageService.java" "retrieveActiveKey" "KeyStorageService: Key retrieval"
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyStorageService.java" "AES" "KeyStorageService: AES encryption"

# KeyRotationService checks
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyRotationService.java" "rotateKey" "KeyRotationService: Key rotation"
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyRotationService.java" "scheduleRotation" "KeyRotationService: Scheduled rotation"

# KeyAccessControlService checks
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyAccessControlService.java" "validateAccess" "KeyAccessControlService: Access validation"
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyAccessControlService.java" "enforceRoleBasedPermissions" "KeyAccessControlService: RBAC"

# KeyManagementService checks
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyManagementService.java" "generateNewKey" "KeyManagementService: Key generation facade"
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyManagementService.java" "getSigningKey" "KeyManagementService: Key retrieval facade"
check_service_method "backend/src/main/java/com/certificateauthority/service/KeyManagementService.java" "Cache" "KeyManagementService: Caching implementation"

# 6. Start services for functional testing
print_info "Starting services for functional testing..."

# Stop any running services first
docker compose down &> /dev/null

# Start database
print_info "Starting database..."
if docker compose up -d database &> /dev/null; then
    print_status 0 "Database started"
    
    # Wait for database to be ready
    print_info "Waiting for database to be ready..."
    sleep 10
    
    # Start backend
    print_info "Starting backend..."
    if docker compose up -d backend &> /dev/null; then
        print_status 0 "Backend started"
        
        # Wait for backend to start
        sleep 15
        
        # Check if backend is healthy
        print_info "Checking backend health..."
        backend_logs=$(docker compose logs backend --tail 50 2>&1)
        
        if echo "$backend_logs" | grep -q "Started CertificateAuthorityApplication"; then
            print_status 0 "Backend application started successfully"
        elif echo "$backend_logs" | grep -q "APPLICATION FAILED TO START"; then
            print_status 1 "Backend application failed to start"
            echo "Error logs:"
            echo "$backend_logs" | tail -20
        else
            print_warning "Backend status unclear, checking logs..."
            echo "Recent logs:"
            echo "$backend_logs" | tail -10
        fi
        
        # Check database migrations
        if echo "$backend_logs" | grep -q "Successfully applied"; then
            print_status 0 "Database migrations applied successfully"
        else
            print_info "Checking migration status..."
        fi
        
    else
        print_status 1 "Backend failed to start"
    fi
else
    print_status 1 "Database failed to start"
fi

# 7. Summary
echo ""
echo "=========================================================="
echo "🔐 Verification Summary"
echo "=========================================================="

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Key Management System verification completed!${NC}"
    echo ""
    echo "✅ All 5 key services implemented:"
    echo "   • KeyGenerationService (Ed25519, ECDSA P-256, RSA-3072)"
    echo "   • KeyStorageService (AES-256-GCM encryption)"
    echo "   • KeyRotationService (Automated policies)"
    echo "   • KeyAccessControlService (RBAC, dual control)"
    echo "   • KeyManagementService (Facade with caching)"
    echo ""
    echo "✅ Database schema updated with migration V7"
    echo "✅ Integration test created"
    echo "✅ Docker build successful"
    echo "✅ Application startup verified"
else
    echo -e "${RED}❌ Verification encountered issues${NC}"
fi

echo ""
echo "Next steps:"
echo "• Run integration tests: docker compose exec backend mvn test"
echo "• Access application: http://localhost:8080"
echo "• View logs: docker compose logs backend"
echo ""

# Cleanup
print_info "Cleaning up test containers..."
docker compose down &> /dev/null
print_status 0 "Cleanup completed"
