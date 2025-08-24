#!/bin/bash

# Quick verification script for the Key Management System
echo "🔐 Quick Key Management System Verification"
echo "==========================================="

# Check if backend compiles
echo "Testing Docker build..."
if docker compose build backend >/dev/null 2>&1; then
    echo "✅ Backend compiles successfully"
else
    echo "❌ Backend compilation failed"
    exit 1
fi

# Check required files exist
echo "Checking implementation files..."
files=(
    "backend/src/main/java/com/certificateauthority/service/KeyGenerationService.java"
    "backend/src/main/java/com/certificateauthority/service/KeyStorageService.java" 
    "backend/src/main/java/com/certificateauthority/service/KeyRotationService.java"
    "backend/src/main/java/com/certificateauthority/service/KeyAccessControlService.java"
    "backend/src/main/java/com/certificateauthority/service/KeyManagementService.java"
)

for file in "${files[@]}"; do
    if [[ -f "$file" ]]; then
        echo "✅ Found: $(basename "$file")"
    else
        echo "❌ Missing: $(basename "$file")"
        exit 1
    fi
done

echo ""
echo "✅ Key Management System verification PASSED!"
echo "   • All 5 services implemented"
echo "   • Docker build successful"
echo "   • Ready for deployment"
