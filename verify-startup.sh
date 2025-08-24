#!/bin/bash

# Docker Startup Verification Script
# Verifies all services are healthy and ports are accessible

echo "🚀 Certificate Authority - Service Startup Verification"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if a service is running
check_service() {
    local service_name=$1
    local port=$2
    local endpoint=${3:-""}
    
    echo -n "Checking $service_name (port $port)... "
    
    # Check if port is listening
    if ! nc -z localhost $port 2>/dev/null; then
        echo -e "${RED}FAILED${NC} - Port $port not accessible"
        return 1
    fi
    
    # If endpoint provided, check HTTP response
    if [ ! -z "$endpoint" ]; then
        if curl -s -o /dev/null -w "%{http_code}" "$endpoint" | grep -q "200\|404"; then
            echo -e "${GREEN}HEALTHY${NC}"
            return 0
        else
            echo -e "${YELLOW}RESPONDING${NC} - Port accessible but endpoint may not be ready"
            return 0
        fi
    else
        echo -e "${GREEN}ACCESSIBLE${NC}"
        return 0
    fi
}

# Function to check Docker Compose services
check_docker_services() {
    echo "Docker Compose Service Status:"
    echo "------------------------------"
    
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Docker not installed or not in PATH${NC}"
        return 1
    fi
    
    if ! docker compose ps --format table; then
        echo -e "${RED}Docker Compose services not running${NC}"
        return 1
    fi
}

# Main verification process
echo "Step 1: Checking Docker Compose services..."
check_docker_services
echo ""

echo "Step 2: Checking service ports..."
echo "--------------------------------"

# Check Database (PostgreSQL)
check_service "Database (PostgreSQL)" "5432"

# Check Backend (Spring Boot)
check_service "Backend (Spring Boot)" "8080" "http://localhost:8080/actuator/health"

# Check Frontend (Vite React)
check_service "Frontend (React + Vite)" "5173" "http://localhost:5173"

echo ""
echo "Step 3: Service URLs"
echo "-------------------"
echo "• Frontend:      http://localhost:5173"
echo "• Backend API:   http://localhost:8080"
echo "• Health Check:  http://localhost:8080/actuator/health"
echo "• Database:      localhost:5432"

echo ""
echo "Step 4: Quick Commands"
echo "--------------------"
echo "• View logs:     docker compose logs -f"
echo "• Stop services: docker compose down"
echo "• Restart:       docker compose restart"

echo ""
echo "Step 5: Environment Check"
echo "------------------------"
if [ -f ".env" ]; then
    echo -e "${GREEN}✓${NC} .env file exists"
else
    echo -e "${YELLOW}⚠${NC} .env file missing (using defaults)"
fi

if [ -f "docker-compose.yml" ]; then
    echo -e "${GREEN}✓${NC} docker-compose.yml exists"
else
    echo -e "${RED}✗${NC} docker-compose.yml missing"
fi

echo ""
echo "=================================================="
echo "🎉 Startup verification complete!"
echo "If all services show as HEALTHY/ACCESSIBLE, your Certificate Authority is ready!"