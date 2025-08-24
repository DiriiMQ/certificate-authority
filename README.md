# Certificate Authority - Image Signing System

A comprehensive digital image signing and verification system built with Spring Boot 3 (Java 21) backend, React TypeScript frontend, and PostgreSQL database. This application provides secure cryptographic signing of PNG and JPEG images using Ed25519, ECDSA P-256, and RSA-3072 algorithms.

## Features

- **Image Signing**: Embed digital signatures directly into PNG and JPEG metadata
- **Detached Signatures**: Generate separate .sig files for images
- **Multiple Algorithms**: Support for Ed25519 (default), ECDSA P-256, and RSA-3072
- **Image Verification**: Validate both embedded and detached signatures
- **Key Management**: Automatic key generation, storage, and rotation
- **Audit Logging**: Complete audit trail for all operations
- **Web Interface**: Modern React TypeScript frontend with drag-and-drop upload
- **REST API**: Full RESTful API for integration

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     Frontend    │    │     Backend     │    │    Database     │
│  React + Vite   │◄──►│  Spring Boot 3  │◄──►│   PostgreSQL    │
│   TypeScript    │    │    Java 21      │    │                 │
│   Port: 5173    │    │   Port: 8080    │    │   Port: 5432    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Keys Volume   │
                       │  Cryptographic  │
                       │   Key Storage   │
                       └─────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Git

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd certificate_authority
   ```

2. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env file with your settings
   ```

3. **Start all services**
   ```bash
   docker compose up -d
   ```

4. **Verify services are running**
   ```bash
   # Check service status
   docker compose ps
   
   # View logs
   docker compose logs -f
   ```

## Service URLs

- **Frontend**: http://localhost:5173
- **Backend API**: http://localhost:8080
- **Database**: localhost:5432
- **Health Check**: http://localhost:8080/actuator/health

## Development Workflow

### Starting Services
```bash
# Start all services
docker compose up -d

# Start specific service
docker compose up frontend

# View logs
docker compose logs -f [service-name]
```

### Stopping Services
```bash
# Stop all services
docker compose down

# Stop and remove volumes (caution: deletes data)
docker compose down -v
```

### Database Access
```bash
# Connect to PostgreSQL
docker compose exec database psql -U postgres -d certificate_authority

# View database logs
docker compose logs database
```

## API Endpoints

### Image Signing
- `POST /api/sign` - Sign an image (multipart form upload)
- `POST /api/sign/detached` - Generate detached signature

### Image Verification
- `POST /api/verify` - Verify image signature
- `POST /api/verify/detached` - Verify detached signature

### Key Management
- `POST /api/keys/rotate` - Rotate signing keys
- `GET /api/keys/info` - Get key information

### Audit Logs
- `GET /api/logs` - Query audit logs with filtering
- `GET /api/logs/export` - Export audit logs

## Configuration

### Environment Variables (.env)
```bash
# Database
POSTGRES_DB=certificate_authority
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_secure_password

# Security
JWT_SECRET=your_jwt_secret
API_KEY_SECRET=your_api_key_secret

# Application
MAX_FILE_SIZE=100MB
DEFAULT_SIGNING_ALGORITHM=Ed25519
KEY_ROTATION_DAYS=90
```

### Supported Image Formats
- PNG (signatures embedded in iTXt chunks)
- JPEG/JPG (signatures embedded in COM/APP segments)
- Maximum file size: 100MB

### Cryptographic Algorithms
- **Ed25519** (default) - Fast, secure, modern
- **ECDSA P-256** - NIST standard elliptic curve
- **RSA-3072** - Traditional RSA with 3072-bit keys

## File Structure

```
certificate_authority/
├── frontend/              # React TypeScript frontend
├── backend/               # Spring Boot 3 Java 21 backend
├── database/              # PostgreSQL scripts and configuration
│   └── init-scripts/      # Database initialization scripts
├── keys/                  # Cryptographic key storage (Docker volume)
├── docs/                  # Documentation
├── docker-compose.yml     # Multi-service orchestration
├── .env                   # Environment configuration
└── README.md             # This file
```

## Security Features

- **Secure Key Storage**: Keys stored in encrypted Docker volumes
- **Algorithm Flexibility**: Multiple signing algorithms supported
- **Audit Trail**: Complete logging of all operations
- **Input Validation**: Comprehensive validation of uploads and inputs
- **Authentication**: JWT-based API authentication
- **Image Integrity**: Signatures preserve original image quality

## Troubleshooting

### Service Health Checks
```bash
# Check if all services are healthy
docker compose ps

# Test backend health endpoint
curl http://localhost:8080/actuator/health

# Test frontend
curl http://localhost:5173
```

### Common Issues
1. **Port conflicts**: Ensure ports 5173, 8080, and 5432 are available
2. **Volume permissions**: Check Docker volume permissions for key storage
3. **Database connection**: Verify PostgreSQL is healthy before backend starts
4. **Memory issues**: Large image uploads may require increased Docker memory limits

### Logs
```bash
# View all service logs
docker compose logs

# View specific service logs
docker compose logs backend
docker compose logs frontend
docker compose logs database
```

## Development

### Running Tests
```bash
# Backend tests
docker compose exec backend ./mvnw test

# Frontend tests
docker compose exec frontend npm test
```

### Hot Reload Development
- Frontend: Automatically reloads on code changes (Vite)
- Backend: Requires restart or Spring Boot DevTools

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and test thoroughly
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
