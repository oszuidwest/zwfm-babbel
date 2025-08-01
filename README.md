# Babbel - Audio News Bulletin API

HTTP API for generating audio news bulletins. Mixes stories with station-specific jingles for radio automation systems.

## Quick Start

```bash
# Development
docker-compose up -d

# Production  
cp .env.example .env  # Configure secrets
docker-compose -f docker-compose.prod.yml up -d

# API runs on http://localhost:8080
# Login: admin/admin
```

## Features

- Multi-station: Different jingles per station/voice combo
- Scheduling: Stories run on specific weekdays  
- Audio mixing: FFmpeg combines stories + jingles
- RESTful API with OpenAPI spec

## Core API

```bash
# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -d '{"username":"admin","password":"admin"}'

# Generate bulletin
curl -X POST http://localhost:8080/api/v1/bulletins \
  -d '{"station_id":1}' 

# Download audio
curl http://localhost:8080/api/v1/stations/1/bulletins/latest/audio \
  -o bulletin.wav
```

**API documentation**: [docs/](docs/) (auto-generated from OpenAPI spec)  
**OpenAPI spec**: [openapi.yaml](openapi.yaml)

## Requirements

- Go 1.24+
- MySQL 8.0+  
- FFmpeg
- Docker (recommended)

## Docker Environments

| Feature | Development | Production |
|---------|-------------|------------|
| **Secrets** | Hardcoded | From `.env` file |
| **MySQL port** | Exposed (3306) | Internal only |
| **Auth method** | Local only | Configurable (local/oauth) |
| **Environment** | `development` | `production` |
| **CORS** | Localhost ports | Configurable via `BABBEL_ALLOWED_ORIGINS` |
| **Health checks** | Basic | Full monitoring |
| **Log rotation** | None | 10MB/3 files |
| **Restart policy** | `unless-stopped` | `always` |
| **Audio volume** | Host mounted | Docker volume |

## Development

```bash
# Setup
make install-tools
docker-compose up -d

# Test
make test-all

# Build
make build
```

## Manual Install

1. **Database**: Create MySQL database `babbel`
2. **Config**: Set environment variables:
   ```bash
   export BABBEL_DB_HOST=localhost
   export BABBEL_DB_USER=babbel  
   export BABBEL_DB_PASSWORD=your_password
   export BABBEL_SESSION_SECRET=your-32-char-secret
   # Optional: Enable CORS for web frontend
   export BABBEL_ALLOWED_ORIGINS=http://localhost:3000
   ```
3. **Run**: `go run cmd/babbel/main.go`

## Authentication

- Local: Username/password (default: admin/admin)
- OAuth: Azure AD, Google, or any OIDC provider
- Sessions: HTTP-only cookies

## Environment Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `BABBEL_DB_HOST` | MySQL host | `localhost` | `mysql` |
| `BABBEL_DB_USER` | MySQL user | `babbel` | `babbel` |
| `BABBEL_DB_PASSWORD` | MySQL password | `babbel` | `secret123` |
| `BABBEL_DB_NAME` | MySQL database | `babbel` | `babbel` |
| `BABBEL_SESSION_SECRET` | 32-char session key | - | `your-32-character-secret-key-here` |
| `BABBEL_AUTH_METHOD` | Auth method | `local` | `local`, `oauth`, `both` |
| `BABBEL_ENVIRONMENT` | Environment | `development` | `production` |
| `BABBEL_ALLOWED_ORIGINS` | CORS origins | - | `https://babbel.zuidwest.cloud` |

### CORS Configuration

Control browser access to the API:
- **Empty/unset**: API-only access (no browser access)
- **Single origin**: `BABBEL_ALLOWED_ORIGINS=https://babbel.zuidwest.cloud`
- **Multiple origins**: `BABBEL_ALLOWED_ORIGINS=https://app1.com,https://app2.com`
- **Development**: `BABBEL_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173`

## Workflow

1. Upload stories - Audio files with weekday schedules
2. Configure stations - Each station has pause settings  
3. Setup voices - Newsreaders with station-specific jingles
4. Generate bulletins - API mixes stories + jingles automatically
5. Download audio - WAV files ready for radio automation

## Files

- `openapi.yaml` - API specification
- `docker-compose.yml` - Development setup
- `migrations/` - Database schema
- `scripts/test-everything.sh` - Full integration test

---

**Streekomroep ZuidWest** | Internal radio automation tool