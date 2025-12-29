# Babbel

Headless REST API for generating audio news bulletins. Combines news stories with station jingles to create ready-to-air audio files for radio automation systems.

## Overview

Babbel is a headless API-only system designed for integration with newsroom workflows and radio automation systems. It provides a comprehensive REST API for managing news bulletin generation for radio stations. It supports station-specific audio branding.

**Key Design Principles:**
- API-first architecture - no built-in UI
- Multi-station support with individual branding
- RFC 9457 Problem Details error handling
- Session-based and OAuth authentication
- Role-based access control (RBAC)

## Features

### Core Functionality
- **RESTful API** - Complete REST API with OpenAPI 3.0.3 specification
- **Multi-station support** - Manage multiple radio stations with individual configurations
- **Voice management** - Multiple newsreaders with station-specific jingles
- **Story scheduling** - Date ranges and weekday-specific scheduling
- **Bulletin generation** - Automated audio mixing with intelligent caching
- **Direct audio URLs** - Radio automation systems can fetch bulletins directly

### Technical Features
- **Authentication** - Local auth with bcrypt or OIDC/OAuth2 (Microsoft Entra ID, Google, Okta)
- **Authorization** - Role-based access control with Casbin (admin, editor, viewer roles)
- **Audio processing** - FFmpeg-based mixing with configurable mix points
- **Error handling** - RFC 9457 Problem Details for consistent error responses
- **Soft delete** - Stories and users support soft deletion with restoration
- **Session management** - Secure encrypted cookie sessions
- **CORS support** - Configurable cross-origin resource sharing

## Installation

See [QUICKSTART.md](QUICKSTART.md) for installation instructions.

## Newsroom Workflow

1. **Setup**: Configure your stations and newsreaders
2. **Upload jingles**: Add station-specific intro/outro jingles
3. **Create stories**: Upload or POST news items with scheduling info
4. **Generate**: API creates bulletins with appropriate jingles
5. **Broadcast**: Automation systems fetch bulletins via HTTP

## Radio Automation Integration

Automation systems can fetch the latest bulletin directly:
```
GET /api/v1/stations/{station_id}/bulletins?latest=true
```

Returns a WAV file ready for broadcast. Most automation systems can schedule HTTP audio downloads.

### Compatible Systems

- mAirList (HTTP audio source)
- RadioDJ (URL tracks)
- PlayoutONE (Network audio)
- StationPlaylist (Remote files)
- RTV AudioDownload Tool
- Any system that supports HTTP audio fetching

## Requirements

- Docker and Docker Compose
- 2GB RAM minimum
- 20GB disk space
- Linux server recommended

## API Documentation

- **OpenAPI Specification**: Complete OpenAPI 3.0.3 spec in `openapi.yaml`
- **Base URL**: `/api/v1/`
- **Authentication**: Session cookies or OAuth2
- **Content Types**: `application/json` for most endpoints, `multipart/form-data` for file uploads

### Key Endpoints

```
# Authentication
POST   /api/v1/sessions              # Login
GET    /api/v1/sessions/current      # Get current user
DELETE /api/v1/sessions/current      # Logout

# Station Management  
GET    /api/v1/stations              # List stations
POST   /api/v1/stations              # Create station
PUT    /api/v1/stations/{id}         # Update station

# Story Management
GET    /api/v1/stories               # List stories (with filters)
POST   /api/v1/stories               # Create story (with audio)
GET    /api/v1/stories/{id}/audio    # Download story audio

# Bulletin Generation
POST   /api/v1/stations/{id}/bulletins         # Generate bulletin
GET    /api/v1/stations/{id}/bulletins?latest=true # Get latest bulletin
GET    /api/v1/bulletins/{id}/audio            # Download bulletin audio
```

## Development

### Quick Start

```bash
git clone https://github.com/oszuidwest/zwfm-babbel.git
cd zwfm-babbel
docker-compose up -d     # Start services
make db-reset           # Initialize database
make run                # Run development server
```

### Available Commands

```bash
# Build & Run
make build              # Build Go binary
make run                # Run development server
make docker             # Build Docker image

# Testing
make test               # Run Go unit tests  
make test-all           # Run full integration test suite (76 tests)
npm test                # Run Node.js integration tests

# Code Quality
make lint               # Run Go linters
make quality            # Advanced static analysis

# Database
make db-reset           # Reset database with migrations
```

### Project Structure

```
cmd/babbel/             # Application entry point
internal/
  api/                  # HTTP handlers and routing
  apperrors/            # Typed application errors
  audio/                # FFmpeg audio processing
  auth/                 # Authentication and authorization
  config/               # Configuration management
  database/             # Database connection
  models/               # Data models
  repository/           # Data access layer (GORM)
  scheduler/            # Background tasks
  services/             # Business logic layer
  utils/                # Shared utilities
tests/                  # Integration test suite
migrations/             # Database migrations
openapi.yaml           # API specification
CLAUDE.md              # AI assistant instructions
```

## Tech Stack

- **Backend**: Go 1.24+ with Gin web framework
- **Database**: MySQL 8.4 with GORM ORM
- **Audio**: FFmpeg for audio mixing and processing
- **Authentication**: Casbin for RBAC, bcrypt for passwords
- **Testing**: Comprehensive Node.js integration test suite
- **Deployment**: Docker and Docker Compose
- **Documentation**: OpenAPI 3.0.3 specification

## Testing

The project includes a comprehensive test suite:
- **Unit tests**: Go tests for individual components
- **Integration tests**: 76 Node.js tests covering all endpoints
- **Test categories**: Authentication, permissions, stations, voices, stories, bulletins, users
- **Coverage**: All major API workflows and edge cases

Run tests with:
```bash
make test-all           # Run complete test suite
npm test -- --verbose   # Run with detailed output
```

## Contributing

Contributions are welcome! Please ensure:
1. All tests pass (`make test-all`)
2. Code follows Go best practices (`make lint`)
3. API changes are reflected in `openapi.yaml`
4. Documentation is updated accordingly

## License

MIT License - see [LICENSE](LICENSE) file.

## Credits

Developed by Streekomroep ZuidWest for newsroom operations across multiple local radio stations in the Netherlands.
