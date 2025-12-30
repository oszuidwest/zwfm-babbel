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

## Fair Story Rotation

Babbel uses a smart rotation system to ensure all news stories get equal airtime throughout the day. This prevents the same stories from repeating every hour while others are never heard.

### How it works

When generating a bulletin, stories are selected in this priority order:

1. **Fresh stories first** - Stories that haven't been used yet today always get priority
2. **Newest content preferred** - Among fresh stories, the most recent ones (by start date) are selected first
3. **Least-recently-used fallback** - If all stories have already aired today, the ones that aired longest ago are chosen
4. **Random tiebreaker** - When stories have equal priority, random selection adds variety

### Key characteristics

- **Daily reset** - The rotation resets at midnight (server's local timezone). Every day starts fresh.
- **Per-station isolation** - Each station has its own rotation. A story airing on Station A doesn't affect its priority for Station B.
- **Automatic balancing** - No manual intervention needed. The system naturally distributes airtime across all available stories.

### Example

Scenario: 13 stories, 4 per bulletin, hourly from 07:30-18:30 (12 bulletins).

The algorithm tracks when each story was last included in a bulletin (via `MAX(bulletins.created_at)`) and prioritizes:
1. Unused stories (NULL timestamp) first, with newer `start_date` preferred
2. Then oldest-used stories (aired longest ago)
3. Random selection within equal-priority groups

| Time | Pool state | Selected | Reason |
|------|------------|----------|--------|
| 07:30 | All 13 unused | 3, 2, 11, 6 | RAND() picks 4 from 13 unused |
| 08:30 | 9 unused | 8, 10, 4, 12 | RAND() picks 4 from 9 unused |
| 09:30 | 5 unused (1,5,7,9,13) | 9, 13, 5, 1 | RAND() picks 4 from 5 unused |
| 10:30 | 1 unused (7) | 7, 11, 6, 3 | 7 (last unused) + RAND() picks 3 from {2,3,6,11} at 07:30 |
| 11:30 | Oldest: 2 at 07:30 | 2, 12, 4, 8 | 2 (oldest) + RAND() picks 3 from {4,8,10,12} at 08:30 |
| 12:30 | Oldest: 10 at 08:30 | 10, 1, 13, 5 | 10 (oldest) + RAND() picks 3 from {1,5,9,13} at 09:30 |
| 13:30 | Oldest: 9 at 09:30 | 9, 6, 7, 11 | 9 (oldest) + RAND() picks 3 from {3,6,7,11} at 10:30 |
| 14:30 | Oldest: 3 at 10:30 | 3, 4, 2, 12 | 3 (oldest) + RAND() picks 3 from {2,4,8,12} at 11:30 |
| 15:30 | Oldest: 8 at 11:30 | 8, 13, 10, 1 | 8 (oldest) + RAND() picks 3 from {1,5,10,13} at 12:30 |
| 16:30 | Oldest: 5 at 12:30 | 5, 11, 9, 6 | 5 (oldest) + RAND() picks 3 from {6,7,9,11} at 13:30 |
| 17:30 | Oldest: 7 at 13:30 | 7, 2, 4, 12 | 7 (oldest) + RAND() picks 3 from {2,3,4,12} at 14:30 |
| 18:30 | Oldest: 3 at 14:30 | 3, 13, 8, 1 | 3 (oldest) + RAND() picks 3 from {1,8,10,13} at 15:30 |

**Daily totals per story:**
| Story | Times aired | Bulletins |
|-------|-------------|-----------|
| 1 | 4× | 09:30, 12:30, 15:30, 18:30 |
| 2 | 4× | 07:30, 11:30, 14:30, 17:30 |
| 3 | 4× | 07:30, 10:30, 14:30, 18:30 |
| 4 | 4× | 08:30, 11:30, 14:30, 17:30 |
| 5 | 3× | 09:30, 12:30, 16:30 |
| 6 | 4× | 07:30, 10:30, 13:30, 16:30 |
| 7 | 3× | 10:30, 13:30, 17:30 |
| 8 | 4× | 08:30, 11:30, 15:30, 18:30 |
| 9 | 3× | 09:30, 13:30, 16:30 |
| 10 | 3× | 08:30, 12:30, 15:30 |
| 11 | 4× | 07:30, 10:30, 13:30, 16:30 |
| 12 | 4× | 08:30, 11:30, 14:30, 17:30 |
| 13 | 4× | 09:30, 12:30, 15:30, 18:30 |

All 13 stories air 3-4 times across 12 bulletins (48 total slots). The RAND() ensures varying combinations - actual selections differ each day but distribution stays fair.

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
