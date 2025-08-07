# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.6] - 2025-08-07

### Changed
- **BREAKING**: `voice_id` field is now optional for stories
- Stories can be created and updated without assigning a voice
- Stories without a voice are excluded from bulletin generation
- Database schema updated: `voice_id` column is now nullable with `ON DELETE SET NULL`

### Technical details
- Go model: `VoiceID` changed from `int` to `*int` (nullable pointer)
- Database: Foreign key constraint updated with `ON DELETE SET NULL`
- API responses: `voice` field is now `null` when no voice is assigned
- Base schema updated for fresh installations

## [1.0.5] - 2025-08-06

### Fixed
- MySQL GROUP BY compatibility issue in bulletin generation (ONLY_FULL_GROUP_BY mode)
- Story selection now uses proper Least Recently Used (LRU) algorithm
- Standardized `audio_url` field naming across all API endpoints for consistency

### Changed
- Bulletin story order is now randomized for playback variety
- Stories are prioritized based on broadcast history to ensure fair rotation
- Improved query structure for better MySQL 8.0+ compatibility

### Documentation
- Updated API documentation to reflect audio_url field standardization

## [1.0.4] - 2025-08-06

### Changed
- GET /session endpoint now returns complete User object with all fields (full_name, email, last_login_at, login_count, etc.)

### Fixed
- OAuth/OIDC login now properly updates last_login_at and login_count
- OAuth/OIDC login now updates user's full_name and email from identity provider claims
- Malformed function signature in auth service

## [1.0.3] - 2025-08-01

### Added
- Frontend redirect support for SSO/OAuth flows

### Changed
- Improved error handling throughout the application

### Fixed
- SSO authentication flow issues

### Dependencies
- Updated github.com/casbin/casbin/v2 from 2.111.0 to 2.115.0

## [1.0.2] - 2025-08-01

### Added
- Public GET /auth/config endpoint for frontend authentication discovery

## [1.0.1] - 2025-08-01

### Fixed
- CORS security configuration
- CI test environment issues
- Docker production image configuration

## [1.0.0] - 2025-01-08

### Added
- Headless API for audio news bulletin generation
- Multi-station support with configurable pause settings
- Station-specific voice jingles with custom mix points
- Flexible weekday scheduling for news stories
- Professional audio processing using FFmpeg (WAV 16bit 48kHz)
- Session-based authentication with RBAC (Admin, Editor, Viewer roles)
- OAuth/OIDC support (Azure AD, Google, custom providers)
- Role-based access control with fine-grained permissions
- Real-time bulletin generation and caching
- RESTful API with complete OpenAPI 3.0 specification
- Docker containerization for development and production
- Comprehensive integration test suite
- User management with soft delete/suspend functionality
- Story expiration scheduling
- Audio file validation and format conversion
- Database migrations and schema management

### Security
- Secure session management with HTTP-only cookies
- Password hashing with bcrypt
- CSRF protection
- Input validation and sanitization
- Audio file type validation based on content

### Documentation
- Complete API documentation (Markdown and HTML formats)
- Authentication setup guide
- Docker deployment instructions
- Development workflow documentation