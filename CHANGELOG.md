# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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