# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] - 2025-01-31

### Initial Release

First release of the rebuilt Babbel API system for generating audio news bulletins for radio automation.

#### Features
- Complete REST API for bulletin generation
- Station management with customizable settings
- Voice configuration for newsreaders
- Story management with scheduling and weekday selection
- Audio bulletin generation with FFmpeg mixing
- Station-specific voice jingles with mix points
- Authentication system (local and OIDC/OAuth)
- Role-based access control (admin, editor, viewer)
- Session-based authentication with encrypted cookies
- Modern query parameters (filtering, sorting, searching)
- Soft delete for stories and users
- Comprehensive error handling with RFC 9457 Problem Details
- Cross-subdomain authentication support
- Auto-provisioning for OAuth users
- Username sanitization for OAuth email addresses

#### Technical Stack
- Go 1.24+ with Gin framework
- MySQL 9.1 database
- FFmpeg for audio processing
- Docker and Docker Compose support
- OpenAPI 3.0.3 specification
- Node.js integration test suite (66 tests)
- GitHub Actions CI/CD pipeline

#### Documentation
- Complete API reference with OpenAPI specification
- Quick start guide with examples
- Docker deployment documentation
- Authentication configuration guide
- Modern query parameters documentation

---
