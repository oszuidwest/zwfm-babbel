# Babbel API

HTTP API for generating audio news bulletins. Combines news stories with station-specific jingles using FFmpeg.

## Authentication

- **Local**: Username/password with session cookies
- **OAuth/OIDC**: Microsoft Entra ID, Google, Okta support
- **Headless Support**: Frontend redirect flow for separate API/UI domains
- **Auto-provisioning**: New OAuth users get 'viewer' role automatically
- **Account lockout protection**: Failed login attempt tracking

## Authorization

Role-based access control:
- admin: Full access including user management
- editor: Content management (stations, voices, stories, bulletins)
- viewer: Read-only access

## Architecture

Station-voice junction table:
- Each voice has different jingles per station
- Mix point defines when voice starts over jingle
- Files stored as `station_{id}_voice_{id}_jingle.wav`

## CORS

Cross-Origin Resource Sharing (CORS) is configurable:
- Set `BABBEL_ALLOWED_ORIGINS` environment variable
- Empty/unset: API-only access (no browser access)
- Comma-separated list: Only listed origins can access from browsers
- Credentials (cookies) are supported when origin is allowed


**Version:** 1.0.0  
**Base URL:** http://localhost:8080/api/v1

## Authentication

All endpoints require session-based authentication (except health and login).

**Login:** `POST /session/login` with `{"username": "admin", "password": "admin"}`

## API Endpoints

| Method | Endpoint | Description | Parameters | Request Body |
|--------|----------|-------------|------------|--------------|
| GET | /auth/config | Get authentication configuration | - | - |
| GET | /bulletins | List bulletins | , , station_id, include_stories | - |
| GET | /bulletins/{id}/audio | Download bulletin audio file |  | - |
| GET | /bulletins/{id}/stories | List stories included in a bulletin | , ,  | - |
| GET | /health | Health check endpoint | - | - |
| DELETE | /session | Logout and destroy session | - | - |
| GET | /session | Get current user information | - | - |
| POST | /session/login | Login with username and password (local authentication) | - | JSON |
| GET | /session/oauth/callback | OAuth callback endpoint | code*, state*, error | - |
| GET | /session/oauth/start | Start OAuth/OIDC authentication flow | frontend_url | - |
| GET | /station_voices | List station-voice relationships | , , station_id, voice_id | - |
| POST | /station_voices | Create a new station-voice relationship | - | Form |
| DELETE | /station_voices/{id} | Delete station-voice relationship |  | - |
| GET | /station_voices/{id} | Get station-voice relationship by ID |  | - |
| PUT | /station_voices/{id} | Update station-voice relationship |  | Form |
| GET | /station_voices/{id}/audio | Download station-voice jingle file |  | - |
| GET | /stations | List all stations | ,  | - |
| POST | /stations | Create a new station | - | JSON |
| DELETE | /stations/{id} | Delete station |  | - |
| GET | /stations/{id} | Get station by ID |  | - |
| PUT | /stations/{id} | Update station |  | JSON |
| POST | /stations/{id}/bulletins/generate | Generate news bulletin for a station | , download, include_story_list, max_age, force | JSON |
| GET | /stations/{id}/bulletins/latest | Get latest bulletin for a station |  | - |
| GET | /stations/{id}/bulletins/latest/audio | Download latest bulletin audio for a station |  | - |
| GET | /stories | List all stories | , , include_deleted, status, voice_id, date, weekday | - |
| POST | /stories | Create a new story | - | Form |
| DELETE | /stories/{id} | Delete story (soft delete) |  | - |
| GET | /stories/{id} | Get story by ID |  | - |
| PATCH | /stories/{id} | Update story state |  | JSON |
| PUT | /stories/{id} | Update story |  | Form |
| GET | /stories/{id}/audio | Download story audio file |  | - |
| GET | /stories/{id}/bulletins | Get bulletin history for a story |  | - |
| GET | /users | List all users | , , include_suspended, role | - |
| POST | /users | Create a new user | - | JSON |
| DELETE | /users/{id} | Permanently delete user |  | - |
| GET | /users/{id} | Get user by ID |  | - |
| PATCH | /users/{id} | Update user state |  | JSON |
| PUT | /users/{id} | Update user |  | JSON |
| PUT | /users/{id}/password | Change user password |  | JSON |
| GET | /voices | List all voices | ,  | - |
| POST | /voices | Create a new voice | - | JSON |
| DELETE | /voices/{id} | Delete voice |  | - |
| GET | /voices/{id} | Get voice by ID |  | - |
| PUT | /voices/{id} | Update voice |  | JSON |


## Response Formats

**Paginated List:**
```json
{"data": [...], "total": 150, "limit": 20, "offset": 0}
```

**Error:**
```json
{"error": "error_code", "message": "Human readable message"}
```

## Common Parameters

- `limit`/`offset`: Pagination (default: 20/0)
- `station_id`, `voice_id`: Filter by ID
- `include_deleted`, `include_suspended`: Include soft-deleted records
- `download=true`: Download file instead of JSON
- `force=true`: Force new generation
- `max_age=300`: Reuse if created within seconds
