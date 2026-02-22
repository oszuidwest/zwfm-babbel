# Babbel API API Reference

HTTP API for generating audio news bulletins. Combines news stories with station-specific jingles using FFmpeg.

## API Design Notes

**Pure JSON API**: Story and StationVoice creation/updates now use JSON instead of multipart/form-data
- Story create/update: Use `POST /stories` and `PUT /stories/{id}` with JSON body
- Audio upload: Use separate endpoint `POST /stories/{id}/audio` with binary audio data
- StationVoice create/update: Use `POST /station-voices` and `PUT /station-voices/{id}` with JSON body
- Jingle upload: Use separate endpoint `POST /station-voices/{id}/audio` with binary audio data
- Metadata: Returned as native JSON object instead of escaped string

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


**Version:** 1.0.0 - "Station-specific voice jingles with mix points" - "Local and OAuth/OIDC authentication" - "Role-based access control (admin, editor, viewer)" - "Soft delete for stories and users" - "FFmpeg audio processing" - "Pagination and filtering on all list endpoints" - "RESTful design for radio automation" - "Removed redundant /broadcasts endpoint"  
**Base URL:** http://localhost:8080/api/v1

## Table of Contents

1. [Authentication](#authentication)
2. [Authorization](#authorization)
3. [Common Parameters](#common-parameters)
4. [Response Formats](#response-formats)
5. [Error Handling](#error-handling)
6. [API Endpoints](#api-endpoints)
   - [System](#system)
   - [Authentication](#authentication)
   - [Stations](#stations)
   - [Voices](#voices)
   - [Stories](#stories)
   - [Audio](#audio)
   - [Users](#users)
   - [Bulletin](#bulletin)
   - [Station-Voices](#station-voices)
   - [Automation](#automation)


---

## Authentication

The Babbel API uses session-based authentication with encrypted cookies. All endpoints require authentication except:
- `GET /health` - Health check endpoint
- `POST /sessions` - Login endpoint
- `GET /auth/config` - Authentication configuration

### Authentication Methods

1. **Local Authentication**
   - Username/password authentication
   - Login: `POST /sessions` with `{"username": "string", "password": "string"}`
   - Returns session cookie valid for 24 hours

2. **OAuth/OIDC Authentication**
   - Supports Microsoft Entra ID, Google, Okta
   - Start flow: `GET /auth/oauth?frontend_url=<redirect_url>`
   - Auto-provisioning for new users (default role: viewer)

3. **Session Management**
   - Check session: `GET /sessions/current`
   - Logout: `DELETE /sessions/current`

## Authorization

Role-based access control (RBAC) with three roles:

| Role | Permissions |
|------|------------|
| **admin** | Full system access including user management |
| **editor** | Create, read, update, delete content (stations, voices, stories, bulletins) |
| **viewer** | Read-only access to all resources |

## Common Parameters

### Pagination
All list endpoints support pagination:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 20 | Maximum items per page (1-100) |
| `offset` | integer | 0 | Number of items to skip |

### Modern Query Parameters
List endpoints support advanced querying:

| Parameter | Type | Example | Description |
|-----------|------|---------|-------------|
| `search` | string | `search=news` | Full-text search across searchable fields |
| `filter[field]` | string | `filter[station_id]=5` | Filter by field value |
| `filter[field][op]` | string | `filter[created_at][gte]=2024-01-01` | Advanced filtering with operators |
| `sort` | string | `sort=-created_at` | Sort results (- for DESC, field:asc/desc) |
| `fields` | string | `fields=id,name,created_at` | Select specific fields to return |

#### Filter Operators
- `gte`: Greater than or equal
- `lte`: Less than or equal
- `gt`: Greater than
- `lt`: Less than
- `ne`: Not equal
- `in`: In list (comma-separated)
- `between`: Between two values (comma-separated)
- `like`: Pattern matching (% for wildcard)

### Special Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `trashed` | string | Soft-delete filter: `only` (deleted only), `with` (include deleted) |
| `include_suspended` | boolean | Include suspended users |
| `download` | boolean | Force file download with appropriate headers |
| `force` | boolean | Force regeneration of cached resources |
| `max_age` | integer | Maximum age in seconds for cached resources |

## Response Formats

### Success Response - Single Resource
```json
{
  "id": 1,
  "name": "Example",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### Success Response - List with Pagination
```json
{
  "data": [
    {
      "id": 1,
      "name": "Example 1"
    },
    {
      "id": 2,
      "name": "Example 2"
    }
  ],
  "pagination": {
    "total": 150,
    "limit": 20,
    "offset": 0,
    "has_more": true
  }
}
```

### Created Response
```json
{
  "id": 123,
  "message": "Resource created successfully"
}
```

## Error Handling

The API uses RFC 9457 Problem Details for error responses:

```json
{
  "type": "https://babbel.api/problems/validation-error",
  "title": "Validation Error",
  "status": 400,
  "detail": "The request contains invalid fields",
  "errors": [
    {
      "field": "name",
      "message": "Name is required"
    }
  ]
}
```

### Common Error Types

| Status | Type | Description |
|--------|------|-------------|
| 400 | `validation-error` | Invalid request parameters or body |
| 401 | `unauthorized` | Missing or invalid authentication |
| 403 | `forbidden` | Insufficient permissions |
| 404 | `not-found` | Resource not found |
| 409 | `conflict` | Resource conflict (duplicate, dependency) |
| 500 | `internal-server-error` | Server error |

---

## API Endpoints


### System

System health and status endpoints


#### Health check endpoint

`GET /health`








**Response:** `200` - Service is healthy




---


### Authentication

User authentication and session management


#### Get authentication configuration

`GET /auth/config`

Returns available authentication methods for the API






**Response:** `200` - Authentication configuration




---

#### OAuth callback endpoint

`GET /auth/oauth/callback`

Handles the OAuth callback from the provider and redirects to the frontend.
This endpoint is called by the OAuth provider after user authentication.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `code` | query | string | Yes | Authorization code from OAuth provider |
| `state` | query | string | Yes | CSRF protection state |
| `error` | query | string | No | Error from OAuth provider (if authentication failed) |







**Error Responses:**

- `302`: Redirect to frontend application
- `500`: Error


---

#### Start OAuth/OIDC authentication flow

`GET /auth/oauth`

Redirects to the configured OAuth provider (Azure AD, Google, etc.).
For headless frontends, specify `frontend_url` parameter to control where users are redirected after login.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `frontend_url` | query | string | No | Frontend URL to redirect to after successful authentication.
If not provided, uses BABBEL_FRONTEND_URL environment variable.
 |







**Error Responses:**

- `302`: Redirect to OAuth provider
- `400`: Error


---

#### Logout and destroy session

`DELETE /sessions/current`








**Response:** `204` - Session terminated successfully



**Error Responses:**

- `500`: Error


---

#### Get current user information

`GET /sessions/current`

Returns the complete user object for the authenticated user, including full_name, email, and login statistics.






**Response:** `200` - Current user information



**Error Responses:**

- `401`: Error


---

#### Login with username and password (local authentication)

`POST /sessions`






**Request Body:** `application/json`



**Response:** `201` - Session created successfully



**Error Responses:**

- `400`: Error
- `401`: Error


---


### Stations

Radio station management


#### Delete station

`DELETE /stations/{id}`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `204` - Station deleted



**Error Responses:**

- `404`: Error
- `500`: Error


---

#### Get station by ID

`GET /stations/{id}`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `200` - Station details



**Error Responses:**

- `404`: Error
- `500`: Error


---

#### Update station

`PUT /stations/{id}`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |



**Request Body:** `application/json`



**Response:** `200` - Station updated successfully



**Error Responses:**

- `400`: Error
- `404`: Error
- `409`: Error
- `422`: Error
- `500`: Error


---

#### List all stations

`GET /stations`

Returns a paginated list of radio stations with modern query parameter support.

## Search Fields
Full-text search across:
- `s.name` - Station name

## Filter Fields
Available filter fields:
- `id` - Station ID
- `name` - Station name (supports like operator for pattern matching)
- `max_stories_per_block` - Maximum stories per bulletin block
- `pause_seconds` - Pause duration between stories
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp

## Sort Fields
Available sort fields:
- `id` - Station ID
- `name` - Station name (default: ascending)
- `max_stories_per_block` - Max stories per block
- `pause_seconds` - Pause duration
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp

## Examples
- Search by name: `?search=Radio`
- Filter by name pattern: `?filter[name][like]=%FM%`
- Sort by creation date: `?sort=-created_at`
- Filter by max stories: `?filter[max_stories_per_block][gte]=5`
- Field selection: `?fields=id,name,max_stories_per_block`
- Complex query: `?search=Radio&filter[max_stories_per_block][gte]=5&sort=name&fields=id,name`



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `limit` | query | integer | No | Maximum number of items to return |
| `offset` | query | integer | No | Number of items to skip |
| `sort` | query | string | No | Sort order. Use field:direction format or prefix notation:
- `name:asc` or `+name` - ascending
- `name:desc` or `-name` - descending
- `created_at:desc,name:asc` - multiple fields
 |
| `fields` | query | string | No | Comma-separated list of fields to include in response.
Use dot notation for nested fields.
 |
| `search` | query | string | No | Search term for full-text search across relevant fields.
Searches in names, titles, text content depending on resource.
 |
| `filter` | query | object | No | Advanced filtering using field-based operators.

Basic usage: `filter[field]=value`

Advanced operators: `filter[field][op]=value`

Supported operators:
- `eq` - equals (default)
- `ne` - not equals
- `gt`, `gte`, `lt`, `lte` - comparisons
- `like` - pattern matching
- `in` - comma-separated values
- `null` - is/isn't null
- `band` - bitwise AND (for bitmask fields, returns records where field & value != 0)

**URL Encoding:** Bracket characters `[` and `]` must be URL-encoded as `%5B` and `%5D` when using HTTP clients like curl. Most modern HTTP libraries (axios, fetch, etc.) handle this encoding automatically.
 |





**Response:** `200` - List of stations with pagination metadata



**Error Responses:**

- `500`: Error


---

#### Create a new station

`POST /stations`






**Request Body:** `application/json`



**Response:** `201` - Station created



**Error Responses:**

- `400`: Error
- `409`: Error
- `422`: Error
- `500`: Error


---


### Voices

Voice/presenter management


#### Delete voice

`DELETE /voices/{id}`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `204` - Voice deleted



**Error Responses:**

- `404`: Error
- `409`: Error
- `500`: Error


---

#### Get voice by ID

`GET /voices/{id}`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `200` - Voice details



**Error Responses:**

- `404`: Error
- `500`: Error


---

#### Update voice

`PUT /voices/{id}`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |



**Request Body:** `application/json`



**Response:** `200` - Voice updated successfully



**Error Responses:**

- `400`: Error
- `404`: Error
- `409`: Error
- `500`: Error


---

#### List all voices

`GET /voices`

Returns a paginated list of newsreader voices with modern query parameter support.

## Search Fields
Full-text search across:
- `name` - Voice name

## Filter Fields
Available filter fields:
- `id` - Voice ID
- `name` - Voice name (supports like operator for pattern matching)
- `created_at` - Creation timestamp

## Sort Fields
Available sort fields:
- `id` - Voice ID
- `name` - Voice name (default: ascending)
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp

## Examples
- Search by name: `?search=John`
- Filter by name pattern: `?filter[name][like]=%Announcer%`
- Sort by name descending: `?sort=-name`
- Multiple filters: `?filter[id][in]=1,2,3&sort=name`
- Field selection: `?fields=id,name,created_at`
- Complex query: `?search=Voice&filter[id][in]=1,2,3&sort=-name&fields=id,name&limit=10`



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `limit` | query | integer | No | Maximum number of items to return |
| `offset` | query | integer | No | Number of items to skip |
| `sort` | query | string | No | Sort order. Use field:direction format or prefix notation:
- `name:asc` or `+name` - ascending
- `name:desc` or `-name` - descending
- `created_at:desc,name:asc` - multiple fields
 |
| `fields` | query | string | No | Comma-separated list of fields to include in response.
Use dot notation for nested fields.
 |
| `search` | query | string | No | Search term for full-text search across relevant fields.
Searches in names, titles, text content depending on resource.
 |
| `filter` | query | object | No | Advanced filtering using field-based operators.

Basic usage: `filter[field]=value`

Advanced operators: `filter[field][op]=value`

Supported operators:
- `eq` - equals (default)
- `ne` - not equals
- `gt`, `gte`, `lt`, `lte` - comparisons
- `like` - pattern matching
- `in` - comma-separated values
- `null` - is/isn't null
- `band` - bitwise AND (for bitmask fields, returns records where field & value != 0)

**URL Encoding:** Bracket characters `[` and `]` must be URL-encoded as `%5B` and `%5D` when using HTTP clients like curl. Most modern HTTP libraries (axios, fetch, etc.) handle this encoding automatically.
 |





**Response:** `200` - List of voices with pagination metadata



**Error Responses:**

- `500`: Error


---

#### Create a new voice

`POST /voices`






**Request Body:** `application/json`



**Response:** `201` - Voice created



**Error Responses:**

- `400`: Error
- `409`: Error
- `500`: Error


---


### Stories

News story management


#### Download story audio file

`GET /stories/{id}/audio`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `200` - Audio file



**Error Responses:**

- `404`: Story not found or no audio file


---

#### Upload story audio file

`POST /stories/{id}/audio`

Upload audio file for a story. Accepts WAV or MP3 format.
Audio duration is automatically calculated and stored.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |



**Request Body:** `multipart/form-data`



**Response:** `201` - Audio uploaded successfully



**Error Responses:**

- `400`: Error
- `404`: Error
- `500`: Error


---

#### Get bulletin history for a story

`GET /stories/{id}/bulletins`

Returns all bulletins that have included this specific story with modern query parameter support.
Ordered by most recent inclusion first by default.

## Search Fields
Full-text search across:
- `b.filename` - Bulletin filename
- `s.name` - Station name

## Filter Fields
Available filter fields:
- `id` - Bulletin ID
- `bulletin_id` - Bulletin ID (same as id)
- `station_id` - Station ID
- `filename` - Bulletin filename
- `audio_file` - Audio filename
- `duration_seconds` - Duration in seconds
- `file_size` - File size in bytes
- `story_count` - Number of stories in bulletin
- `file_purged_at` - When audio file was cleaned up (null = file exists)
- `created_at` - Bulletin creation timestamp
- `station_name` - Station name (from join)
- `story_order` - Order of story in bulletin
- `included_at` - When story was included in bulletin

## Sort Fields
Available sort fields:
- `id` - Bulletin ID
- `station_id` - Station ID
- `filename` - Bulletin filename
- `audio_file` - Audio filename
- `duration_seconds` - Duration
- `file_size` - File size
- `story_count` - Number of stories
- `file_purged_at` - File cleanup timestamp
- `created_at` - Bulletin creation timestamp
- `station_name` - Station name
- `story_order` - Story order in bulletin
- `included_at` - Inclusion timestamp (default: descending)

## Examples
- Search by bulletin filename: `?search=bulletin_2024`
- Filter by station: `?filter[station_id]=1`
- Filter by date range: `?filter[included_at][gte]=2024-01-01`
- Sort by story order: `?sort=story_order`
- Field selection: `?fields=id,filename,story_order,included_at`
- Complex query: `?search=bulletin&filter[story_order][lte]=2&sort=-included_at&fields=id,filename,story_order`



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |
| `limit` | query | integer | No | Maximum number of items to return |
| `offset` | query | integer | No | Number of items to skip |
| `sort` | query | string | No | Sort order. Use field:direction format or prefix notation:
- `name:asc` or `+name` - ascending
- `name:desc` or `-name` - descending
- `created_at:desc,name:asc` - multiple fields
 |
| `fields` | query | string | No | Comma-separated list of fields to include in response.
Use dot notation for nested fields.
 |
| `search` | query | string | No | Search term for full-text search across relevant fields.
Searches in names, titles, text content depending on resource.
 |
| `filter` | query | object | No | Advanced filtering using field-based operators.

Basic usage: `filter[field]=value`

Advanced operators: `filter[field][op]=value`

Supported operators:
- `eq` - equals (default)
- `ne` - not equals
- `gt`, `gte`, `lt`, `lte` - comparisons
- `like` - pattern matching
- `in` - comma-separated values
- `null` - is/isn't null
- `band` - bitwise AND (for bitmask fields, returns records where field & value != 0)

**URL Encoding:** Bracket characters `[` and `]` must be URL-encoded as `%5B` and `%5D` when using HTTP clients like curl. Most modern HTTP libraries (axios, fetch, etc.) handle this encoding automatically.
 |





**Response:** `200` - Story bulletin history with pagination metadata



**Error Responses:**

- `404`: Error
- `500`: Error


---

#### Generate story audio via text-to-speech

`POST /stories/{id}/tts`

Generates audio for a story using the ElevenLabs text-to-speech API.
Requires the story to have text content and a voice with an ElevenLabs voice ID configured.
The generated audio replaces any existing audio file for the story.

**Prerequisites:**
- TTS must be enabled (BABBEL_ELEVENLABS_API_KEY configured)
- Story must have non-empty `text`
- Story must have a `voice_id` assigned
- The assigned voice must have an `elevenlabs_voice_id` configured

**Audio pipeline:** ElevenLabs returns MP3 → converted to 48kHz mono WAV → stored as story audio.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |
| `force` | query | string | No | Set to "true" to overwrite existing audio. Without this, the request fails if the story already has audio. |





**Response:** `201` - TTS audio generated successfully



**Error Responses:**

- `400`: Validation error. Possible causes:
- Story has no text
- Story has no voice assigned
- Voice has no ElevenLabs voice ID configured
- Story already has audio (use ?force=true to overwrite)
- ElevenLabs voice ID not found
- ElevenLabs API key is invalid
- ElevenLabs rate limit exceeded

- `404`: Error
- `500`: Error
- `501`: TTS is not configured on the server


---

#### Delete story (soft delete)

`DELETE /stories/{id}`

Performs a soft delete by setting deleted_at timestamp.
The story will no longer appear in listings unless trashed=with is specified.
Story data and audio files are preserved for potential restoration.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `204` - Story soft deleted successfully



**Error Responses:**

- `404`: Error


---

#### Get story by ID

`GET /stories/{id}`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `200` - Story details



**Error Responses:**

- `404`: Error
- `500`: Error


---

#### Update story state

`PATCH /stories/{id}`

Update story status or restore soft-deleted stories. 
This endpoint can be used to:
- Change story status (draft, active, expired)
- Restore a soft-deleted story by setting deleted_at to empty string



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |



**Request Body:** `application/json`



**Response:** `200` - Story state updated successfully (status change or restore). Returns the updated story.



**Error Responses:**

- `400`: Error
- `404`: Error


---

#### Update story (full update)

`PUT /stories/{id}`

Update story with JSON body. All fields are optional - only provided fields will be updated.
Audio file must be uploaded separately via POST /stories/{id}/audio.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |



**Request Body:** `application/json`



**Response:** `200` - Story updated



**Error Responses:**

- `400`: Error
- `404`: Error
- `422`: Error
- `500`: Error


---

#### List all stories

`GET /stories`

List stories with modern query parameter support.

## Date Filtering
Use date range filters to find stories active on specific dates:
- `filter[start_date][lte]=2024-06-15` - Start date before or on date
- `filter[end_date][gte]=2024-06-15` - End date after or on date

## Weekday Filtering
The weekdays field is a bitmask integer (0-127). Each day is a power of 2:
- Sunday=1, Monday=2, Tuesday=4, Wednesday=8, Thursday=16, Friday=32, Saturday=64
- Common values: 127 (all days), 62 (Mon-Fri), 65 (weekend)

Use the `band` operator for bitwise AND filtering (returns stories where field & value != 0):
- `filter[weekdays][band]=2` - Stories that play on Monday
- `filter[weekdays][band]=64` - Stories that play on Saturday
- `filter[weekdays][band]=65` - Stories that play on weekend (Sat=64 + Sun=1)

Use exact equality for specific schedule:
- `filter[weekdays]=62` - Stories scheduled for Mon-Fri only
- `filter[weekdays]=127` - Stories scheduled for all days

## Voice Filtering
- `filter[voice_id]=5` - Stories with specific voice
- `filter[voice_id][ne]=null` - Stories with any voice assigned
- `filter[voice_id][null]=true` - Stories without voice

## Audio Filtering
Filter stories by audio presence using the `audio_url` field:
- `filter[audio_url]=` - Stories WITHOUT audio (empty value)
- `filter[audio_url][ne]=` - Stories WITH audio (not empty)

Use cases:
- Quality control: Find stories missing audio before publication
- Bulk TTS: Identify stories that need text-to-speech generation
- Dashboard: Sort by audio presence with `sort=audio_url:asc`

## Examples
- Active stories on June 15, 2024: `?filter[start_date][lte]=2024-06-15&filter[end_date][gte]=2024-06-15`
- Stories that play on Monday: `?filter[weekdays][band]=2`
- Weekend stories with voice: `?filter[weekdays][band]=65&filter[voice_id][ne]=null`
- Search with sorting: `?search=breaking&sort=-created_at`



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `limit` | query | integer | No | Maximum number of items to return |
| `offset` | query | integer | No | Number of items to skip |
| `sort` | query | string | No | Sort order. Use field:direction format or prefix notation:
- `name:asc` or `+name` - ascending
- `name:desc` or `-name` - descending
- `created_at:desc,name:asc` - multiple fields
 |
| `fields` | query | string | No | Comma-separated list of fields to include in response.
Use dot notation for nested fields.
 |
| `search` | query | string | No | Search term for full-text search across relevant fields.
Searches in names, titles, text content depending on resource.
 |
| `trashed` | query | string | No | Filter soft-deleted records:
- (omitted) - only non-deleted records (default)
- `only` - only soft-deleted records
- `with` - all records including deleted
 |
| `filter` | query | object | No | Advanced filtering using field-based operators.

Basic usage: `filter[field]=value`

Advanced operators: `filter[field][op]=value`

Supported operators:
- `eq` - equals (default)
- `ne` - not equals
- `gt`, `gte`, `lt`, `lte` - comparisons
- `like` - pattern matching
- `in` - comma-separated values
- `null` - is/isn't null
- `band` - bitwise AND (for bitmask fields, returns records where field & value != 0)

**URL Encoding:** Bracket characters `[` and `]` must be URL-encoded as `%5B` and `%5D` when using HTTP clients like curl. Most modern HTTP libraries (axios, fetch, etc.) handle this encoding automatically.
 |





**Response:** `200` - List of stories




---

#### Create a new story

`POST /stories`

Create a new story with JSON body. Audio file must be uploaded separately via POST /stories/{id}/audio.





**Request Body:** `application/json`



**Response:** `201` - Story created



**Error Responses:**

- `400`: Error
- `500`: Error


---


### Audio

Audio file serving



### Users

User account management


#### Permanently delete user

`DELETE /users/{id}`

Permanently deletes a user account and all associated data.
This action cannot be undone. All active sessions for the user will be terminated.
Cannot delete the last admin user.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `204` - User permanently deleted



**Error Responses:**

- `400`: Error
- `404`: Error


---

#### Get user by ID

`GET /users/{id}`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `200` - User details



**Error Responses:**

- `404`: Error


---

#### Update user state

`PATCH /users/{id}`

Update user state (suspend/restore) without requiring full user data. 
This is an alternative to using PUT /users/{id} with the suspended field.
Use this endpoint when you only want to change suspension status without providing other user fields.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |



**Request Body:** `application/json`



**Response:** `200` - User state updated successfully. Returns the updated user.



**Error Responses:**

- `400`: Error
- `404`: Error


---

#### Update user

`PUT /users/{id}`

Update user information. All fields are optional - only provided fields will be updated.
Can also suspend/restore users by setting the suspended field to true/false.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |



**Request Body:** `application/json`



**Response:** `200` - User updated successfully



**Error Responses:**

- `404`: Error


---

#### List all users

`GET /users`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `limit` | query | integer | No | Maximum number of items to return |
| `offset` | query | integer | No | Number of items to skip |
| `sort` | query | string | No | Sort order. Use field:direction format or prefix notation:
- `name:asc` or `+name` - ascending
- `name:desc` or `-name` - descending
- `created_at:desc,name:asc` - multiple fields
 |
| `fields` | query | string | No | Comma-separated list of fields to include in response.
Use dot notation for nested fields.
 |
| `search` | query | string | No | Search term for full-text search across relevant fields.
Searches in names, titles, text content depending on resource.
 |
| `trashed` | query | string | No | Filter soft-deleted records:
- (omitted) - only non-deleted records (default)
- `only` - only soft-deleted records
- `with` - all records including deleted
 |
| `filter` | query | object | No | Advanced filtering using field-based operators.

Basic usage: `filter[field]=value`

Advanced operators: `filter[field][op]=value`

Supported operators:
- `eq` - equals (default)
- `ne` - not equals
- `gt`, `gte`, `lt`, `lte` - comparisons
- `like` - pattern matching
- `in` - comma-separated values
- `null` - is/isn't null
- `band` - bitwise AND (for bitmask fields, returns records where field & value != 0)

**URL Encoding:** Bracket characters `[` and `]` must be URL-encoded as `%5B` and `%5D` when using HTTP clients like curl. Most modern HTTP libraries (axios, fetch, etc.) handle this encoding automatically.
 |





**Response:** `200` - List of users




---

#### Create a new user

`POST /users`






**Request Body:** `application/json`



**Response:** `201` - User created



**Error Responses:**

- `400`: Error


---


### Bulletin

Audio bulletin generation


#### Download bulletin audio file

`GET /bulletins/{id}/audio`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `200` - Audio file



**Error Responses:**

- `404`: Bulletin not found or no audio file


---

#### List stories included in a bulletin

`GET /bulletins/{id}/stories`

Returns a paginated list of stories that were included in a specific bulletin with modern query parameter support.
Ordered by story appearance order (story_order) by default.

## Search Fields
Full-text search across:
- `st.title` - Story title
- `s.name` - Station name
- `b.filename` - Bulletin filename

## Filter Fields
Available filter fields:
- `id` - Bulletin-story relationship ID
- `bulletin_id` - Bulletin ID (automatically filtered by path parameter)
- `story_id` - Story ID
- `story_order` - Order of story in bulletin
- `created_at` - When story was added to bulletin
- `station_id` - Station ID (from bulletin join)
- `station_name` - Station name (from join)
- `story_title` - Story title (from join)
- `bulletin_filename` - Bulletin filename (from join)

## Sort Fields
Available sort fields:
- `id` - Relationship ID
- `story_id` - Story ID
- `story_order` - Story order in bulletin (default: ascending)
- `created_at` - Addition timestamp
- `station_name` - Station name
- `story_title` - Story title
- `bulletin_filename` - Bulletin filename

## Examples
- Search by story title: `?search=breaking`
- Filter by story order: `?filter[story_order][lte]=3`
- Sort by story title: `?sort=story_title`
- Field selection: `?fields=id,story_id,story_order,story_title`
- Complex query: `?search=news&filter[story_order][lte]=5&sort=story_order&fields=id,story_title,story_order`



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |
| `limit` | query | integer | No | Maximum number of items to return |
| `offset` | query | integer | No | Number of items to skip |
| `sort` | query | string | No | Sort order. Use field:direction format or prefix notation:
- `name:asc` or `+name` - ascending
- `name:desc` or `-name` - descending
- `created_at:desc,name:asc` - multiple fields
 |
| `fields` | query | string | No | Comma-separated list of fields to include in response.
Use dot notation for nested fields.
 |
| `search` | query | string | No | Search term for full-text search across relevant fields.
Searches in names, titles, text content depending on resource.
 |
| `filter` | query | object | No | Advanced filtering using field-based operators.

Basic usage: `filter[field]=value`

Advanced operators: `filter[field][op]=value`

Supported operators:
- `eq` - equals (default)
- `ne` - not equals
- `gt`, `gte`, `lt`, `lte` - comparisons
- `like` - pattern matching
- `in` - comma-separated values
- `null` - is/isn't null
- `band` - bitwise AND (for bitmask fields, returns records where field & value != 0)

**URL Encoding:** Bracket characters `[` and `]` must be URL-encoded as `%5B` and `%5D` when using HTTP clients like curl. Most modern HTTP libraries (axios, fetch, etc.) handle this encoding automatically.
 |





**Response:** `200` - List of stories in the bulletin with pagination metadata



**Error Responses:**

- `404`: Error
- `500`: Error


---

#### Get bulletin by ID

`GET /bulletins/{id}`

Returns a single bulletin by its ID.

The response includes computed fields:
- `station_name` - Name of the associated station
- `audio_url` - URL to download the bulletin audio file



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `200` - Bulletin details



**Error Responses:**

- `401`: Error
- `403`: Error
- `404`: Error
- `500`: Error


---

#### List bulletins

`GET /bulletins`

Returns a paginated list of generated bulletins with modern query parameter support.

## Search Fields
Full-text search across:
- `b.filename` - Bulletin filename
- `s.name` - Station name

## Filter Fields
Available filter fields:
- `id` - Bulletin ID
- `station_id` - Station ID
- `filename` - Bulletin filename
- `audio_file` - Audio filename
- `duration_seconds` - Duration in seconds
- `file_size` - File size in bytes
- `story_count` - Number of stories in bulletin
- `file_purged_at` - When audio file was cleaned up (null = file exists)
- `metadata` - JSON metadata
- `created_at` - Creation timestamp
- `station_name` - Station name (from join)

## Sort Fields
Available sort fields:
- `id` - Bulletin ID
- `station_id` - Station ID
- `filename` - Bulletin filename
- `audio_file` - Audio filename
- `duration_seconds` - Duration
- `file_size` - File size
- `story_count` - Number of stories
- `file_purged_at` - File cleanup timestamp
- `created_at` - Creation timestamp (default: descending)
- `station_name` - Station name

## Notes
To get story information for a bulletin, use GET /bulletins/{id}/stories after fetching the bulletin list.

## Examples
- Search by filename: `?search=bulletin_2024`
- Filter by station: `?filter[station_id]=1`
- Filter by date range: `?filter[created_at][gte]=2024-01-01`
- Sort by duration: `?sort=-duration_seconds`
- Filter by story count: `?filter[story_count][gte]=3`
- Field selection: `?fields=id,filename,duration_seconds,story_count,created_at`
- Complex query: `?search=2024&filter[station_id]=1&filter[story_count][gte]=3&sort=-created_at`



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `limit` | query | integer | No | Maximum number of items to return |
| `offset` | query | integer | No | Number of items to skip |
| `sort` | query | string | No | Sort order. Use field:direction format or prefix notation:
- `name:asc` or `+name` - ascending
- `name:desc` or `-name` - descending
- `created_at:desc,name:asc` - multiple fields
 |
| `fields` | query | string | No | Comma-separated list of fields to include in response.
Use dot notation for nested fields.
 |
| `search` | query | string | No | Search term for full-text search across relevant fields.
Searches in names, titles, text content depending on resource.
 |
| `filter` | query | object | No | Advanced filtering using field-based operators.

Basic usage: `filter[field]=value`

Advanced operators: `filter[field][op]=value`

Supported operators:
- `eq` - equals (default)
- `ne` - not equals
- `gt`, `gte`, `lt`, `lte` - comparisons
- `like` - pattern matching
- `in` - comma-separated values
- `null` - is/isn't null
- `band` - bitwise AND (for bitmask fields, returns records where field & value != 0)

**URL Encoding:** Bracket characters `[` and `]` must be URL-encoded as `%5B` and `%5D` when using HTTP clients like curl. Most modern HTTP libraries (axios, fetch, etc.) handle this encoding automatically.
 |





**Response:** `200` - List of bulletins with pagination metadata



**Error Responses:**

- `401`: Error
- `403`: Error
- `500`: Error


---

#### List bulletins for a station

`GET /stations/{id}/bulletins`

Returns a paginated list of bulletins generated for a specific station with modern query parameter support.
Ordered by most recent first by default.

## Search Fields
Full-text search across:
- `b.filename` - Bulletin filename
- `s.name` - Station name

## Filter Fields
Available filter fields:
- `id` - Bulletin ID
- `station_id` - Station ID (automatically filtered by path parameter)
- `filename` - Bulletin filename
- `audio_file` - Audio filename
- `duration_seconds` - Duration in seconds
- `file_size` - File size in bytes
- `story_count` - Number of stories in bulletin
- `file_purged_at` - When audio file was cleaned up (null = file exists)
- `created_at` - Creation timestamp
- `station_name` - Station name (from join)

## Sort Fields
Available sort fields:
- `id` - Bulletin ID
- `filename` - Bulletin filename
- `audio_file` - Audio filename
- `duration_seconds` - Duration
- `file_size` - File size
- `story_count` - Number of stories
- `file_purged_at` - File cleanup timestamp
- `created_at` - Creation timestamp (default: descending)
- `station_name` - Station name

## Special Parameters
- `latest=true` - Returns only the latest bulletin with cache headers (Last-Modified, ETag)
- `limit=1` - Also triggers the special single-bulletin response with cache headers, equivalent to `latest=true`

## Notes
To get story information for bulletins, use GET /bulletins/{id}/stories for each bulletin.

## Examples
- Latest bulletin: `?latest=true`
- Search by filename: `?search=bulletin_2024`
- Filter by date range: `?filter[created_at][gte]=2024-01-01`
- Sort by duration: `?sort=-duration_seconds`
- Field selection: `?fields=id,filename,duration_seconds,created_at`
- Complex query: `?search=2024&filter[story_count][gte]=3&sort=-created_at&fields=id,filename,story_count`



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |
| `limit` | query | integer | No | Maximum number of items to return |
| `offset` | query | integer | No | Number of items to skip |
| `sort` | query | string | No | Sort order. Use field:direction format or prefix notation:
- `name:asc` or `+name` - ascending
- `name:desc` or `-name` - descending
- `created_at:desc,name:asc` - multiple fields
 |
| `fields` | query | string | No | Comma-separated list of fields to include in response.
Use dot notation for nested fields.
 |
| `search` | query | string | No | Search term for full-text search across relevant fields.
Searches in names, titles, text content depending on resource.
 |
| `filter` | query | object | No | Advanced filtering using field-based operators.

Basic usage: `filter[field]=value`

Advanced operators: `filter[field][op]=value`

Supported operators:
- `eq` - equals (default)
- `ne` - not equals
- `gt`, `gte`, `lt`, `lte` - comparisons
- `like` - pattern matching
- `in` - comma-separated values
- `null` - is/isn't null
- `band` - bitwise AND (for bitmask fields, returns records where field & value != 0)

**URL Encoding:** Bracket characters `[` and `]` must be URL-encoded as `%5B` and `%5D` when using HTTP clients like curl. Most modern HTTP libraries (axios, fetch, etc.) handle this encoding automatically.
 |
| `latest` | query | boolean | No | Return only the latest bulletin for this station (equivalent to limit=1) |





**Response:** `200` - List of station bulletins with pagination metadata



**Error Responses:**

- `404`: Error
- `500`: Error


---

#### Generate news bulletin for a station

`POST /stations/{id}/bulletins`

Generates a news bulletin for a specific station with smart caching and flexible response options.

## HTTP Headers for Control
- `Accept: audio/wav` - Return WAV file directly instead of JSON response
- `Cache-Control: no-cache` - Force new generation ignoring cache
- `Cache-Control: max-age=N` - Reuse existing bulletin if created within N seconds

## Response Headers
- `X-Cache: HIT|MISS` - Indicates if bulletin was served from cache or freshly generated
- `Age: N` - Age of the bulletin in seconds (0 for fresh bulletins)

## Notes
To get story information, use the separate GET /bulletins/{id}/stories endpoint after bulletin generation.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |
| `Accept` | header | string | No | Response format - use 'audio/wav' to download file directly |
| `Cache-Control` | header | string | No | Cache control directives:
- `no-cache` - Force new generation ignoring existing bulletins
- `max-age=N` - Reuse bulletin if created within N seconds
 |



**Request Body:** `application/json`



**Response:** `200` - Bulletin generated successfully or WAV file if download=true



**Error Responses:**

- `400`: Error
- `404`: Station not found or no stories available


---


### Station-Voices

Station-specific voice jingle management


#### Download station-voice jingle file

`GET /station-voices/{id}/audio`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `200` - Jingle audio file



**Error Responses:**

- `404`: Station-voice not found or no jingle file


---

#### Upload station-voice jingle file

`POST /station-voices/{id}/audio`

Upload jingle audio file for a station-voice relationship. Accepts WAV or MP3 format.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |



**Request Body:** `multipart/form-data`



**Response:** `201` - Jingle uploaded successfully



**Error Responses:**

- `400`: Error
- `404`: Error
- `500`: Error


---

#### Delete station-voice relationship

`DELETE /station-voices/{id}`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `204` - Station-voice relationship deleted



**Error Responses:**

- `404`: Error


---

#### Get station-voice relationship by ID

`GET /station-voices/{id}`




**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |





**Response:** `200` - Station-voice relationship details



**Error Responses:**

- `404`: Error


---

#### Update station-voice relationship

`PUT /station-voices/{id}`

Update station-voice relationship properties with JSON body. All fields are optional - only provided fields will be updated.
When updating station_id or voice_id, the system checks for duplicate combinations.
Jingle audio file must be uploaded separately via POST /station-voices/{id}/audio.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Resource ID |



**Request Body:** `application/json`



**Response:** `200` - Station-voice relationship updated



**Error Responses:**

- `400`: Error
- `404`: Error
- `409`: Error
- `422`: Error
- `500`: Error


---

#### List station-voice relationships

`GET /station-voices`

Returns a paginated list of station-voice relationships with modern query parameter support.
Includes station and voice information via database joins.

## Search Fields
Full-text search across:
- `s.name` - Station name
- `v.name` - Voice name

## Filter Fields
Available filter fields:
- `id` - Station-voice relationship ID
- `station_id` - Station ID
- `voice_id` - Voice ID
- `audio_url` - Filter by audio presence (maps to audio_file column)
- `mix_point` - Mix point in seconds
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp

## Audio Filtering
Filter station-voices by jingle audio presence:
- `filter[audio_url]=` - Station-voices WITHOUT jingle audio
- `filter[audio_url][ne]=` - Station-voices WITH jingle audio

## Sort Fields
Available sort fields:
- `id` - Relationship ID (default: descending)
- `station_id` - Station ID
- `voice_id` - Voice ID
- `audio_file` - Audio filename
- `mix_point` - Mix point value
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp
- `station_name` - Station name
- `voice_name` - Voice name

## Examples
- Search by station name: `?search=Radio`
- Filter by station: `?filter[station_id]=1`
- Filter by voice: `?filter[voice_id]=2`
- Sort by station name: `?sort=station_name`
- Field selection: `?fields=id,station_name,voice_name,mix_point`
- Complex query: `?search=Radio&filter[station_id]=1&sort=-created_at&fields=id,station_name,voice_name`



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `limit` | query | integer | No | Maximum number of items to return |
| `offset` | query | integer | No | Number of items to skip |
| `sort` | query | string | No | Sort order. Use field:direction format or prefix notation:
- `name:asc` or `+name` - ascending
- `name:desc` or `-name` - descending
- `created_at:desc,name:asc` - multiple fields
 |
| `fields` | query | string | No | Comma-separated list of fields to include in response.
Use dot notation for nested fields.
 |
| `search` | query | string | No | Search term for full-text search across relevant fields.
Searches in names, titles, text content depending on resource.
 |
| `filter` | query | object | No | Advanced filtering using field-based operators.

Basic usage: `filter[field]=value`

Advanced operators: `filter[field][op]=value`

Supported operators:
- `eq` - equals (default)
- `ne` - not equals
- `gt`, `gte`, `lt`, `lte` - comparisons
- `like` - pattern matching
- `in` - comma-separated values
- `null` - is/isn't null
- `band` - bitwise AND (for bitmask fields, returns records where field & value != 0)

**URL Encoding:** Bracket characters `[` and `]` must be URL-encoded as `%5B` and `%5D` when using HTTP clients like curl. Most modern HTTP libraries (axios, fetch, etc.) handle this encoding automatically.
 |





**Response:** `200` - List of station-voice relationships with pagination metadata



**Error Responses:**

- `500`: Error


---

#### Create a new station-voice relationship

`POST /station-voices`

Create station-voice relationship with JSON body. Jingle audio file must be uploaded separately via POST /station-voices/{id}/audio.





**Request Body:** `application/json`



**Response:** `201` - Station-voice relationship created



**Error Responses:**

- `400`: Error
- `409`: Error
- `422`: Error
- `500`: Error


---


### Automation

Public endpoints for radio automation systems (mAirList, RadioDJ, etc.)


#### Get bulletin audio for radio automation

`GET /public/stations/{id}/bulletin.wav`

Public endpoint for radio automation systems to fetch the latest bulletin audio.

**Authentication**: Requires API key via `key` query parameter.
Configure via `BABBEL_AUTOMATION_KEY` environment variable.

**Behavior**:
- If `max_age > 0`: Returns cached bulletin if younger than max_age, otherwise generates new
- If `max_age = 0`: Always generates a fresh bulletin
- If endpoint is disabled (no API key configured): Returns 404

**Concurrency**: Only one bulletin can be generated per station at a time.
Concurrent requests for the same station will queue.

**Compatible systems**: mAirList, RadioDJ, PlayoutONE, StationPlaylist, and any
system that supports HTTP audio fetching.



**Parameters:**

| Name | In | Type | Required | Description |
|------|-----|------|----------|-------------|
| `id` | path | integer | Yes | Station ID |
| `key` | query | string | Yes | Automation API key (configured via BABBEL_AUTOMATION_KEY) |
| `max_age` | query | integer | Yes | Maximum age of cached bulletin in seconds.
- Use `0` to always generate a fresh bulletin
- Use `3600` for bulletins up to 1 hour old
 |





**Response:** `200` - Bulletin WAV audio file



**Error Responses:**

- `401`: Invalid or missing API key
- `404`: Station not found, endpoint disabled, or no stories available
- `422`: Invalid parameters
- `500`: Bulletin generation failed or timed out


---



## Additional Resources

- [OpenAPI Specification](../openapi.yaml) - Full API specification
- [Authentication Guide](AUTHENTICATION.md) - Detailed authentication setup
- [Docker Setup](DOCKER.md) - Container deployment guide
- [Development Guide](DEVELOPMENT.md) - Local development setup
