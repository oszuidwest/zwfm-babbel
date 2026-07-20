# Babbel

Babbel is a headless REST API that makes audio news bulletins. Babbel mixes news stories with station jingles. The result is an audio file that is ready for broadcast through a radio automation system.

## Overview

Babbel connects to newsroom workflows and radio automation systems. It supplies a REST API that controls bulletin generation for radio stations. Each station can have its own audio branding.

## Features

### Core Functionality
- **RESTful API** - A complete REST API with an OpenAPI 3.1 specification in `openapi.yaml`
- **Multi-station support** - Control of multiple radio stations, each with its own configuration
- **Voice management** - Multiple newsreaders, each with jingles for each station
- **Text-to-speech** - An ElevenLabs connection that makes story audio automatically; the API controls the global settings
- **Story scheduling** - A date range and a weekday schedule for each story
- **Bulletin generation** - Automatic audio mixing with a cache
- **Direct audio URLs** - Radio automation systems can get the bulletins directly

### Technical Features
- **Authentication** - Local accounts with bcrypt, or OIDC/OAuth2 (Microsoft Entra ID, Google, Okta)
- **Authorization** - Role-based access control with Casbin (admin, editor, and viewer roles)
- **Audio processing** - Audio mixing with FFmpeg and configurable mix points
- **Loudness normalization** - Audio levels that agree with EBU R128 s2 (-16 LUFS)
- **Error handling** - Error responses in the RFC 9457 Problem Details format
- **Soft delete** - You can delete stories and users temporarily, and you can restore them
- **Session management** - Sessions in encrypted cookies
- **CORS support** - Configurable cross-origin resource sharing

## Installation

Refer to [QUICKSTART.md](QUICKSTART.md) for the installation instructions.

## Newsroom Workflow

1. **Setup**: Configure the stations, the newsreaders, and the optional ElevenLabs TTS settings.
2. **Upload jingles**: Add the intro and outro jingles for each station.
3. **Create stories**: Upload audio files, or use text-to-speech to make them.
4. **Generate**: The API makes bulletins with the correct jingles.
5. **Broadcast**: The automation systems get the bulletins through HTTP.

## Story Selection

Babbel selects stories with breaking-news priority and fair rotation. Babbel always includes breaking news when slots are open. Babbel fills the other slots with the rotation. The rotation gives each story an equal quantity of airtime.

### How it works

Babbel selects the stories for a bulletin in this sequence:

1. **Breaking news first** - Babbel selects stories with the `is_breaking` flag before all other stories. The newest start date has priority. The usual conditions (date range, weekday schedule, active status, available audio) continue to apply.
2. **Fresh stories next** - Babbel then selects the stories that did not air today. The newest start date has priority.
3. **Least-recently-used fallback** - If all stories aired today, Babbel selects the stories that aired the longest time ago.
4. **Random tiebreaker** - If stories have the same priority, Babbel makes a random selection.

After the selection, Babbel puts the stories in a random sequence. This gives a natural radio flow. The breaking-news priority controls which stories are in the bulletin. It does not control their position in the audio.

### Key characteristics

- **Daily reset** - The rotation starts again at midnight (the local timezone of the server).
- **Per-station isolation** - Each station has its own rotation. The airtime of a story on station A has no effect on its priority for station B.
- **Automatic balance** - Manual work is not necessary. Babbel divides the airtime across all stories that are not breaking news.
- **Breaking stories use slots** - The `max_stories_per_block` limit of a station applies to all stories. If breaking stories fill all slots, Babbel does not include the other stories.

### Example (fair rotation for non-breaking stories)

Scenario: 13 stories that are not breaking news, 4 stories for each bulletin, one bulletin each hour from 07:30 to 18:30 (12 bulletins).

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

All 13 stories air 3 or 4 times in 12 bulletins (48 slots). The `RAND()` function makes different combinations.

## Bulletin File Cleanup

Each bulletin WAV file uses approximately 15 MB. A background service deletes the old files automatically. The database records stay as an audit trail.

- The service operates one time each day. It deletes the bulletin audio files that are older than the retention period.
- The service always keeps the latest bulletin of each station.
- The service removes the files that have no database record.
- Set the retention period with `BABBEL_BULLETIN_RETENTION` (default: `168h` = 7 days).

## Loudness Normalization

Babbel normalizes all audio to [EBU R128](https://tech.ebu.ch/docs/r/r128.pdf) with the FFmpeg `loudnorm` filter:

| Parameter | Value |
|-----------|-------|
| Integrated Loudness | -16 LUFS |
| True Peak | -1 dBTP |
| Loudness Range | 11 LU |

Babbel normalizes:
- The story audio, during the upload or the TTS process. A second pass sets the true peak to -1 dBTP.
- The final bulletin mix, after Babbel adds the jingle.

The target is -16 LUFS, not the usual -23 LUFS. Low audio levels can cause a radio automation system to start a mix point at the incorrect time. The -16 LUFS target prevents this.

## Radio Automation Integration

### Public Endpoint (Recommended)

Use the public endpoint with an API key for automation systems that operate without personnel:

```
GET /public/stations/{id}/bulletin.wav?key=YOUR_API_KEY&max_age=3600
```

**Setup:**
1. Make a safe key: `openssl rand -hex 32`.
2. Set `BABBEL_AUTOMATION_KEY` in the environment.
3. Configure the automation system to get the URL.

**Parameters:**
- `key` - The API key (required).
- `max_age` - The maximum age of the bulletin in seconds. Use `0` for a new bulletin each time. Use `3600` for a bulletin with a maximum age of 1 hour.

**Features:**
- Session or cookie authentication is not necessary.
- If the available bulletin is too old, Babbel makes a new bulletin.
- If no key is set, the endpoint is not available and returns 404.

### Authenticated Endpoint

Use this endpoint for systems that have session authentication:
```
GET /api/v1/stations/{station_id}/bulletins?latest=true
```

### Compatible Systems

- mAirList (HTTP audio source)
- RadioDJ (URL tracks)
- PlayoutONE (Network audio)
- StationPlaylist (Remote files)
- RTV AudioDownload Tool
- Each system that can get audio through HTTP

## Requirements

- Docker and Docker Compose
- 2 GB RAM minimum
- 20 GB disk space
- A Linux server (recommended)

## Configuration

### Database connection pool

Babbel configures the Go SQL connection pool from environment variables. The default values are the same as the values that were in the code before. Set these variables only if the pool must be different.

| Env var | Default | Description |
|---|---:|---|
| `BABBEL_DB_MAX_OPEN_CONNS` | `100` | The maximum number of open database connections. |
| `BABBEL_DB_MAX_IDLE_CONNS` | `10` | The maximum number of idle database connections in the pool. |
| `BABBEL_DB_CONN_MAX_LIFETIME` | `1h` | The maximum lifetime of a database connection that Babbel uses again. |

### Audio tools

Babbel uses FFmpeg for the audio mixing, the loudness normalization, and the audio analysis. You can set the paths of the executables. Do this for custom runtimes, alternative FFmpeg builds, or local development environments with different binary names.

| Env var | Default | Description |
|---|---|---|
| `BABBEL_FFMPEG_PATH` | `ffmpeg` | The FFmpeg executable for the mixing and the loudness normalization. Babbel finds it through PATH at startup. |
| `BABBEL_FFPROBE_PATH` | `ffprobe` | The ffprobe executable for the audio analysis. Babbel finds it through PATH at startup. |

Babbel finds and tests the two executables at startup with `<tool> -version`. If a tool is missing or does not operate correctly, the process stops. The error message shows the related environment variable.

### Text-to-speech

To enable TTS, set an ElevenLabs API key. The credentials stay in environment variables. Babbel always uses the ElevenLabs `eleven_v3` model. The voice options are in the `tts_settings` singleton row. The API gives access to these options.

| Env var | Default | Description |
|---|---|---|
| `BABBEL_ELEVENLABS_API_KEY` | unset | Enables TTS. If not set, `POST /api/v1/stories/{id}/tts` returns 501. |
| `BABBEL_ELEVENLABS_TIMEOUT` | `60s` | The timeout for calls to the ElevenLabs API. |

The initial settings row has stability `0.80`, similarity boost `0.80`, style `0.25`, speed `1.00`, text normalization `auto`, no seed, and the prefix `[professional][news anchor][engaging]`.

Use `GET /api/v1/settings/tts` to see the settings. The admin, editor, and viewer roles can read them. Use `PATCH /api/v1/settings/tts` as an admin to change the voice settings, the text normalization, the seed, or `tts_style_prefix`. Babbel puts the prefix before the story text in the `eleven_v3` request.

Use `GET` and `PUT /api/v1/settings/tts/pronunciations` to control the local IPA pronunciation rules. Admins and editors can save the rules. Viewers can read them. Babbel keeps the rules in its database. Babbel puts the rules in the text as `/ipa/` spans before the ElevenLabs request.

### Operational e-mail notifications

Babbel can send alert e-mails to administrators. Babbel sends the e-mails only through Microsoft Graph. Babbel uses the OAuth2 client-credentials flow. The tool `zwfm-aerontoolbox` uses the same flow.

Do these steps to configure the e-mails:

1. Give the Azure app registration the application permission `Mail.Send`.
2. Give admin consent to this permission.
3. Set the eight environment variables that follow.

| Env var | Default | Description |
|---|---:|---|
| `BABBEL_NOTIFICATIONS_EMAIL_TENANT_ID` | unset | The GUID of the Microsoft Entra tenant. |
| `BABBEL_NOTIFICATIONS_EMAIL_CLIENT_ID` | unset | The GUID of the app registration. |
| `BABBEL_NOTIFICATIONS_EMAIL_CLIENT_SECRET` | unset | The client secret of the app registration. |
| `BABBEL_NOTIFICATIONS_EMAIL_FROM_ADDRESS` | unset | The shared mailbox or user that sends the e-mails. |
| `BABBEL_NOTIFICATIONS_EMAIL_RECIPIENTS` | unset | The addresses of the administrators, with commas between them. |
| `BABBEL_NOTIFICATIONS_COOLDOWN` | `1h` | The minimum time between two alerts for the same active condition and resource. |
| `BABBEL_NOTIFICATIONS_FAILURE_THRESHOLD` | `3` | The number of transient failures that starts an alert. The minimum value is 2. |
| `BABBEL_NOTIFICATIONS_FAILURE_WINDOW` | `10m` | The time in which Babbel counts the transient failures. |

To disable the e-mails, keep the five `BABBEL_NOTIFICATIONS_EMAIL_*` values empty. If the configuration is not complete or not correct, Babbel does not start.

Each condition has one of these three policies:

| Policy | When Babbel sends the alert |
|---|---|
| Immediate | When the condition occurs the first time. |
| Thresholded | When the condition occurs `BABBEL_NOTIFICATIONS_FAILURE_THRESHOLD` times in `BABBEL_NOTIFICATIONS_FAILURE_WINDOW`. |
| Critical | Immediately before the process stops. The cooldown and the threshold do not apply. |

These conditions cause an immediate alert:

- There are no stories for a bulletin.
- The stories in a bulletin do not use the same voice.
- The audio file of a story is missing, or a jingle is missing.
- Bulletin generation fails, and the cause is not a timeout.
- Babbel cannot read the bulletin output directory.
- The ElevenLabs credentials are not valid.
- A scheduler job stops because of a panic.
- Babbel locks a user account after too many bad login attempts.
- The OAuth state or the OAuth token data is not valid.

These conditions cause a thresholded alert:

- ElevenLabs sends error 429 or an upstream error, or does not reply in time.
- Bulletin generation stops because of a timeout.
- A database request or the database connection fails.
- The bulletin cleanup job or the story expiration job fails.
- Babbel cannot parse the FFmpeg loudnorm output.
- Requests to the public bulletin endpoint use a bad automation key.

Babbel groups the alerts by condition and by resource. In the cooldown time, Babbel does not send the same alert again. When the condition stops, Babbel sends a recovery e-mail. The subject of an alert is `[ALERT] <summary> - Babbel`. The subject of a recovery is `[RESOLVED] <summary> - Babbel`.

The `/health` endpoint also does a database check. If the database ping fails, the endpoint returns HTTP 503 with `status: "unhealthy"`. A background monitor does the same database check each minute. This monitor also operates when no load balancer polls the endpoint.

## API Documentation

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
POST   /api/v1/stories/{id}/tts     # Generate audio via ElevenLabs TTS

# Settings
GET    /api/v1/settings/tts          # Inspect global ElevenLabs TTS settings
PATCH  /api/v1/settings/tts          # Update global TTS settings (admin only)
GET    /api/v1/settings/tts/pronunciations # Inspect managed pronunciation rules
PUT    /api/v1/settings/tts/pronunciations # Replace managed pronunciation rules

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
  notify/               # Operational alert e-mails (Microsoft Graph)
  repository/           # Data access layer (GORM)
  scheduler/            # Background tasks
  services/             # Business logic layer
  tts/                  # ElevenLabs text-to-speech integration
  utils/                # Shared utilities
tests/                  # Integration test suite
migrations/             # Database migrations
openapi.yaml           # API specification
```

## Tech Stack

- **Backend**: Go 1.26+ with the Gin web framework
- **Database**: MySQL 8.4 with the GORM ORM
- **Audio**: FFmpeg for the audio mixing and processing
- **Authentication**: Casbin for RBAC, bcrypt for passwords
- **Testing**: Go unit tests and a Jest integration test suite
- **Deployment**: Docker and Docker Compose

## Testing

The project has Go unit tests and a full Jest integration test suite:
- **Test categories**: Authentication, permissions, stations, voices, station-voices, stories, TTS, TTS settings, bulletins, bulletin cleanup, automation, users, validation
- **Test generators**: Schema-driven generators for the CRUD, query, and validation tests
- **Coverage**: All API endpoints, RBAC, file uploads, audio processing, and security

Run the tests with:
```bash
go test ./...           # Run Go unit tests
make test-all           # Run complete integration test suite
npm test -- --verbose   # Run integration tests with detailed output
```

## Contributing

Contributions are welcome. Before you open a pull request:
1. Make sure that all tests pass (`make test-all`).
2. Make sure that the code obeys the Go best practices (`make lint`).
3. Put API changes also in `openapi.yaml`.
4. Update the related documentation.

## License

MIT License - refer to [LICENSE](LICENSE).

## Credits

Streekomroep ZuidWest made Babbel for newsroom operations at multiple local radio stations in the Netherlands.
