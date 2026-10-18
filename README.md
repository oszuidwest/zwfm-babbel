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
- **Error handling** - Error responses in the RFC 9457 Problem Details format. Every 400 and 422 response lists each rejected value in `errors[]` with `field`, `code` and `message`; see "Validation errors" in `openapi.yaml`
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

- The service runs at startup and then once each day. It deletes the bulletin audio files that are older than the retention period.
- The service always keeps the latest bulletin of each station.
- The service removes the files that have no database record.
- The service removes abandoned audio conversions older than 24 hours directly in `BABBEL_PROCESSED_PATH`: `*.processing` directories, and `*.processing.wav` files left by earlier releases. It never follows symlinks and logs each removal.
- The service removes regular files older than 24 hours from `BABBEL_TEMP_PATH` (upload and TTS inputs). It never follows symlinks or enters directories, and it refuses to sweep a temporary directory that is also the processed or output directory.
- Set the retention period with `BABBEL_BULLETIN_RETENTION` (default: `168h` = 7 days).

## Loudness Normalization

Babbel normalizes audio to [EBU R128](https://tech.ebu.ch/docs/r/r128.pdf) with the FFmpeg `loudnorm` filter:

| Parameter | Value |
|-----------|-------|
| Integrated Loudness | -16 LUFS |
| True Peak | -1 dBTP |
| Loudness Range | 11 LU |

Babbel normalizes:
- Story audio during upload or TTS. Two-pass `loudnorm` measures the mono downmix, then applies linear gain when possible to preserve dynamics while targeting -16 LUFS with a -1 dBTP ceiling. It uses dynamic mode when linear gain would breach that ceiling or its loudness-range constraints. Ungated clips use single-pass `loudnorm` and remain true-peak-limited. An uploaded file that is silent, or below -50 LUFS, is rejected with `422` (`errors[].field` `audio`, `errors[].code` `silent_audio`), and existing audio is kept. Silent TTS output returns `502 tts.upstream_failed`.
- The final bulletin mix, after Babbel adds the jingle. This also runs in two passes, measured on the stereo mix, so the balance between jingle and voice survives normalization.

Babbel does not normalize uploaded jingles. It converts them to stereo 48 kHz 16-bit PCM WAV as-is, so the level balance between intro and bed survives until the bulletin mix.

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
- If the available bulletin is too old or was created on a previous local day, Babbel makes a new bulletin.
- If no key is set, the endpoint is not available and returns 404.

### Authenticated Endpoint

Use this endpoint for systems that have session authentication:
```
GET /api/v1/stations/{station_id}/bulletins/latest
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

Use these environment variables to override the database connection pool defaults:

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

### Asynchronous bulletin generation

`POST /api/v1/stations/{id}/bulletins` returns `202 Accepted` with a `Location` header pointing to `/api/v1/bulletin-jobs/{id}`. Poll that URL until the job status is `succeeded` or `failed`; a successful job carries the created `bulletin_id`. No request body is needed; only an empty body or `{}` is accepted, and any member, including `date`, returns `400` with code `unknown_field`. Every request creates a generation job; each job generates for the local day the worker runs it. A single background worker processes jobs in order; after an unclean restart, interrupted jobs are requeued automatically.

Run exactly one Babbel instance per database. Startup recovery requeues every `running` job, so a second instance would requeue jobs the first instance is still processing.

| Env var | Default | Description |
|---|---|---|
| `BABBEL_BULLETIN_JOBS_GENERATION_TIMEOUT` | `120s` | Maximum duration of one asynchronous bulletin-generation attempt. |

### Text-to-speech

To enable TTS, set an ElevenLabs API key. The credentials stay in environment variables. Babbel always uses the ElevenLabs `eleven_v4` model. The voice options are in the `tts_settings` singleton row. The API gives access to these options.

| Env var | Default | Description |
|---|---|---|
| `BABBEL_ELEVENLABS_API_KEY` | unset | Enables TTS. If not set, `POST /api/v1/stories/{id}/tts` returns 501. |
| `BABBEL_ELEVENLABS_TIMEOUT` | `60s` | The timeout for calls to the ElevenLabs API. |

The initial settings row has stability `0.80`, text normalization `auto`, no seed, and the prefix `[professional][news anchor][engaging]`. Babbel sends only `stability` in `voice_settings`.

Use `GET /api/v1/settings/tts` to see the settings. The admin, editor, and viewer roles can read them. Use `PATCH /api/v1/settings/tts` as an admin to change stability, text normalization, the seed, or `tts_style_prefix`. Babbel puts the prefix before the story text in the ElevenLabs request.

Use `GET` and `PUT /api/v1/settings/tts/pronunciations` to control the local IPA pronunciation rules. Admins and editors can save the rules. Viewers can read them. Babbel keeps the rules in its database. Babbel puts the rules in the text as `/ipa/` spans before the ElevenLabs request.

### HTTP timeouts

The server read timeout is 15s; authenticated audio uploads get 2 minutes to send their body. The write timeout covers the slowest synchronous route plus 2 minutes to stream audio to slow clients: `max(2 x BABBEL_AUTOMATION_TIMEOUT, BABBEL_ELEVENLABS_TIMEOUT) + 2m`, 360s by default. An automation request may wait one generation budget for the station lock (then it returns 504) and spend another generating. Reverse proxies must allow the same durations.

If a bulletin cannot be written completely to the automation client, Babbel logs it and sends a per-station alert. The stories still count as broadcast.

### Logging

Use this environment variable to set the log level:

| Env var | Default | Description |
|---|---|---|
| `BABBEL_LOG_LEVEL` | `4` | The value 5 or higher enables debug logs. Lower values set the info level. |

Babbel writes one access log line for each request. The line does not include the query string. `BABBEL_LOG_LEVEL` does not change the access log.

When Babbel maps a service error to an error response, or a bulletin job fails, the log level depends on the class of the error:

| Class | Level | Examples |
|---|---|---|
| Client error | debug | 404 for an unknown ID, 409 for a duplicate value, a resource that is in use or another state conflict, 410 for a deleted story, 422 for request data or query parameters that are not valid, for a silent audio upload, or for an uploaded file that FFmpeg cannot decode (`undecodable_audio`) |
| Operational signal | warn | 429 `tts.rate_limited` (ElevenLabs quota), 502 or 503 `tts.upstream_failed` (ElevenLabs could not be reached, rejected the credentials or the request, failed, or returned silent audio), `bulletin.no_stories` as a 409 response or as the error code of a failed bulletin job, a 404 for audio whose record exists but whose file is missing on disk |
| Server failure | error | 500 for a database error, an audio processing error, an audio file that Babbel cannot stat on disk or an unhandled error, 503 for a missing migration or seed row, 504 for a timeout, and the other failures of a bulletin job |

A client error is a problem with the request. The response tells the client what to fix, and the access log records the status. At the default level, Babbel does not write these logs. These errors do not cause an alert. For invalid query parameters, the 422 response shows each field that is not valid, and the log line has the route and the field errors.

A client that disconnects before Babbel responds cancels the request, and the database query then fails with `context canceled`. Babbel logs this at debug level, does not send an alert, and does not count it as a database failure. The access log records status 499, the code that nginx uses for a request that the client closed. A canceled context that is not the request context, for example during a server shutdown, is still a server failure. A disconnect after Babbel has published new story audio does not cancel the database update. If that update fails, the new file stays published but the database may not record it; Babbel then sends an alert that asks to publish the story's audio again.

An operational signal is usually not a fault of the client or of Babbel, but it can need action from an administrator. These conditions can also cause alerts, some only after repeated failures, as [Operational e-mail notifications](#operational-e-mail-notifications) describes. A request for story, jingle or bulletin audio whose file is missing on disk logs the resource, the ID and the path at warn level, but does not cause an alert. The log also occurs for a bulletin whose file the cleanup job removed after the retention time. Bulletin generation and the radio automation endpoint send their own alerts for missing files, and log a missing story or bulletin file at error level.

A server failure can cause an alert, for example when database requests fail repeatedly. A story whose audio file is missing on disk logs at error level, even when the bulletin then fails with `bulletin.no_stories`. A log alert on `level=ERROR` does not fire for the client errors in this table. Babbel logs each failed ElevenLabs request once, at the level of the response Babbel returns for it, with the ElevenLabs error code and request ID when ElevenLabs sends them. ElevenLabs error responses, including rejected credentials, log at warn (an unknown voice ID at debug), not at error: without e-mail notifications, alert on `error_type=upstream_failed` and `error_type=rate_limited` as well as on `level=ERROR`. For an ElevenLabs error status, debug logs also show the status and the concurrency headers.

An OIDC login logs at warn level when the user cancels or the identity provider denies the user (`access_denied`), or when Babbel rejects the login, for example for an expired login state, a callback with an empty `error` value or a suspended account. Any other `error` value from the identity provider in a callback with a valid login state, for example `server_error` or `invalid_scope`, points to a problem with the provider or the client configuration and logs at error level, like a failed token exchange. The log line has the provider's `error` and `error_description` values, each cut to 1024 bytes. The message to the user does not include these values.

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
- New story audio is live, but Babbel cannot confirm that its database record was saved. The next successful upload or TTS generation for that story sends the recovery.
- Bulletin generation fails, and the cause is not a timeout.
- Babbel cannot read the bulletin output directory.
- The ElevenLabs credentials are not valid.
- The bulletin cleanup job or the story expiration job fails. These jobs run each day or each hour, too rarely to reach the failure threshold in the default failure window. While the failure continues, each run after the cooldown sends the alert again.
- A scheduler job stops because of a panic.
- Babbel locks a user account after too many bad login attempts.
- The OAuth state or the OAuth token data is not valid.

These conditions cause a thresholded alert:

- ElevenLabs sends error 429 or an upstream error, cannot be reached, or does not reply in time.
- Bulletin generation stops because of a timeout.
- A database request or the database connection fails.
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
POST   /api/v1/stories               # Create story
GET    /api/v1/stories/{id}/audio    # Download story audio
POST   /api/v1/stories/{id}/tts     # Generate audio via ElevenLabs TTS

# Settings
GET    /api/v1/settings/tts          # Inspect global ElevenLabs TTS settings
PATCH  /api/v1/settings/tts          # Update global TTS settings (admin only)
GET    /api/v1/settings/tts/pronunciations # Inspect managed pronunciation rules
PUT    /api/v1/settings/tts/pronunciations # Replace managed pronunciation rules

# Bulletin Generation
POST   /api/v1/stations/{id}/bulletins         # Queue bulletin generation (202 + polling URL)
GET    /api/v1/bulletin-jobs/{id}              # Poll generation job status
GET    /api/v1/stations/{id}/bulletins/latest  # Get latest bulletin
GET    /api/v1/bulletins/{id}/audio            # Download bulletin audio
```

## Development

### Quick Start

```bash
git clone https://github.com/oszuidwest/zwfm-babbel.git
cd zwfm-babbel
docker-compose up -d     # Start services
make db-reset           # Recreate all tables (deletes data)
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
make quality            # Tests and static analysis

# Database
make db-reset           # Recreate all tables (deletes data)
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

- **Backend**: Go 1.27+ with the Gin web framework
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
