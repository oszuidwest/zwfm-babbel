# Babbel Quick Start Guide

This guide will help you set up Babbel - a headless REST API for generating audio news bulletins - with basic local authentication in 10 minutes.

## Prerequisites

- Linux server (Ubuntu/Debian recommended) or macOS/Windows with Docker Desktop
- Docker and Docker Compose installed
- 2GB RAM minimum
- 20GB free disk space
- FFmpeg (included in Docker image)

## Step 1: Download Configuration

```bash
# Create directory
sudo mkdir -p /opt/babbel
sudo chown $USER:$USER /opt/babbel
cd /opt/babbel

# Download docker-compose file
wget -O docker-compose.yml \
  https://raw.githubusercontent.com/oszuidwest/zwfm-babbel/main/docker-compose.prod.yml

# Download .env.example
wget https://raw.githubusercontent.com/oszuidwest/zwfm-babbel/main/.env.example

# Download database schema
mkdir migrations
wget -O migrations/001_complete_schema.sql \
  https://raw.githubusercontent.com/oszuidwest/zwfm-babbel/main/migrations/001_complete_schema.sql
cp .env.example .env

# Generate passwords
openssl rand -hex 32  # Save as BABBEL_DB_PASSWORD

# Edit .env file
nano .env
```

**Minimal .env configuration:**
```env
# Database
BABBEL_DB_HOST=mysql
BABBEL_DB_PASSWORD=your_generated_64_char_password_here

# API
BABBEL_ENV=production
BABBEL_AUTH_METHOD=local
BABBEL_ALLOWED_ORIGINS=

# Timezone (adjust to your location)
TZ=Europe/Amsterdam

# Leave other settings as default
```

## Step 2: Configure Environment

Edit the `.env` file with your generated passwords and configuration.

## Step 3: Start Babbel

```bash
# Start services
docker compose up -d

# Check if running
docker compose ps

# View logs
docker compose logs -f
```

## Step 4: Create the First Admin

A new database has no users, so nobody can log in yet. Neither container has a bcrypt tool, so the first command uses the official Apache image to make the hash. With `BABBEL_AUTH_METHOD=oidc`, skip this step and the curl examples in Steps 5 to 8, which use a local login, and follow [OAuth/OIDC Authentication](#oauthoidc-authentication).

```bash
# This insert skips the password check of the API, so choose a strong, unique password
# yourself: at least 8 characters, with an uppercase letter, a lowercase letter and a number.
# Type your password twice. This prints admin:<hash>. Copy the hash, it starts with $2y$.
docker run --rm -it httpd:2.4-alpine htpasswd -nBC 10 admin

# Put the hash in the INSERT, then run this. The quotes around 'SQL' keep the $ signs intact.
# If an OIDC login already took the name admin, the INSERT fails: use another username,
# here and in the login examples below.
docker compose exec -T mysql sh -c 'MYSQL_PWD="$MYSQL_PASSWORD" mysql -u "$MYSQL_USER" "$MYSQL_DATABASE"' <<'SQL'
INSERT INTO users (username, full_name, password_hash, role)
VALUES ('admin', 'Administrator', 'PASTE_THE_HASH_HERE', 'admin');
SQL
```

## Step 5: Test the Installation

```bash
# Test API is running
curl http://localhost:8080/health
# Should return: {"service":"babbel-api","status":"ok"}

# Login (note: endpoint is /sessions, not /session/login). This reads the password
# without showing it. In the JSON, write a " or \ in the password as \" or \\.
printf 'Password: '; IFS= read -rs PASSWORD; echo
printf '{"username":"admin","password":"%s"}' "$PASSWORD" | \
  curl -c cookies.txt -X POST http://localhost:8080/api/v1/sessions \
  -H "Content-Type: application/json" -d @-
unset PASSWORD
```

## Step 6: Create Station and Voice

```bash
# Create your first radio station
curl -b cookies.txt -X POST http://localhost:8080/api/v1/stations \
  -H "Content-Type: application/json" \
  -d '{"name":"My Radio Station","max_stories_per_block":5,"pause_seconds":2.0}'

# Create your first voice
curl -b cookies.txt -X POST http://localhost:8080/api/v1/voices \
  -H "Content-Type: application/json" \
  -d '{"name":"Main Newsreader"}'

# Link the voice to the station. A bulletin only uses stories whose voice is linked
# to the station. A jingle is optional, see Station-Voice Relationships below.
curl -b cookies.txt -X POST http://localhost:8080/api/v1/station-voices \
  -H "Content-Type: application/json" \
  -d '{"station_id":1,"voice_id":1}'
```

## Step 7: Upload First Story

```bash
# Create test audio file
ffmpeg -f lavfi -i "sine=frequency=440:duration=5" -ac 1 -ar 48000 test.wav

# Create story with JSON. A story only plays from start_date to end_date, on the days
# in weekdays. weekdays is a bitmask: 127 = all days, 62 = Mon-Fri, 65 = Sat+Sun.
curl -b cookies.txt -X POST http://localhost:8080/api/v1/stories \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Story",
    "text": "This is my first news story",
    "voice_id": 1,
    "weekdays": 127,
    "is_breaking": false,
    "start_date": "2025-01-01",
    "end_date": "2099-12-31",
    "status": "active"
  }'

# Upload audio separately (replace 1 with the story ID from previous response)
curl -b cookies.txt -X POST http://localhost:8080/api/v1/stories/1/audio \
  -F "audio=@test.wav"
```

## Step 8: Generate Bulletin

```bash
# Queue bulletin generation for station 1 (returns 202 with a job id)
curl -b cookies.txt -X POST http://localhost:8080/api/v1/stations/1/bulletins \
  -H "Content-Type: application/json" \
  -d '{}'

# Poll the job until status is "succeeded" (replace 1 with the job id from the response)
curl -b cookies.txt http://localhost:8080/api/v1/bulletin-jobs/1

# Get latest bulletin info
curl -b cookies.txt "http://localhost:8080/api/v1/stations/1/bulletins/latest"

# Download bulletin audio directly (replace 1 with actual ID from previous response)
curl -b cookies.txt http://localhost:8080/api/v1/bulletins/1/audio \
  -o bulletin.wav
  
# Play the bulletin (if you have a player installed)
# ffplay bulletin.wav  # or vlc bulletin.wav

# Set the test story to draft, so new bulletins leave its tone out
# (replace 1 with the story ID from Step 7). Automation with a max_age can
# still get this test bulletin until you generate a new one.
curl -b cookies.txt -X PATCH http://localhost:8080/api/v1/stories/1 \
  -H "Content-Type: application/json" -d '{"status":"draft"}'
```

## You're Done!

Babbel is now running at `http://localhost:8080`

### Next Steps

1. **Set up backup** - Regular database and audio backups
2. **Configure firewall** - Only allow necessary ports

### How to Change Admin Password

```bash
# Login as admin
printf 'Password: '; IFS= read -rs PASSWORD; echo
printf '{"username":"admin","password":"%s"}' "$PASSWORD" | \
  curl -c cookies.txt -X POST http://localhost:8080/api/v1/sessions \
  -H "Content-Type: application/json" -d @-

# Find the id of the account you logged in with
curl -b cookies.txt http://localhost:8080/api/v1/sessions/current

# Change password (minimum 8 characters), with that id in the URL
printf 'New password: '; IFS= read -rs PASSWORD; echo
printf '{"password":"%s"}' "$PASSWORD" | \
  curl -b cookies.txt -X PUT http://localhost:8080/api/v1/users/YOUR_ID \
  -H "Content-Type: application/json" -d @-
unset PASSWORD
```

### Common Commands

```bash
# Stop Babbel
cd /opt/babbel
docker compose down

# Start Babbel
docker compose up -d

# View logs
docker compose logs -f

# Backup database
docker exec babbel-mysql sh -c \
  'mysqldump --no-tablespaces -u babbel -p"$MYSQL_PASSWORD" babbel' > backup.sql

# Update Babbel (pull latest image)
docker pull ghcr.io/oszuidwest/zwfm-babbel:latest
docker compose up -d
```

A newer MySQL version in the compose file upgrades the database files on its first start. An older version cannot start on them again, so make the backup above first.

### Troubleshooting

**API not responding?**
- Check logs: `docker compose logs babbel`
- Verify port 8080 is not in use: `netstat -tulpn | grep 8080` (Linux) or `lsof -i :8080` (macOS)
- Ensure Docker is running: `docker ps`
- Check health endpoint: `curl http://localhost:8080/health`

**Can't login?**
- A new database has no users until you create the first admin in Step 4
- Verify you're using the correct endpoint: `/api/v1/sessions` (not `/session/login`)
- Check if cookies are being saved: `cat cookies.txt`
- Verify timezone in .env matches your location
- For OIDC/OAuth issues, check `BABBEL_AUTH_METHOD`, `BABBEL_OIDC_*`, and `BABBEL_FRONTEND_URL` configuration

**Audio generation fails?**
- Check disk space: `df -h`
- Verify FFmpeg: `docker compose exec babbel ffmpeg -version`
- Ensure stories have audio files uploaded
- Check that stories are scheduled for the current day, by their dates and their weekdays
- Check that the voice of each story is linked to the station in `/api/v1/station-voices`
- For TTS, verify `BABBEL_ELEVENLABS_API_KEY` is set and the selected voice has an `elevenlabs_voice_id`
- If `GET /api/v1/settings/tts` returns `tts_settings.not_initialized`, restore the singleton row from `migrations/001_complete_schema.sql` or reset with the complete schema

**Database connection issues?**
- Check MySQL is running: `docker compose ps`
- Verify passwords match in .env file
- Run migrations manually if needed. This deletes all data, including users, so create the first admin again as in Step 4:
  ```bash
  docker compose exec mysql mysql -u babbel -p babbel < migrations/001_complete_schema.sql
  ```

**Permission errors?**
- Check user role (admin, editor, viewer)
- Verify session cookie is valid
- Use `GET /api/v1/sessions/current` to check current user

### Using Pre-built Docker Images

The official Docker image is available at GitHub Container Registry:
`ghcr.io/oszuidwest/zwfm-babbel:latest`

Images are built for new releases. Version tags have no `v` prefix, for example `0.17.1`.

## API Usage Examples

### Working with Stories

```bash
# List active stories (default, excludes soft-deleted)
curl -b cookies.txt "http://localhost:8080/api/v1/stories"

# Filter stories by voice
curl -b cookies.txt "http://localhost:8080/api/v1/stories?filter[voice_id]=1"

# Get stories for specific weekday
curl -b cookies.txt "http://localhost:8080/api/v1/stories?filter[monday]=true"

# Search stories
curl -b cookies.txt "http://localhost:8080/api/v1/stories?search=breaking%20news"
```

### Station-Voice Relationships

```bash
# Create station-voice relationship with JSON
curl -b cookies.txt -X POST http://localhost:8080/api/v1/station-voices \
  -H "Content-Type: application/json" \
  -d '{
    "station_id": 1,
    "voice_id": 1,
    "mix_point": 2.5
  }'

# Upload jingle audio separately (replace 1 with the station-voice ID from previous response)
curl -b cookies.txt -X POST http://localhost:8080/api/v1/station-voices/1/audio \
  -F "jingle=@station_jingle.wav"
```

### User Management

```bash
# Create editor user
curl -b cookies.txt -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"username":"editor1","full_name":"News Editor","password":"SecurePass123","role":"editor"}'

# Suspend user (using PATCH method)
curl -b cookies.txt -X PATCH http://localhost:8080/api/v1/users/2 \
  -H "Content-Type: application/json" \
  -d '{"action":"suspend"}'

# Or restore suspended user
curl -b cookies.txt -X PATCH http://localhost:8080/api/v1/users/2 \
  -H "Content-Type: application/json" \
  -d '{"action":"restore"}'
```

## Advanced Features

### Text-to-Speech

Enable TTS by setting an ElevenLabs API key, then restart the app:

```env
BABBEL_ELEVENLABS_API_KEY=your-elevenlabs-api-key
```

Runtime credentials use environment variables. Babbel always sends ElevenLabs `eleven_v4`; voice-generation options live in the `tts_settings` database row and are managed through the API.

```bash
# Inspect current TTS settings (all authenticated roles can read)
curl -b cookies.txt http://localhost:8080/api/v1/settings/tts

# Update global TTS settings (admin only)
curl -b cookies.txt -X PATCH http://localhost:8080/api/v1/settings/tts \
  -H "Content-Type: application/json" \
  -d '{
    "stability": 0.8,
    "apply_text_normalization": "auto",
    "seed": null,
    "tts_style_prefix": "[professional][news anchor][engaging]"
  }'

# Assign an ElevenLabs voice ID to a voice
curl -b cookies.txt -X PUT http://localhost:8080/api/v1/voices/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"Main Newsreader","elevenlabs_voice_id":"your-elevenlabs-voice-id"}'

# Generate story audio with the current global settings
curl -b cookies.txt -X POST http://localhost:8080/api/v1/stories/1/tts

# Overwrite existing story audio
curl -b cookies.txt -X POST "http://localhost:8080/api/v1/stories/1/tts?force=true"
```

Babbel includes only `stability` in `voice_settings`; `tts_style_prefix` is prepended to the story text before synthesis.

Manage local IPA pronunciation rules:

```bash
# Inspect pronunciation rules
curl -b cookies.txt http://localhost:8080/api/v1/settings/tts/pronunciations

# Replace all rules; PUT {"rules": []} clears the local table
curl -b cookies.txt -X PUT http://localhost:8080/api/v1/settings/tts/pronunciations \
  -H "Content-Type: application/json" \
  -d '{
    "rules": [
      {
        "string_to_replace": "Albert Heijn",
        "ipa": "ˈɑlbərt ˈɦɛin",
        "case_sensitive": false,
        "word_boundaries": true
      }
    ]
  }'
```

Pronunciation rules are stored locally; saving them does not call ElevenLabs. During story TTS, Babbel injects inline IPA into the story text before sending the ElevenLabs request.

### Modern Query Parameters

Most resource list endpoints support advanced filtering and searching:

```bash
# Search across fields
curl -b cookies.txt "http://localhost:8080/api/v1/stories?search=breaking"

# Filter with operators
curl -b cookies.txt "http://localhost:8080/api/v1/stories?filter[created_at][gte]=2024-01-01"

# Select specific fields
curl -b cookies.txt "http://localhost:8080/api/v1/stories?fields=id,title,created_at"

# Advanced sorting
curl -b cookies.txt "http://localhost:8080/api/v1/stories?sort=-created_at,title"
```

Available filter operators: `gte`, `lte`, `gt`, `lt`, `ne`, `in`, `between`, `like`

### OAuth/OIDC Authentication

To enable SSO with Microsoft, Google, or other OIDC providers:

1. Set environment variables:
```bash
BABBEL_AUTH_METHOD=oidc  # or "both" for local + OIDC
BABBEL_OIDC_PROVIDER_URL=https://login.microsoftonline.com/YOUR-TENANT-ID/v2.0
BABBEL_OIDC_CLIENT_ID=your-client-id
BABBEL_OIDC_CLIENT_SECRET=your-client-secret
BABBEL_OIDC_REDIRECT_URL=https://your-api.com/api/v1/auth/oauth/callback
BABBEL_FRONTEND_URL=https://your-frontend.com
```

2. Check available auth methods:
```bash
curl http://localhost:8080/api/v1/auth/config
# Returns: {"methods":["oidc"],"oauth_url":"/api/v1/auth/oauth"}
```

3. Start OAuth flow by redirecting users to:
```
http://localhost:8080/api/v1/auth/oauth?frontend_url=https://your-frontend.com
```

4. A first login creates a viewer account. Log in once, find your account in this list, and put its id in the `UPDATE` below. Someone else may have logged in first, so check that the id is yours:
```bash
docker compose exec -T mysql sh -c 'MYSQL_PWD="$MYSQL_PASSWORD" mysql -u "$MYSQL_USER" "$MYSQL_DATABASE"' <<'SQL'
SELECT id, username, full_name, email, role FROM users;
SQL

docker compose exec -T mysql sh -c 'MYSQL_PWD="$MYSQL_PASSWORD" mysql -u "$MYSQL_USER" "$MYSQL_DATABASE"' <<'SQL'
UPDATE users SET role = 'admin' WHERE id = YOUR_ID;
SQL
```

## Development Setup

For local development without Docker:

```bash
# Clone repository
git clone https://github.com/oszuidwest/zwfm-babbel.git
cd zwfm-babbel

# Install Go dependencies
go mod download

# Set up MySQL database, with the admin / admin development login
mysql -u root -p -e "CREATE DATABASE babbel; CREATE USER 'babbel'@'localhost' IDENTIFIED BY 'your_local_db_password'; GRANT ALL ON babbel.* TO 'babbel'@'localhost';"
mysql -u root -p babbel < migrations/001_complete_schema.sql
mysql -u root -p babbel < tests/fixtures/dev-admin.sql

# Configure environment
# The binary does not read .env, so export these values in your shell.
# Without BABBEL_ENV=development the server runs in production mode.
export BABBEL_ENV=development
export BABBEL_DB_PASSWORD=your_local_db_password

# Run development server
make run

# Run tests
make test-all
```

## API Documentation

- **OpenAPI Spec**: Available in `openapi.yaml`
- **Full Reference**: Generate `docs/API_REFERENCE.md` and `docs/index.html` with `make docs`
- **Postman Collection**: Import the OpenAPI spec into Postman
- **Authentication**: `GET /health`, `POST /api/v1/sessions`, `GET /api/v1/auth/config`, and OAuth start/callback endpoints are public; protected API endpoints require a session cookie

## Security Notes

1. **Use HTTPS in production** - Configure a reverse proxy (nginx, Caddy)
2. **Configure CORS properly** - Set `BABBEL_ALLOWED_ORIGINS` for your frontend
3. **Regular backups** - Automate database and audio file backups
4. **Monitor logs** - Set up log aggregation for production

For more help, see [GitHub Issues](https://github.com/oszuidwest/zwfm-babbel/issues)
