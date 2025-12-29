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
openssl rand -hex 32  # Save as MYSQL_ROOT_PASSWORD
openssl rand -hex 32  # Save as MYSQL_PASSWORD
openssl rand -hex 16  # Save as SESSION_SECRET

# Edit .env file
nano .env
```

**Minimal .env configuration:**
```env
# Database
MYSQL_ROOT_PASSWORD=your_generated_64_char_password_here
MYSQL_PASSWORD=your_generated_64_char_password_here

# API
BABBEL_SESSION_SECRET=your_generated_32_char_secret_here
BABBEL_AUTH_METHOD=local
BABBEL_SERVER_PORT=8080

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

## Step 4: First Login

The database includes a default admin user:
- **Username:** `admin`
- **Password:** `admin`

⚠️ **IMPORTANT:** Change this password immediately after first login!

## Step 5: Test the Installation

```bash
# Test API is running
curl http://localhost:8080/api/v1/health
# Should return: {"service":"babbel-api","status":"ok"}

# Login (note: endpoint is /sessions, not /session/login)
curl -c cookies.txt -X POST http://localhost:8080/api/v1/sessions \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
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
```

## Step 7: Upload First Story

```bash
# Create test audio file
ffmpeg -f lavfi -i "sine=frequency=440:duration=5" -ac 1 -ar 48000 test.wav

# Create story with JSON (weekdays is a bitmask: 127 = all days, 62 = Mon-Fri, 65 = Sat+Sun)
curl -b cookies.txt -X POST http://localhost:8080/api/v1/stories \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Test Story",
    "text": "This is my first news story",
    "voice_id": 1,
    "weekdays": 62,
    "start_date": "2025-01-01",
    "end_date": "2025-12-31",
    "status": "active"
  }'

# Upload audio separately (replace 1 with the story ID from previous response)
curl -b cookies.txt -X POST http://localhost:8080/api/v1/stories/1/audio \
  -F "file=@test.wav"
```

## Step 8: Generate Bulletin

```bash
# Generate bulletin for station 1
curl -b cookies.txt -X POST http://localhost:8080/api/v1/stations/1/bulletins \
  -H "Content-Type: application/json" \
  -d '{}'

# Get latest bulletin info
curl -b cookies.txt "http://localhost:8080/api/v1/stations/1/bulletins?latest=true"

# Download bulletin audio directly (replace 1 with actual ID from previous response)
curl -b cookies.txt http://localhost:8080/api/v1/bulletins/1/audio \
  -o bulletin.wav
  
# Play the bulletin (if you have a player installed)
# ffplay bulletin.wav  # or vlc bulletin.wav
```

## You're Done!

Babbel is now running at `http://localhost:8080`

### Next Steps

1. **CHANGE ADMIN PASSWORD** - The default admin/admin is insecure!
2. **Set up backup** - Regular database and audio backups
3. **Configure firewall** - Only allow necessary ports

### How to Change Admin Password

```bash
# Login as admin
curl -c cookies.txt -X POST http://localhost:8080/api/v1/sessions \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Change password (minimum 8 characters)
curl -b cookies.txt -X PUT http://localhost:8080/api/v1/users/1 \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","full_name":"Administrator","password":"YourNewSecurePassword123!"}'
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

# Backup database (use your MYSQL_PASSWORD from .env)
docker exec babbel-mysql sh -c \
  'mysqldump --no-tablespaces -u babbel -p"$MYSQL_PASSWORD" babbel' > backup.sql

# Update Babbel (pull latest image)
docker pull ghcr.io/oszuidwest/zwfm-babbel:latest
docker compose up -d
```

### Troubleshooting

**API not responding?**
- Check logs: `docker compose logs babbel`
- Verify port 8080 is not in use: `netstat -tulpn | grep 8080` (Linux) or `lsof -i :8080` (macOS)
- Ensure Docker is running: `docker ps`
- Check health endpoint: `curl http://localhost:8080/api/v1/health`

**Can't login?**
- Verify you're using the correct endpoint: `/api/v1/sessions` (not `/session/login`)
- Check if cookies are being saved: `cat cookies.txt`
- Verify timezone in .env matches your location
- For OIDC/OAuth issues, check `BABBEL_AUTH_METHOD` and OIDC configuration

**Audio generation fails?**
- Check disk space: `df -h`
- Verify FFmpeg: `docker compose exec babbel ffmpeg -version`
- Ensure stories have audio files uploaded
- Check that stories are scheduled for the current day
- Verify voice assignments are correct

**Database connection issues?**
- Check MySQL is running: `docker compose ps`
- Verify passwords match in .env file
- Run migrations manually if needed:
  ```bash
  docker compose exec mysql mysql -u babbel -p babbel < migrations/001_complete_schema.sql
  ```

**Permission errors?**
- Check user role (admin, editor, viewer)
- Verify session cookie is valid
- Use `GET /api/v1/sessions/current` to check current user

### Using Pre-built Docker Images

The official Docker images are available at GitHub Container Registry:
- Latest: `ghcr.io/oszuidwest/zwfm-babbel:latest`
- Specific version: `ghcr.io/oszuidwest/zwfm-babbel:v0.0.1`

Images are automatically built for:
- New releases (tags)
- Main branch updates

## API Usage Examples

### Working with Stories

```bash
# List active stories for today
curl -b cookies.txt "http://localhost:8080/api/v1/stories?status=active"

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
  -F "file=@station_jingle.wav"
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

### Modern Query Parameters

All list endpoints support advanced filtering and searching:

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
OIDC_PROVIDER_URL=https://login.microsoftonline.com/YOUR-TENANT-ID/v2.0
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URL=https://your-api.com/api/v1/auth/oauth/callback
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

## Development Setup

For local development without Docker:

```bash
# Clone repository
git clone https://github.com/oszuidwest/zwfm-babbel.git
cd zwfm-babbel

# Install Go dependencies
go mod download

# Set up MySQL database
mysql -u root -p < migrations/001_complete_schema.sql

# Configure environment
cp .env.example .env
# Edit .env with your local settings

# Run development server
make run

# Run tests
make test-all
```

## API Documentation

- **OpenAPI Spec**: Available in `openapi.yaml`
- **Full Reference**: See [API_REFERENCE.md](docs/API_REFERENCE.md)
- **Postman Collection**: Import the OpenAPI spec into Postman
- **Authentication**: All endpoints except `/health` and `/auth/config` require authentication

## Security Notes

1. **Always change default passwords** immediately after installation
2. **Use HTTPS in production** - Configure a reverse proxy (nginx, Caddy)
3. **Set strong session secrets** - Use cryptographically secure random values
4. **Configure CORS properly** - Set `BABBEL_ALLOWED_ORIGINS` for your frontend
5. **Regular backups** - Automate database and audio file backups
6. **Monitor logs** - Set up log aggregation for production

For more help, see [GitHub Issues](https://github.com/oszuidwest/zwfm-babbel/issues)
