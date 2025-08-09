# Babbel Quick Start Guide

This guide will help you set up Babbel with basic local authentication in 10 minutes.

## Prerequisites

- Linux server (Ubuntu/Debian recommended)
- Docker and Docker Compose installed
- 2GB RAM minimum
- 20GB free disk space

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
SESSION_SECRET=your_generated_32_char_secret_here
AUTH_METHOD=local
API_PORT=8080

# Timezone (adjust to your location)
TZ=Europe/Amsterdam

# Leave other settings as default
```

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
curl http://localhost:8080/health
# Should return: {"service":"babbel-api","status":"ok"}

# Login
curl -c cookies.txt -X POST http://localhost:8080/api/v1/session/login \
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

# Upload story (multipart form)
curl -b cookies.txt -X POST http://localhost:8080/api/v1/stories \
  -F "title=Test Story" \
  -F "text=This is my first story" \
  -F "voice_id=1" \
  -F "weekdays[]=monday" \
  -F "weekdays[]=tuesday" \
  -F "weekdays[]=wednesday" \
  -F "weekdays[]=thursday" \
  -F "weekdays[]=friday" \
  -F "start_date=2025-01-01" \
  -F "end_date=2025-12-31" \
  -F "audio=@test.wav"
```

## Step 8: Generate Bulletin

```bash
# Generate bulletin for today
curl -b cookies.txt -X POST http://localhost:8080/api/v1/stations/1/bulletins/generate \
  -H "Content-Type: application/json" \
  -d '{}'

# Download bulletin audio
curl -b cookies.txt http://localhost:8080/api/v1/stations/1/bulletins/latest/audio \
  -o bulletin.wav
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
curl -c cookies.txt -X POST http://localhost:8080/api/v1/session/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Change password (minimum 8 characters)
curl -b cookies.txt -X PUT http://localhost:8080/api/v1/users/1/password \
  -H "Content-Type: application/json" \
  -d '{"password":"YourNewSecurePassword123!"}'
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
- Verify port 8080 is not in use: `netstat -tulpn | grep 8080`

**Can't login?**
- Verify password hash is correct (use bcrypt generator)
- Check timezone in .env matches your location

**Audio generation fails?**
- Check disk space: `df -h`
- Verify FFmpeg: `docker compose exec babbel ffmpeg -version`

### Using Pre-built Docker Images

The official Docker images are available at GitHub Container Registry:
- Latest: `ghcr.io/oszuidwest/zwfm-babbel:latest`
- Specific version: `ghcr.io/oszuidwest/zwfm-babbel:v1.0.0`

Images are automatically built for:
- New releases (tags)
- Main branch updates

For more help, see [GitHub Issues](https://github.com/oszuidwest/zwfm-babbel/issues)
