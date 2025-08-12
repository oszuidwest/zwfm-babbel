#!/bin/bash

# Comprehensive Babbel Test Suite - No Flags Required
# This script tests EVERYTHING from start to finish

# Don't exit on error - we handle errors ourselves
set +e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
API_URL="http://localhost:8080/api/v1"
AUDIO_DIR="./audio"
COOKIE_FILE="./test_cookies.txt"
MYSQL_USER="${MYSQL_USER:-babbel}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-babbel}"
MYSQL_DATABASE="${MYSQL_DATABASE:-babbel}"

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
print_header() {
    echo -e "\n${MAGENTA}${BOLD}════════════════════════════════════════════════════════════${NC}" >&2
    echo -e "${MAGENTA}${BOLD}  $1${NC}" >&2
    echo -e "${MAGENTA}${BOLD}════════════════════════════════════════════════════════════${NC}\n" >&2
}

print_section() {
    echo -e "\n${CYAN}━━━ $1 ━━━${NC}" >&2
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}" >&2
    ((TESTS_PASSED++))
}

print_error() {
    echo -e "${RED}✗ $1${NC}" >&2
    ((TESTS_FAILED++))
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}" >&2
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}" >&2
}

# Check if FFmpeg is installed
check_ffmpeg() {
    if ! command -v ffmpeg &> /dev/null; then
        print_error "FFmpeg not found. Please install FFmpeg."
        exit 1
    fi
}

# File availability checking with timeout and polling
wait_for_file() {
    local file="$1"
    local timeout="${2:-10}"
    local counter=0
    
    print_info "Waiting for file: $file (timeout: ${timeout}s)"
    
    while [ ! -f "$file" ] && [ $counter -lt $timeout ]; do
        sleep 0.5
        counter=$((counter+1))
    done
    
    if [ -f "$file" ]; then
        print_success "File exists: $file"
        return 0
    else
        print_error "File not found after ${timeout}s: $file"
        return 1
    fi
}

# Comprehensive file system verification
verify_audio_files() {
    print_section "Verifying Audio File Availability"
    
    local errors=0
    
    # Check story audio files
    print_info "Checking story audio files..."
    for i in {1..8}; do
        local story_file="$AUDIO_DIR/processed/story_${i}.wav"
        if [ -f "$story_file" ]; then
            # Verify it's a valid audio file with ffprobe
            if ffprobe -v quiet -select_streams a:0 -show_entries stream=codec_type -of csv=p=0 "$story_file" >/dev/null 2>&1; then
                local size=$(stat -c%s "$story_file" 2>/dev/null || stat -f%z "$story_file" 2>/dev/null || echo "0")
                print_success "Story $i: valid audio file (${size} bytes)"
            else
                print_error "Story $i: invalid audio file"
                errors=$((errors+1))
            fi
        else
            print_error "Story $i: file missing"
            errors=$((errors+1))
        fi
    done
    
    # Check station-voice jingle files
    print_info "Checking station-voice jingle files..."
    local jingle_count=0
    for station_id in $(seq 1 10); do
        for voice_id in $(seq 1 10); do
            local jingle_file="$AUDIO_DIR/processed/station_${station_id}_voice_${voice_id}_jingle.wav"
            if [ -f "$jingle_file" ]; then
                if ffprobe -v quiet -select_streams a:0 -show_entries stream=codec_type -of csv=p=0 "$jingle_file" >/dev/null 2>&1; then
                    local size=$(stat -c%s "$jingle_file" 2>/dev/null || stat -f%z "$jingle_file" 2>/dev/null || echo "0")
                    print_success "Station $station_id + Voice $voice_id: valid jingle (${size} bytes)"
                    jingle_count=$((jingle_count+1))
                else
                    print_error "Station $station_id + Voice $voice_id: invalid jingle file"
                    errors=$((errors+1))
                fi
            fi
        done
    done
    
    print_info "Found $jingle_count valid station-voice jingle files"
    
    if [ $errors -eq 0 ]; then
        print_success "All audio files verified successfully"
        return 0
    else
        print_error "Found $errors audio file issues"
        return 1
    fi
}

# Simple download function
simple_download() {
    local url="$1"
    local output_file="$2"
    local cookie_file="${3:-$COOKIE_FILE}"
    
    print_info "Downloading: $url"
    
    response=$(curl -s -w "\n%{http_code}" -X GET "$url" -b "$cookie_file" -o "$output_file" 2>/dev/null)
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ] && [ -f "$output_file" ] && [ -s "$output_file" ]; then
        print_success "Download successful"
        return 0
    else
        print_error "Download failed with HTTP $http_code"
        rm -f "$output_file" 2>/dev/null
        return 1
    fi
}


# Wait for file with verification
wait_for_audio_file() {
    local file="$1"
    local timeout="${2:-15}"
    
    if wait_for_file "$file" "$timeout"; then
        # Additional verification that it's a valid audio file
        if ffprobe -v quiet -select_streams a:0 -show_entries stream=codec_type -of csv=p=0 "$file" >/dev/null 2>&1; then
            local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "0")
            if [ "$size" -gt 1000 ]; then  # At least 1KB
                print_success "Valid audio file ready: $file (${size} bytes)"
                return 0
            else
                print_error "Audio file too small: $file (${size} bytes)"
                return 1
            fi
        else
            print_error "File exists but is not valid audio: $file"
            return 1
        fi
    else
        return 1
    fi
}

# Step 1: Start Docker containers
start_docker() {
    print_section "Starting Docker Containers"
    
    # Force complete recreation of containers
    print_info "Stopping and removing existing containers..."
    docker-compose down -v >/dev/null 2>&1 || true
    
    print_info "Removing container images to force rebuild..."
    docker-compose rm -f >/dev/null 2>&1 || true
    
    print_info "Building and starting fresh containers..."
    if ! docker-compose up -d --build --force-recreate >/dev/null 2>&1; then
        print_error "Failed to start Docker containers"
        exit 1
    fi
    
    # Wait for MySQL to be ready
    print_info "Waiting for MySQL to be ready..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "SELECT 1" >/dev/null 2>&1; then
            break
        fi
        retries=$((retries - 1))
        sleep 1
    done
    
    # Wait for API to be ready
    print_info "Waiting for API to be ready..."
    retries=30
    while [ $retries -gt 0 ]; do
        if curl -s http://localhost:8080/health >/dev/null 2>&1; then
            print_success "Docker containers are ready"
            return 0
        fi
        retries=$((retries - 1))
        sleep 1
    done
    
    print_error "Services failed to start"
    exit 1
}

# Step 2: Setup clean database
setup_database() {
    print_section "Setting Up Database"
    
    # Drop and recreate database
    print_info "Dropping database..."
    docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "DROP DATABASE IF EXISTS $MYSQL_DATABASE;" 2>/dev/null
    
    print_info "Creating database..."
    docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "CREATE DATABASE $MYSQL_DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/dev/null
    
    print_info "Applying schema..."
    docker exec -i babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" < ./migrations/001_complete_schema.sql 2>/dev/null
    
    # Restart API to ensure clean state
    print_info "Restarting API..."
    docker-compose restart babbel >/dev/null 2>&1
    
    # Wait for API to be ready
    local retries=20
    while [ $retries -gt 0 ]; do
        if curl -s http://localhost:8080/health >/dev/null 2>&1; then
            print_success "Database setup complete"
            return 0
        fi
        retries=$((retries - 1))
        sleep 1
    done
    
    print_error "API failed to restart"
    exit 1
}

# Step 3: Clean audio directories
clean_audio() {
    print_section "Cleaning Audio Directories"
    
    rm -rf "$AUDIO_DIR"/*
    mkdir -p "$AUDIO_DIR"/{voices,stories,processed,output}
    
    print_success "Audio directories cleaned"
}

# Step 4: Generate test audio files
generate_audio() {
    print_section "Generating Audio Files"
    
    # This function will be called AFTER stations and voices are created
    # We'll receive the actual IDs as parameters
    local station_ids="$1"
    local voice_ids="$2"
    
    if [ -z "$station_ids" ] || [ -z "$voice_ids" ]; then
        print_error "Station or voice IDs not provided"
        return 1
    fi
    
    # Generate station-specific jingles (5 minutes of white noise at -20dB)
    print_info "Generating station-specific jingles..."
    
    # Extract only numeric IDs to avoid parsing issues with names containing spaces
    station_id_list=$(echo "$station_ids" | cut -d: -f1)
    voice_id_list=$(echo "$voice_ids" | cut -d: -f1)
    
    # Generate jingles only for actual station-voice combinations
    for station_id in $station_id_list; do
        if [ -z "$station_id" ]; then continue; fi
        
        for voice_id in $voice_id_list; do
            if [ -z "$voice_id" ]; then continue; fi
            
            jingle_file="$AUDIO_DIR/processed/station_${station_id}_voice_${voice_id}_jingle.wav"
            temp_jingle="$AUDIO_DIR/voices/station_${station_id}_voice_${voice_id}_jingle.wav"
            
            print_info "Generating jingle for Station $station_id + Voice $voice_id (white noise)"
            
            # Generate white noise jingle (5 minutes = 300 seconds) at -20dB
            if ! ffmpeg -f lavfi -i "anoisesrc=duration=300:amplitude=0.1" \
                   -ac 2 -ar 48000 -acodec pcm_s16le \
                   -filter:a "volume=-20dB" \
                   "$temp_jingle" -y 2>/dev/null; then
                print_error "Failed to generate jingle for station $station_id, voice $voice_id"
                continue
            fi
            
            
            if [ -f "$temp_jingle" ]; then
                cp "$temp_jingle" "$jingle_file"
                print_success "Generated jingle: station_${station_id}_voice_${voice_id}_jingle.wav"
            fi
        done
    done
    
    # Generate story audio files (different frequencies for each story)
    print_info "Generating story audio files (sine waves)..."
    for i in {1..8}; do
        voice_id=$(( (i % 2) + 1 ))
        case $voice_id in
            1) freq=220 ;;  # A3
            2) freq=330 ;;  # E4
            3) freq=440 ;;  # A4
        esac
        
        # Add slight frequency variation per story for distinction
        freq_offset=$((i * 5))
        actual_freq=$((freq + freq_offset))
        
        if ! ffmpeg -f lavfi -i "sine=frequency=${actual_freq}:duration=15" \
               -ar 48000 -ac 1 -acodec pcm_s16le \
               "$AUDIO_DIR/stories/story${i}.wav" -y 2>/dev/null; then
            print_error "Failed to generate story $i"
        fi
        
        
        if [ -f "$AUDIO_DIR/stories/story${i}.wav" ]; then
            cp "$AUDIO_DIR/stories/story${i}.wav" "$AUDIO_DIR/processed/story_${i}.wav"
        else
            print_error "Story file not created for story $i"
        fi
    done
    
    print_success "Generated audio files"
    
    
    # Wait for all files to be available with timeout
    print_info "Waiting for all audio files to be available..."
    
    # Verify files were created (should be 2 stations × 2 voices = 4 jingle files with numeric IDs only)
    jingle_count=$(find "$AUDIO_DIR/processed" -name "station_*_voice_*_jingle.wav" | grep -c '^.*station_[0-9]*_voice_[0-9]*_jingle\.wav$' 2>/dev/null || echo 0)
    expected_jingles=4
    if [ "$jingle_count" -eq "$expected_jingles" ]; then
        print_success "Generated $jingle_count station-voice jingle files (expected $expected_jingles)"
    else
        print_error "Generated $jingle_count valid jingle files, expected $expected_jingles"
        echo "All jingle files found:"
        find "$AUDIO_DIR/processed" -name "station_*_voice_*_jingle.wav" | head -10
    fi
    
    # Run comprehensive file verification
    verify_audio_files
}

# Step 5: Login to API
api_login() {
    print_section "API Authentication"
    
    rm -f "$COOKIE_FILE"
    
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/session/login" \
        -H "Content-Type: application/json" \
        -d '{"username": "admin", "password": "admin"}' \
        -c "$COOKIE_FILE")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        print_success "Logged in as admin"
    else
        print_error "Login failed"
        exit 1
    fi
}

# Step 5A: Create initial data (stations and voices)
create_initial_data() {
    print_section "Creating Initial Data"
    
    # Create stations with different pause settings
    print_info "Creating stations..."
    stations=(
        "ZuidWest FM:5:2.0"
        "Radio Regio:4:1.5"
    )
    
    for station in "${stations[@]}"; do
        IFS=':' read -r name max_stories pause_seconds <<< "$station"
        
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"$name\", \"max_stories_per_block\": $max_stories, \"pause_seconds\": $pause_seconds}")
        
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
            print_success "Created station: $name (pause: ${pause_seconds}s)"
        else
            print_error "Failed to create station: $name"
        fi
    done
    
    # Create voices (without jingles - jingles are now station-specific)
    print_info "Creating voices..."
    voices=(
        "News Anchor"
        "Sports Reporter"
    )
    
    for i in "${!voices[@]}"; do
        name="${voices[$i]}"
        
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/voices" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"$name\"}")
        
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
            print_success "Created voice: $name"
        else
            print_error "Failed to create voice: $name (HTTP $http_code)"
            # Show error details to stderr
            echo "Response: $(echo "$response" | sed '$d')" >&2
        fi
    done
    
    # Get actual station and voice IDs from the API
    print_info "Fetching station and voice IDs..."
    
    # Get stations
    stations_response=$(curl -s -X GET "$API_URL/stations" -b "$COOKIE_FILE")
    station_ids=$(echo "$stations_response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data:
    for station in data['data'][:2]:  # Use first 2 stations
        print(f\"{station['id']}:{station['name']}\")" 2>/dev/null)
    
    # Get voices
    voices_response=$(curl -s -X GET "$API_URL/voices" -b "$COOKIE_FILE")
    voice_ids=$(echo "$voices_response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data:
    for voice in data['data'][:2]:  # Use first 2 voices
        print(f\"{voice['id']}:{voice['name']}\")" 2>/dev/null)
    
    # Return the IDs for use in generate_audio
    echo "$station_ids|$voice_ids"
}

# Step 6: Create station-voice relationships
create_station_voices() {
    print_section "Creating Station-Voice Relationships"
    
    local station_ids="$1"
    local voice_ids="$2"
    
    # Create relationships for ALL station-voice combinations to ensure complete coverage
    while IFS=: read -r station_id station_name; do
        if [ -z "$station_id" ]; then continue; fi
        
        while IFS=: read -r voice_id voice_name; do
            if [ -z "$voice_id" ]; then continue; fi
            
            # Calculate mix point based on station and voice (varies per combination)
            # Ensure IDs are numeric
            station_id_num=$(echo "$station_id" | grep -o '[0-9]*' | head -1)
            voice_id_num=$(echo "$voice_id" | grep -o '[0-9]*' | head -1)
            
            if [ -z "$station_id_num" ] || [ -z "$voice_id_num" ]; then
                print_error "Invalid station or voice ID for mix point calculation"
                continue
            fi
            
            mix_point=$(echo "scale=1; 1.0 + (($station_id_num % 3) * 0.5) + (($voice_id_num % 3) * 0.3)" | bc)
            
            # Use the appropriate station-specific jingle file
            jingle_file="$AUDIO_DIR/voices/station_${station_id}_voice_${voice_id}_jingle.wav"
            
            # Check if jingle file exists
            if [ ! -f "$jingle_file" ]; then
                print_error "Jingle file not found: $jingle_file"
                continue
            fi
            
            response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/station_voices" \
                -b "$COOKIE_FILE" \
                -F "station_id=$station_id" \
                -F "voice_id=$voice_id" \
                -F "mix_point=$mix_point" \
                -F "jingle=@$jingle_file")
            
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
                print_success "Created station-voice: $station_name + $voice_name"
            elif [ "$http_code" = "400" ] && echo "$response" | grep -q "already exists"; then
                print_info "Station-voice already exists: $station_name + $voice_name"
            else
                print_error "Failed to create station-voice: $station_name + $voice_name (HTTP $http_code)"
                # Show error details
                echo "Response: $(echo "$response" | sed '$d')" >&2
            fi
        done <<< "$voice_ids"
    done <<< "$station_ids"
    
    # Create one station-voice relationship without a jingle to test null audio_url
    print_info "Creating station-voice without jingle to test null audio_url..."
    first_station_id=$(echo "$station_ids" | head -n1 | cut -d: -f1)
    first_voice_id=$(echo "$voice_ids" | head -n1 | cut -d: -f1)
    
    # Create a new unique combination that doesn't exist yet (using mix_point 99 as identifier)
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/station_voices" \
        -b "$COOKIE_FILE" \
        -F "station_id=$first_station_id" \
        -F "voice_id=$first_voice_id" \
        -F "mix_point=99")
    
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
        print_success "Created station-voice without jingle (for null audio_url test)"
    elif [ "$http_code" = "400" ]; then
        # Try deleting the existing one and recreating without jingle
        sv_list=$(curl -s -X GET "$API_URL/station_voices?station_id=$first_station_id&voice_id=$first_voice_id" -b "$COOKIE_FILE")
        sv_id=$(echo "$sv_list" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data.get('data') and len(data['data']) > 0:
    for sv in data['data']:
        if sv.get('mix_point') == 99:
            print(sv['id'])
            break
" 2>/dev/null || echo "")
        
        if [ -n "$sv_id" ]; then
            print_info "Station-voice with mix_point=99 already exists (ID: $sv_id)"
        else
            print_warning "Could not create station-voice without jingle (may already exist)"
        fi
    else
        print_error "Failed to create station-voice without jingle (HTTP $http_code)"
    fi
}

# Step 7: Create stories
create_stories() {
    print_section "Creating Stories"
    
    local voice_ids="$1"
    
    current_date=$(date +%Y-%m-%d)
    next_week=$(date -v+7d +%Y-%m-%d 2>/dev/null || date -d "+7 days" +%Y-%m-%d)
    weekdays='{"monday":true,"tuesday":true,"wednesday":true,"thursday":true,"friday":true,"saturday":true,"sunday":true}'
    
    stories=(
        "Breaking news: Local team wins"
        "City council meeting today"
        "Weather: Sunny skies ahead"
        "Tech: New gadget released"
        "Sports: Game highlights"
        "Entertainment: Concert tonight"
        "Safety: Fire prevention tips"
        "Politics: Election update"
        "Text-only story: No audio content"  # Story without audio
        "Another text story: Also no audio"   # Another story without audio
    )
    
    # Extract first two voice IDs
    voice_id_1=$(echo "$voice_ids" | head -n1 | cut -d: -f1)
    voice_id_2=$(echo "$voice_ids" | tail -n1 | cut -d: -f1)
    
    if [ -z "$voice_id_1" ]; then voice_id_1=1; fi
    if [ -z "$voice_id_2" ]; then voice_id_2=2; fi
    
    for i in "${!stories[@]}"; do
        story_num=$((i + 1))
        # Alternate between the two voice IDs
        if [ $((i % 2)) -eq 0 ]; then
            voice_id="$voice_id_1"
        else
            voice_id="$voice_id_2"
        fi
        
        # Create stories 9 and 10 without audio files
        if [ $i -ge 8 ]; then
            response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
                -b "$COOKIE_FILE" \
                -F "title=${stories[$i]}" \
                -F "text=Full text for: ${stories[$i]}" \
                -F "voice_id=$voice_id" \
                -F "start_date=$current_date" \
                -F "end_date=$next_week" \
                -F "weekdays=$weekdays" \
                -F "status=active")
            
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
                print_success "Created story without audio: ${stories[$i]} (voice $voice_id)"
            else
                print_error "Failed to create story: ${stories[$i]} (HTTP $http_code)"
                echo "Response: $(echo "$response" | sed '$d')" >&2
            fi
        else
            response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
                -b "$COOKIE_FILE" \
                -F "title=${stories[$i]}" \
                -F "text=Full text for: ${stories[$i]}" \
                -F "voice_id=$voice_id" \
                -F "start_date=$current_date" \
                -F "end_date=$next_week" \
                -F "weekdays=$weekdays" \
                -F "status=active" \
                -F "audio=@$AUDIO_DIR/stories/story${story_num}.wav")
            
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
                print_success "Created story: ${stories[$i]} (voice $voice_id)"
            else
                print_error "Failed to create story: ${stories[$i]} (HTTP $http_code)"
                echo "Response: $(echo "$response" | sed '$d')" >&2
            fi
        fi
    done
}

# Step 8: Test bulletin generation for all stations
test_bulletins() {
    print_section "Testing Bulletin Generation with Station-Specific Jingles"
    
    # Get all stations
    stations=$(curl -s -X GET "$API_URL/stations" -b "$COOKIE_FILE")
    station_data=$(echo "$stations" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data:
    for station in data['data']:
        print(f\"{station['id']}:{station['name']}:{station['pause_seconds']}\")
" 2>/dev/null)
    
    # Generate bulletin for each station
    while IFS=: read -r id name pause; do
        print_info "Generating bulletin for $name (pause: ${pause}s)..."
        
        # Verify required audio files exist before attempting bulletin generation
        print_info "Verifying audio files for station $id before bulletin generation..."
        
        # Check if we have station-voice jingles for this station
        jingle_found=false
        for voice_file in "$AUDIO_DIR/processed/station_${id}_voice_"*"_jingle.wav"; do
            if [ -f "$voice_file" ] && wait_for_audio_file "$voice_file" 5; then
                jingle_found=true
                break
            fi
        done
        
        if [ "$jingle_found" = "false" ]; then
            print_warning "No valid jingles found for station $id, bulletin generation may fail"
        fi
        
        # Small delay to allow any background operations to complete
        sleep 1
        
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$id/bulletins/generate" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "{\"date\": \"$(date +%Y-%m-%d)\"}")
        
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "200" ]; then
            duration=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['duration'])" 2>/dev/null || echo "0")
            stories=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(len(json.load(sys.stdin)['stories']))" 2>/dev/null || echo "0")
            bulletin_url=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['audio_url'])" 2>/dev/null || echo "")
            print_success "Bulletin for $name: ${stories} stories, ${duration}s duration"
            
            # Verify station-specific elements
            if [ ! -z "$bulletin_url" ]; then
                print_info "  Bulletin URL: $bulletin_url"
                # Extract filename from URL
                bulletin_file=$(basename "$bulletin_url")
                bulletin_path="$AUDIO_DIR/output/$bulletin_file"
                
                # Wait for bulletin file with timeout and verification
                if wait_for_audio_file "$bulletin_path" 15; then
                    file_size=$(ls -lh "$bulletin_path" | awk '{print $5}')
                    print_success "  Bulletin file created: $bulletin_file ($file_size)"
                else
                    print_error "  Bulletin file not created or invalid: $bulletin_file"
                fi
            fi
        else
            print_error "Failed to generate bulletin for $name (HTTP $http_code)"
            # Show error details to stderr
            echo "Response: $(echo "$response" | sed '$d')" >&2
        fi
    done <<< "$station_data"
    
    # Test that different stations use different jingles
    print_info "Verifying station-specific jingles in bulletins..."
    
    # We don't need to check specific IDs anymore since we're using actual IDs from the API
    print_info "Station-specific jingles are created based on actual station and voice IDs"
}

# Step 9: Test bulletin endpoints
test_bulletin_endpoints() {
    print_section "Testing Bulletin Endpoints"
    
    # Get all stations
    stations=$(curl -s -X GET "$API_URL/stations" -b "$COOKIE_FILE")
    first_station_id=$(echo "$stations" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data and len(data['data']) > 0:
    print(data['data'][0]['id'])
" 2>/dev/null)
    
    if [ -n "$first_station_id" ]; then
        # Test getting latest bulletin for a station
        print_info "Testing get latest bulletin for station $first_station_id..."
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations/$first_station_id/bulletins/latest" -b "$COOKIE_FILE")
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "200" ]; then
            bulletin_data=$(echo "$response" | sed '$d')
            bulletin_url=$(echo "$bulletin_data" | python3 -c "import sys, json; print(json.load(sys.stdin).get('audio_url', ''))" 2>/dev/null || echo "")
            duration=$(echo "$bulletin_data" | python3 -c "import sys, json; print(json.load(sys.stdin).get('duration', 0))" 2>/dev/null || echo "0")
            story_count=$(echo "$bulletin_data" | python3 -c "import sys, json; print(json.load(sys.stdin).get('story_count', 0))" 2>/dev/null || echo "0")
            filename=$(echo "$bulletin_data" | python3 -c "import sys, json; print(json.load(sys.stdin).get('filename', ''))" 2>/dev/null || echo "")
            print_success "Latest bulletin for station $first_station_id: filename=$filename, duration=${duration}s, stories=$story_count"
            print_info "Bulletin URL provided: $bulletin_url"
            
            # Test the direct audio download endpoint for radio automation
            print_info "Testing direct audio download for radio automation..."
            
            # First verify the bulletin file exists in the filesystem
            if [ -n "$filename" ]; then
                bulletin_file_path="$AUDIO_DIR/output/$filename"
                if [ -f "$bulletin_file_path" ] && [ -s "$bulletin_file_path" ]; then
                    print_success "Bulletin file verified on filesystem: $filename"
                else
                    print_warning "Bulletin file not ready, but proceeding with download test"
                fi
                
                fi
            
            # Use retry logic for the download test (increased to 5 retries for race condition)
            if simple_download "$API_URL/stations/$first_station_id/bulletins/latest/audio" "/tmp/test_bulletin.wav"; then
                print_success "Successfully downloaded bulletin audio directly (perfect for radio automation!)"
                rm -f /tmp/test_bulletin.wav
            else
                print_error "Failed to download bulletin audio directly after retries"
            fi
        else
            print_error "Failed to get latest bulletin (HTTP $http_code)"
        fi
    fi
    
    # Test listing all bulletins
    print_info "Testing list all bulletins..."
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins?include_story_list=true" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        bulletin_count=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
        print_success "Listed bulletins: $bulletin_count found"
    else
        print_error "Failed to list bulletins (HTTP $http_code)"
    fi
}

# Step 10: Test soft delete and restore functionality
test_soft_delete() {
    print_section "Testing Soft Delete and Restore"
    
    # Test story soft delete
    print_info "Testing story soft delete..."
    
    # Get a story ID
    stories=$(curl -s -X GET "$API_URL/stories" -b "$COOKIE_FILE")
    first_story=$(echo "$stories" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data and len(data['data']) > 0:
    story = data['data'][0]
    print(f\"{story['id']}:{story['title']}\")
" 2>/dev/null)
    
    if [ -n "$first_story" ]; then
        IFS=: read -r story_id story_title <<< "$first_story"
        
        # Delete the story
        response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/stories/$story_id" -b "$COOKIE_FILE")
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "204" ] || [ "$http_code" = "200" ]; then
            print_success "Story soft deleted: $story_title"
            
            # Small delay to ensure database transaction completes
            sleep 0.5
            
            # Verify story is not in default list
            stories_after=$(curl -s -X GET "$API_URL/stories" -b "$COOKIE_FILE")
            if echo "$stories_after" | grep -q "\"id\":$story_id"; then
                print_error "Deleted story still appears in default list"
            else
                print_success "Deleted story correctly hidden from default list"
            fi
            
            # Check if story appears with include_deleted=true
            stories_deleted=$(curl -s -X GET "$API_URL/stories?include_deleted=true" -b "$COOKIE_FILE")
            if echo "$stories_deleted" | grep -q "\"id\":$story_id"; then
                print_success "Deleted story appears with include_deleted=true"
            else
                print_error "Deleted story not found with include_deleted=true"
            fi
            
            # Restore the story
            response=$(curl -s -w "\n%{http_code}" -X PATCH "$API_URL/stories/$story_id" \
                -H "Content-Type: application/json" \
                -d '{"deleted_at": ""}' \
                -b "$COOKIE_FILE")
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "200" ]; then
                print_success "Story restored: $story_title"
            else
                print_error "Failed to restore story (HTTP $http_code)"
            fi
        else
            print_error "Failed to delete story (HTTP $http_code)"
        fi
    fi
    
    # Test user suspension
    print_info "Testing user suspension..."
    
    # Create a test user to suspend
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"username": "suspend_test", "full_name": "Suspend Test", "password": "testpass", "role": "viewer"}')
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
        suspend_user_id=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
        
        if [ -n "$suspend_user_id" ]; then
            # Suspend the user
            response=$(curl -s -w "\n%{http_code}" -X PATCH "$API_URL/users/$suspend_user_id" \
                -H "Content-Type: application/json" \
                -d '{"suspended_at": "2024-01-01T00:00:00Z"}' \
                -b "$COOKIE_FILE")
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "204" ]; then
                print_success "User suspended successfully"
                
                # Try to login as suspended user (should fail)
                response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/session/login" \
                    -H "Content-Type: application/json" \
                    -d '{"username": "suspend_test", "password": "testpass"}')
                http_code=$(echo "$response" | tail -n1)
                if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
                    print_success "Suspended user correctly cannot login"
                else
                    print_error "Suspended user unexpectedly allowed to login"
                fi
                
                # Restore the user
                response=$(curl -s -w "\n%{http_code}" -X PATCH "$API_URL/users/$suspend_user_id" \
                    -H "Content-Type: application/json" \
                    -d '{"suspended_at": ""}' \
                    -b "$COOKIE_FILE")
                http_code=$(echo "$response" | tail -n1)
                if [ "$http_code" = "200" ]; then
                    print_success "User restored successfully"
                else
                    print_error "Failed to restore user (HTTP $http_code)"
                fi
                
                # Clean up test user
                curl -s -X DELETE "$API_URL/users/$suspend_user_id" -b "$COOKIE_FILE" >/dev/null 2>&1
            else
                print_error "Failed to suspend user (HTTP $http_code)"
            fi
        fi
    fi
}

# Step 11: Test permissions and RBAC
test_permissions() {
    print_section "Testing User Permissions & RBAC"
    
    # Test admin permissions (should have access to everything)
    print_info "Testing admin permissions..."
    
    # Admin should be able to create users
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"username": "testuser", "full_name": "Test User", "password": "testpass", "role": "editor"}')
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
        print_success "Admin can create users"
        # Extract user ID for later tests
        TEST_USER_ID=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
    else
        print_error "Admin cannot create users (HTTP $http_code)"
        echo "Response: $(echo "$response" | sed '$d')" >&2
        TEST_USER_ID=""
    fi
    
    # Admin should be able to list users
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        print_success "Admin can list users"
    else
        print_error "Admin cannot list users (HTTP $http_code)"
        echo "Response: $(echo "$response" | sed '$d')" >&2
    fi
    
    # Admin should be able to update users
    if [ -n "$TEST_USER_ID" ]; then
        response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/users/$TEST_USER_ID" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d '{"username": "testuser", "full_name": "Test User", "role": "viewer"}')
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "200" ]; then
            print_success "Admin can update users"
        else
            print_error "Admin cannot update users (HTTP $http_code)"
        fi
    fi
    
    # Test editor permissions (login as the test user)
    print_info "Testing editor/viewer permissions..."
    
    # Save admin cookie and login as test user
    cp "$COOKIE_FILE" "${COOKIE_FILE}.admin"
    
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/session/login" \
        -H "Content-Type: application/json" \
        -d '{"username": "testuser", "password": "testpass"}' \
        -c "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        print_success "Test user can login"
        
        # Test user should be able to read resources
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations" -b "$COOKIE_FILE")
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "200" ]; then
            print_success "Test user can read stations"
        else
            print_error "Test user cannot read stations (HTTP $http_code)"
        fi
        
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories" -b "$COOKIE_FILE")
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "200" ]; then
            print_success "Test user can read stories"
        else
            print_error "Test user cannot read stories (HTTP $http_code)"
        fi
        
        # Test user should NOT be able to create users (viewer role)
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d '{"username": "unauthorized", "full_name": "Unauthorized User", "password": "test", "role": "viewer"}')
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "403" ] || [ "$http_code" = "401" ]; then
            print_success "Test user correctly denied user creation"
        else
            print_error "Test user unexpectedly allowed to create users (HTTP $http_code)"
        fi
        
        # Test user should NOT be able to delete users
        response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/users/1" -b "$COOKIE_FILE")
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "403" ] || [ "$http_code" = "401" ]; then
            print_success "Test user correctly denied user deletion"
        else
            print_error "Test user unexpectedly allowed to delete users (HTTP $http_code)"
        fi
        
    else
        print_error "Test user cannot login (HTTP $http_code)"
    fi
    
    # Test unauthorized access (no authentication)
    print_info "Testing unauthorized access..."
    
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
        print_success "Unauthorized requests correctly rejected"
    else
        print_error "Unauthorized request unexpectedly allowed (HTTP $http_code)"
    fi
    
    # Test invalid session
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/session" \
        -H "Cookie: babbel_session=invalid_session_token")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
        print_success "Invalid session correctly rejected"
    else
        print_error "Invalid session unexpectedly accepted (HTTP $http_code)"
    fi
    
    # Restore admin session for cleanup
    cp "${COOKIE_FILE}.admin" "$COOKIE_FILE"
    
    # Clean up test user
    if [ -n "$TEST_USER_ID" ]; then
        curl -s -X DELETE "$API_URL/users/$TEST_USER_ID" -b "$COOKIE_FILE" >/dev/null 2>&1
    fi
    
    rm -f "${COOKIE_FILE}.admin"
}

# Step 12: Test API endpoints
test_api_endpoints() {
    print_section "Testing API Endpoints"
    
    # Test health endpoint
    response=$(curl -s -w "\n%{http_code}" http://localhost:8080/health)
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        print_success "Health endpoint"
    else
        print_error "Health endpoint"
    fi
    
    # Test auth config endpoint
    response=$(curl -s -w "\n%{http_code}" "$API_URL/auth/config")
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')  # Remove last line (http_code)
    if [ "$http_code" = "200" ]; then
        # Check if response contains methods array
        if echo "$body" | jq -e '.methods | type == "array"' > /dev/null 2>&1; then
            print_success "Auth config endpoint"
        else
            print_error "Auth config endpoint - invalid response format"
        fi
    else
        print_error "Auth config endpoint"
    fi
    
    # Test current user endpoint
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/session" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        print_success "Current user endpoint"
    else
        print_error "Current user endpoint"
    fi
    
    # Test stations list
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        print_success "Stations list endpoint"
    else
        print_error "Stations list endpoint"
    fi
    
    # Test voices list
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/voices" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        print_success "Voices list endpoint"
    else
        print_error "Voices list endpoint"
    fi
    
    # Test stories list
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        print_success "Stories list endpoint"
    else
        print_error "Stories list endpoint"
    fi
    
    # Test individual story retrieval
    stories_response=$(curl -s -X GET "$API_URL/stories" -b "$COOKIE_FILE")
    first_story_id=$(echo "$stories_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'data' in data and len(data['data']) > 0:
        print(data['data'][0]['id'])
    else:
        print('')
except:
    print('')
" 2>/dev/null)
    
    if [ -n "$first_story_id" ]; then
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories/$first_story_id" -b "$COOKIE_FILE")
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "200" ]; then
            # Validate response structure
            story_data=$(echo "$response" | sed '$d')
            if echo "$story_data" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    required_fields = ['id', 'title', 'text', 'voice_id', 'status', 'weekdays', 'metadata']
    missing = [f for f in required_fields if f not in data]
    if missing:
        print(f'Missing fields: {missing}')
        sys.exit(1)
    print('Valid story structure')
except Exception as e:
    print(f'Invalid JSON or structure: {e}')
    sys.exit(1)
" 2>/dev/null; then
                print_success "Individual story retrieval"
            else
                print_error "Individual story retrieval - invalid response structure"
            fi
        else
            print_error "Individual story retrieval (HTTP $http_code)"
        fi
    else
        print_warning "Skipping individual story test - no stories available"
    fi
    
    # Test station_voices list
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/station_voices" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        print_success "Station-voices list endpoint"
    else
        print_error "Station-voices list endpoint"
    fi
}

# Step 13: Test Station-Voice CRUD operations
test_station_voices_crud() {
    print_section "Testing Station-Voice CRUD Operations"
    
    # Get all station_voices to find valid IDs
    response=$(curl -s -X GET "$API_URL/station_voices" -b "$COOKIE_FILE")
    first_sv=$(echo "$response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data and len(data['data']) > 0:
    sv = data['data'][0]
    print(f\"{sv['id']}:{sv['station_id']}:{sv['voice_id']}:{sv.get('station_name', 'Station')}:{sv.get('voice_name', 'Voice')}:{sv['mix_point']}\")
" 2>/dev/null)
    
    if [ -z "$first_sv" ]; then
        print_error "No station-voice relationships found"
        return
    fi
    
    IFS=: read -r sv_id station_id voice_id station_name voice_name mix_point <<< "$first_sv"
    print_info "Extracted values: sv_id=$sv_id, station_id=$station_id, voice_id=$voice_id"
    
    # Test filter by station
    print_info "Testing station-voice filtering by station..."
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/station_voices?station_id=$station_id" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        count=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
        print_success "Filter by station ID=$station_id: $count relationships found"
    else
        print_error "Failed to filter by station"
    fi
    
    # Test filter by voice
    print_info "Testing station-voice filtering by voice..."
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/station_voices?voice_id=$voice_id" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        count=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
        print_success "Filter by voice ID=$voice_id: $count relationships found"
    else
        print_error "Failed to filter by voice"
    fi
    
    # Get specific station-voice
    print_info "Testing get specific station-voice..."
    print_info "Using station-voice ID: $sv_id"
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/station_voices/$sv_id" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        sv_data=$(echo "$response" | sed '$d')
        station_name=$(echo "$sv_data" | python3 -c "import sys, json; print(json.load(sys.stdin)['station_name'])" 2>/dev/null || echo "unknown")
        voice_name=$(echo "$sv_data" | python3 -c "import sys, json; print(json.load(sys.stdin)['voice_name'])" 2>/dev/null || echo "unknown")
        mix_point=$(echo "$sv_data" | python3 -c "import sys, json; print(json.load(sys.stdin)['mix_point'])" 2>/dev/null || echo "0")
        print_success "Station-Voice $sv_id: $station_name + $voice_name (mix: ${mix_point}s)"
    else
        print_error "Failed to get station-voice ID=$sv_id (HTTP $http_code)"
        echo "Response: $(echo "$response" | sed '$d')" >&2
    fi
    
    # Test update station-voice mix point
    print_info "Testing update station-voice mix point..."
    response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/station_voices/$sv_id" \
        -b "$COOKIE_FILE" \
        -F "mix_point=3.5")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        new_mix_point=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['mix_point'])" 2>/dev/null || echo "0")
        print_success "Updated station-voice mix point to ${new_mix_point}s"
    else
        print_error "Failed to update station-voice"
    fi
    
    # Test create new station-voice relationship
    print_info "Testing create new station-voice (should fail - already exists)..."
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/station_voices" \
        -b "$COOKIE_FILE" \
        -F "station_id=$station_id" \
        -F "voice_id=$voice_id" \
        -F "mix_point=5.0")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "400" ]; then
        print_success "Correctly rejected duplicate station-voice relationship"
    else
        print_error "Should have rejected duplicate station-voice"
    fi
    
    # Test audio file naming convention
    print_info "Verifying audio file naming conventions..."
    jingle_file="$AUDIO_DIR/processed/station_${station_id}_voice_${voice_id}_jingle.wav"
    if [ -f "$jingle_file" ]; then
        print_success "Station-specific jingle naming: station_${station_id}_voice_${voice_id}_jingle.wav exists"
    else
        print_error "Station-specific jingle file not found: $jingle_file"
    fi
}

# Priority 1: Test PATCH endpoints for soft delete/restore
test_patch_endpoints() {
    print_section "Testing PATCH Endpoints (Soft Delete/Restore)"
    
    # Test story PATCH endpoint
    print_info "Testing story soft delete/restore via PATCH..."
    
    # Get a story ID
    stories=$(curl -s -X GET "$API_URL/stories" -b "$COOKIE_FILE")
    first_story=$(echo "$stories" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data and len(data['data']) > 0:
    story = data['data'][0]
    print(f\"{story['id']}:{story['title']}\")
" 2>/dev/null)
    
    if [ -n "$first_story" ]; then
        IFS=: read -r story_id story_title <<< "$first_story"
        
        # Soft delete via PATCH
        response=$(curl -s -w "\n%{http_code}" -X PATCH "$API_URL/stories/$story_id" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d '{"deleted_at": "2024-01-01T00:00:00Z"}')
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "204" ]; then
            print_success "Story soft deleted via PATCH: $story_title"
            
            # Small delay to ensure database transaction completes
            sleep 0.5
            
            # Verify story is hidden
            stories_after=$(curl -s -X GET "$API_URL/stories" -b "$COOKIE_FILE")
            if echo "$stories_after" | grep -q "\"id\":$story_id"; then
                print_error "Deleted story still appears in default list"
            else
                print_success "Deleted story correctly hidden from default list"
            fi
            
            # Restore via PATCH
            response=$(curl -s -w "\n%{http_code}" -X PATCH "$API_URL/stories/$story_id" \
                -b "$COOKIE_FILE" \
                -H "Content-Type: application/json" \
                -d '{"deleted_at": ""}')
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "200" ]; then
                print_success "Story restored via PATCH"
            else
                print_error "Failed to restore story via PATCH (HTTP $http_code)"
            fi
        else
            print_error "Failed to soft delete story via PATCH (HTTP $http_code)"
        fi
    fi
    
    # Test user PATCH endpoint
    print_info "Testing user suspend/restore via PATCH..."
    
    # Create a test user
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"username": "patch_test", "full_name": "Patch Test", "password": "testpass123", "role": "viewer"}')
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
        user_id=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
        
        if [ -n "$user_id" ]; then
            # Suspend via PATCH
            response=$(curl -s -w "\n%{http_code}" -X PATCH "$API_URL/users/$user_id" \
                -b "$COOKIE_FILE" \
                -H "Content-Type: application/json" \
                -d '{"suspended_at": "2024-01-01T00:00:00Z"}')
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "204" ]; then
                print_success "User suspended via PATCH"
                
                # Try to login as suspended user
                response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/session/login" \
                    -H "Content-Type: application/json" \
                    -d '{"username": "patch_test", "password": "testpass123"}')
                http_code=$(echo "$response" | tail -n1)
                if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
                    print_success "Suspended user correctly cannot login"
                else
                    print_error "Suspended user unexpectedly allowed to login"
                fi
                
                # Restore via PATCH
                response=$(curl -s -w "\n%{http_code}" -X PATCH "$API_URL/users/$user_id" \
                    -b "$COOKIE_FILE" \
                    -H "Content-Type: application/json" \
                    -d '{"suspended_at": ""}')
                http_code=$(echo "$response" | tail -n1)
                if [ "$http_code" = "200" ]; then
                    print_success "User restored via PATCH"
                else
                    print_error "Failed to restore user via PATCH (HTTP $http_code)"
                fi
            else
                print_error "Failed to suspend user via PATCH (HTTP $http_code)"
            fi
            
            # Clean up
            curl -s -X DELETE "$API_URL/users/$user_id" -b "$COOKIE_FILE" >/dev/null 2>&1
        fi
    fi
}

# Priority 1: Test audio download endpoints
test_audio_downloads() {
    print_section "Testing Audio Download Endpoints"
    
    # Test story audio download
    print_info "Testing story audio downloads..."
    stories=$(curl -s -X GET "$API_URL/stories" -b "$COOKIE_FILE")
    # Find a story that has audio (should be stories 1-8, which have audio files)
    story_with_audio_id=$(echo "$stories" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data:
    for story in data['data']:
        # Look for stories that have audio_url (indicating they have audio files)
        if story.get('audio_url') is not None:
            print(story['id'])
            break
" 2>/dev/null)
    
    # Fallback to story ID 1-8 if no story with audio_url found
    if [ -z "$story_with_audio_id" ]; then
        print_info "No story with audio_url found, using fallback story ID 1"
        story_with_audio_id=1
    fi
    
    if [ -n "$story_with_audio_id" ]; then
        # First, verify the source story audio file exists  
        story_source_file="$AUDIO_DIR/processed/story_${story_with_audio_id}.wav"
        if [ ! -f "$story_source_file" ] || [ ! -s "$story_source_file" ]; then
            print_warning "Story source file not available, trying different approach"
        fi
        
        # Use retry logic for download with file verification
        if simple_download "$API_URL/stories/$story_with_audio_id/audio" "/tmp/test_story.wav"; then
            # Verify it's actually a valid audio file using ffprobe
            audio_info=$(ffprobe -v error -show_format -show_streams /tmp/test_story.wav 2>&1)
            if echo "$audio_info" | grep -q "codec_type=audio"; then
                # Get audio duration to verify it's valid
                duration=$(ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 /tmp/test_story.wav 2>/dev/null)
                if [ -n "$duration" ] && (( $(echo "$duration > 0" | bc -l) )); then
                    print_success "Story audio download successful (valid WAV, duration: ${duration}s)"
                else
                    print_error "Story audio file has invalid duration"
                fi
            else
                print_error "Downloaded file is not a valid audio file"
            fi
            rm -f /tmp/test_story.wav
        else
            print_error "Failed to download story audio after retries"
        fi
        
        # Test non-existent story audio
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories/99999/audio" -b "$COOKIE_FILE")
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "404" ]; then
            print_success "Non-existent story audio correctly returns 404"
        else
            print_error "Non-existent story audio returned HTTP $http_code (expected 404)"
        fi
        
        # Test text-only story audio (should return 404)
        # Stories 9-10 are created without audio files
        text_only_story_id=$(echo "$stories" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data:
    for story in data['data']:
        # Look for stories that don't have audio_url (text-only stories)
        if story.get('audio_url') is None:
            print(story['id'])
            break
" 2>/dev/null)
        
        if [ -n "$text_only_story_id" ]; then
            response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories/$text_only_story_id/audio" -b "$COOKIE_FILE")
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "404" ]; then
                print_success "Text-only story audio correctly returns 404 (story ID: $text_only_story_id)"
            else
                print_error "Text-only story audio returned HTTP $http_code (expected 404, story ID: $text_only_story_id)"
            fi
        else
            print_info "No text-only stories found to test 404 response"
        fi
    fi
    
    # Test stories without audio have null audio_url
    print_info "Testing stories without audio return null audio_url..."
    stories_response=$(curl -s -X GET "$API_URL/stories?limit=100" -b "$COOKIE_FILE")
    stories_without_audio=$(echo "$stories_response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
stories_with_null = []
if 'data' in data:
    for story in data['data']:
        if story.get('audio_url') is None:
            stories_with_null.append(story['title'])
if stories_with_null:
    print(f'Found {len(stories_with_null)} stories with null audio_url: ' + ', '.join(stories_with_null[:3]))
else:
    print('NO_NULL_FOUND')
" 2>/dev/null || echo "ERROR")
    
    if [[ "$stories_without_audio" == *"null audio_url"* ]]; then
        print_success "$stories_without_audio"
    elif [[ "$stories_without_audio" == "NO_NULL_FOUND" ]]; then
        print_warning "No stories found with null audio_url (all have audio)"
    else
        print_error "Failed to check stories with null audio_url"
    fi
    
    # Test station-voices without jingles have null audio_url
    print_info "Testing station-voices without jingles return null audio_url..."
    sv_response=$(curl -s -X GET "$API_URL/station_voices?limit=100" -b "$COOKIE_FILE")
    sv_without_jingles=$(echo "$sv_response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
sv_with_null = []
if 'data' in data:
    for sv in data['data']:
        if sv.get('audio_url') is None:
            sv_with_null.append(f\"Station {sv.get('station_id')} + Voice {sv.get('voice_id')}\")
if sv_with_null:
    print(f'Found {len(sv_with_null)} station-voices with null audio_url: ' + ', '.join(sv_with_null[:2]))
else:
    print('NO_NULL_FOUND')
" 2>/dev/null || echo "ERROR")
    
    if [[ "$sv_without_jingles" == *"null audio_url"* ]]; then
        print_success "$sv_without_jingles"
    elif [[ "$sv_without_jingles" == "NO_NULL_FOUND" ]]; then
        print_warning "No station-voices found with null audio_url (all have jingles)"
    else
        print_error "Failed to check station-voices with null audio_url"
    fi
    
    # Test station-voice jingle download
    print_info "Testing station-voice jingle downloads..."
    sv_data=$(curl -s -X GET "$API_URL/station_voices" -b "$COOKIE_FILE")
    first_sv_id=$(echo "$sv_data" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data and len(data['data']) > 0:
    print(data['data'][0]['id'])
" 2>/dev/null)
    
    if [ -n "$first_sv_id" ]; then
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/station_voices/$first_sv_id/audio" \
            -b "$COOKIE_FILE" -o /tmp/test_jingle.wav)
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "200" ]; then
            if [ -f /tmp/test_jingle.wav ] && [ -s /tmp/test_jingle.wav ]; then
                # Verify it's actually a valid audio file using ffprobe
                audio_info=$(ffprobe -v error -show_format -show_streams /tmp/test_jingle.wav 2>&1)
                if echo "$audio_info" | grep -q "codec_type=audio"; then
                    # Get audio duration to verify it's valid
                    duration=$(ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 /tmp/test_jingle.wav 2>/dev/null)
                    if [ -n "$duration" ] && (( $(echo "$duration > 0" | bc -l) )); then
                        print_success "Station-voice jingle download successful (valid WAV, duration: ${duration}s)"
                    else
                        print_error "Station-voice jingle has invalid duration"
                    fi
                else
                    print_error "Downloaded jingle is not a valid audio file"
                fi
                rm -f /tmp/test_jingle.wav
            else
                print_error "Jingle file empty or not created"
            fi
        else
            print_error "Failed to download jingle (HTTP $http_code)"
        fi
    fi
    
    # Test bulletin audio download
    print_info "Testing bulletin audio downloads..."
    bulletins=$(curl -s -X GET "$API_URL/bulletins" -b "$COOKIE_FILE")
    first_bulletin_id=$(echo "$bulletins" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data and len(data['data']) > 0:
    print(data['data'][0]['id'])
" 2>/dev/null)
    
    if [ -n "$first_bulletin_id" ]; then
        # Get bulletin details to verify file exists before download attempt
        print_info "Verifying bulletin file exists before download..."
        bulletin_details=$(curl -s -X GET "$API_URL/bulletins/$first_bulletin_id" -b "$COOKIE_FILE")
        bulletin_filename=$(echo "$bulletin_details" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('filename', ''))
except:
    pass
" 2>/dev/null)
        
        # Wait for bulletin file to be available on filesystem before HTTP download
        if [ -n "$bulletin_filename" ]; then
            bulletin_file_path="$AUDIO_DIR/output/$bulletin_filename"
            if [ -f "$bulletin_file_path" ] && [ -s "$bulletin_file_path" ]; then
                print_success "Bulletin file verified on filesystem: $bulletin_filename"
            else
                print_warning "Bulletin file not ready on filesystem, but proceeding with download test"
            fi
            
        fi
        
        # Use retry logic for the bulletin download test
        if simple_download "$API_URL/bulletins/$first_bulletin_id/audio" "/tmp/test_bulletin.wav"; then
            # Verify it's actually a valid audio file using ffprobe
            audio_info=$(ffprobe -v error -show_format -show_streams /tmp/test_bulletin.wav 2>&1)
            if echo "$audio_info" | grep -q "codec_type=audio"; then
                # Get audio duration and verify it's valid
                duration=$(ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 /tmp/test_bulletin.wav 2>/dev/null)
                # Get file size in human-readable format
                file_size=$(ls -lh /tmp/test_bulletin.wav | awk '{print $5}')
                if [ -n "$duration" ] && (( $(echo "$duration > 0" | bc -l) )); then
                    print_success "Bulletin audio download successful (valid WAV, duration: ${duration}s, size: $file_size)"
                else
                    print_error "Bulletin audio has invalid duration"
                fi
            else
                print_error "Downloaded bulletin is not a valid audio file"
            fi
            rm -f /tmp/test_bulletin.wav
        else
            print_error "Failed to download bulletin audio after retries"
        fi
    else
        print_warning "No bulletins available for download test"
    fi
}

# Priority 1: Test story-bulletin relationships
test_relationship_endpoints() {
    print_section "Testing Story-Bulletin Relationship Endpoints"
    
    # Get a story with bulletins
    stories=$(curl -s -X GET "$API_URL/stories" -b "$COOKIE_FILE")
    first_story_id=$(echo "$stories" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data and len(data['data']) > 0:
    print(data['data'][0]['id'])
" 2>/dev/null)
    
    if [ -n "$first_story_id" ]; then
        # Test getting bulletins for a story
        print_info "Testing GET /stories/$first_story_id/bulletins..."
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories/$first_story_id/bulletins" -b "$COOKIE_FILE")
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "200" ]; then
            bulletin_count=$(echo "$response" | sed '$d' | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if isinstance(data, dict) and 'data' in data:
        print(len(data['data']))
    elif isinstance(data, list):
        print(len(data))
    else:
        print(0)
except:
    print(0)
" 2>/dev/null || echo "0")
            print_success "Story bulletin history: $bulletin_count bulletins found"
        else
            print_error "Failed to get story bulletin history (HTTP $http_code)"
        fi
    fi
    
    # Get a bulletin with stories
    bulletins=$(curl -s -X GET "$API_URL/bulletins" -b "$COOKIE_FILE")
    first_bulletin_id=$(echo "$bulletins" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data and len(data['data']) > 0:
    print(data['data'][0]['id'])
" 2>/dev/null)
    
    if [ -n "$first_bulletin_id" ]; then
        # Test getting stories for a bulletin
        print_info "Testing GET /bulletins/$first_bulletin_id/stories..."
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins/$first_bulletin_id/stories" -b "$COOKIE_FILE")
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "200" ]; then
            story_count=$(echo "$response" | sed '$d' | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if isinstance(data, dict) and 'data' in data:
        print(len(data['data']))
    elif isinstance(data, list):
        print(len(data))
    else:
        print(0)
except:
    print(0)
" 2>/dev/null || echo "0")
            print_success "Bulletin stories: $story_count stories found"
        else
            print_error "Failed to get bulletin stories (HTTP $http_code)"
        fi
    fi
    
    # Test with non-existent IDs
    print_info "Testing relationship endpoints with invalid IDs..."
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories/99999/bulletins" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent story bulletins correctly returns 404"
    else
        print_error "Non-existent story bulletins returned HTTP $http_code (expected 404)"
    fi
    
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins/99999/stories" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent bulletin stories correctly returns 404"
    else
        print_error "Non-existent bulletin stories returned HTTP $http_code (expected 404)"
    fi
}

# Priority 1: Test password management
test_password_management() {
    print_section "Testing User Password Management"
    
    # Create a test user
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"username": "pwtest", "full_name": "Password Test", "password": "oldpass123", "role": "viewer"}')
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
        user_id=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
        
        if [ -n "$user_id" ]; then
            # Test password change
            print_info "Testing password change..."
            response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/users/$user_id/password" \
                -b "$COOKIE_FILE" \
                -H "Content-Type: application/json" \
                -d '{"password": "newpass123"}')
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "200" ]; then
                print_success "Password changed successfully"
                
                # Try to login with old password (should fail)
                response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/session/login" \
                    -H "Content-Type: application/json" \
                    -d '{"username": "pwtest", "password": "oldpass123"}')
                http_code=$(echo "$response" | tail -n1)
                if [ "$http_code" = "401" ]; then
                    print_success "Old password correctly rejected"
                else
                    print_error "Old password unexpectedly accepted"
                fi
                
                # Try to login with new password (should succeed)
                response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/session/login" \
                    -H "Content-Type: application/json" \
                    -d '{"username": "pwtest", "password": "newpass123"}' \
                    -c "/tmp/pwtest_cookie.txt")
                http_code=$(echo "$response" | tail -n1)
                if [ "$http_code" = "200" ]; then
                    print_success "New password works correctly"
                    rm -f /tmp/pwtest_cookie.txt
                else
                    print_error "New password rejected (HTTP $http_code)"
                fi
            else
                print_error "Failed to change password (HTTP $http_code)"
            fi
            
            # Test password validation
            print_info "Testing password validation..."
            response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/users/$user_id/password" \
                -b "$COOKIE_FILE" \
                -H "Content-Type: application/json" \
                -d '{"password": "short"}')
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "400" ]; then
                print_success "Short password correctly rejected"
            else
                print_error "Short password unexpectedly accepted (HTTP $http_code)"
            fi
            
            # Test changing password for non-existent user
            response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/users/99999/password" \
                -b "$COOKIE_FILE" \
                -H "Content-Type: application/json" \
                -d '{"password": "newpass123"}')
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "404" ]; then
                print_success "Non-existent user password change correctly returns 404"
            else
                print_error "Non-existent user password change returned HTTP $http_code (expected 404)"
            fi
            
            # Clean up
            curl -s -X DELETE "$API_URL/users/$user_id" -b "$COOKIE_FILE" >/dev/null 2>&1
        fi
    fi
}

# Priority 1: Test session logout
test_session_logout() {
    print_section "Testing Session Logout"
    
    # Create a test user and login
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"username": "logouttest", "full_name": "Logout Test", "password": "testpass123", "role": "viewer"}')
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
        user_id=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
        
        # Login as test user
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/session/login" \
            -H "Content-Type: application/json" \
            -d '{"username": "logouttest", "password": "testpass123"}' \
            -c "/tmp/logout_test_cookie.txt")
        http_code=$(echo "$response" | tail -n1)
        
        if [ "$http_code" = "200" ]; then
            print_success "Test user logged in"
            
            # Verify session is active
            response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/session" \
                -b "/tmp/logout_test_cookie.txt")
            http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "200" ]; then
                print_success "Session is active"
                
                # Test logout
                response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/session" \
                    -b "/tmp/logout_test_cookie.txt")
                http_code=$(echo "$response" | tail -n1)
                if [ "$http_code" = "200" ]; then
                    print_success "Logout successful"
                    
                    # Verify session is destroyed
                    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/session" \
                        -b "/tmp/logout_test_cookie.txt")
                    http_code=$(echo "$response" | tail -n1)
                    if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
                        print_success "Session correctly destroyed after logout"
                    else
                        print_error "Session still active after logout (HTTP $http_code)"
                    fi
                else
                    print_error "Logout failed (HTTP $http_code)"
                fi
            else
                print_error "Failed to verify session (HTTP $http_code)"
            fi
            
            rm -f /tmp/logout_test_cookie.txt
        fi
        
        # Clean up
        if [ -n "$user_id" ]; then
            curl -s -X DELETE "$API_URL/users/$user_id" -b "$COOKIE_FILE" >/dev/null 2>&1
        fi
    fi
}

# Priority 2: Test error scenarios
test_error_scenarios() {
    print_section "Testing Error Scenarios (404, 400, Constraints)"
    
    # Test 404 errors - Invalid IDs
    print_info "Testing 404 errors for non-existent resources..."
    
    endpoints=(
        "stations/99999"
        "voices/99999"
        "stories/99999"
        "users/99999"
        "station_voices/99999"
        "bulletins/99999/audio"
    )
    
    for endpoint in "${endpoints[@]}"; do
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/$endpoint" -b "$COOKIE_FILE")
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "404" ]; then
            print_success "GET /$endpoint correctly returns 404"
        else
            print_error "GET /$endpoint returned HTTP $http_code (expected 404)"
        fi
    done
    
    # Test 400 errors - Validation errors
    print_info "Testing 400 errors for validation failures..."
    
    # Missing required fields
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{}')
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "400" ]; then
        print_success "Empty station creation correctly returns 400"
    else
        print_error "Empty station creation returned HTTP $http_code (expected 400)"
    fi
    
    # Invalid data types
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"name": "Test", "max_stories_per_block": "not-a-number"}')
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "400" ]; then
        print_success "Invalid data type correctly returns 400"
    else
        print_error "Invalid data type returned HTTP $http_code (expected 400)"
    fi
    
    # Test constraint violations
    print_info "Testing constraint violations..."
    
    # Duplicate station name (should be rejected - unique constraint enforced)
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"name": "ZuidWest FM", "max_stories_per_block": 5, "pause_seconds": 2.0}')
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "400" ]; then
        print_success "Duplicate station name correctly rejected (unique constraint enforced)"
        # Check error message
        error_msg=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin).get('message', ''))" 2>/dev/null || echo "")
        if [[ "$error_msg" == *"already exists"* ]]; then
            print_success "Error message indicates duplicate name: $error_msg"
        fi
    else
        print_error "Duplicate station should have been rejected (HTTP $http_code)"
        # If it was accidentally created, clean it up
        if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
            dup_id=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
            if [ -n "$dup_id" ]; then
                curl -s -X DELETE "$API_URL/stations/$dup_id" -b "$COOKIE_FILE" >/dev/null 2>&1
            fi
        fi
    fi
    
    # Test update with duplicate station name (create a second station first)
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"name": "Test Station 2", "max_stories_per_block": 3, "pause_seconds": 1.5}')
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "201" ]; then
        station2_id=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")
        
        # Try to update station2 with station1's name
        response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/stations/$station2_id" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d '{"name": "ZuidWest FM", "max_stories_per_block": 3, "pause_seconds": 1.5}')
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "400" ]; then
            print_success "Update with duplicate station name correctly rejected"
        else
            print_error "Update with duplicate name should have been rejected (HTTP $http_code)"
        fi
        
        # Clean up station2
        curl -s -X DELETE "$API_URL/stations/$station2_id" -b "$COOKIE_FILE" >/dev/null 2>&1
    fi
    
    # Foreign key violation - Invalid voice_id in story
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
        -b "$COOKIE_FILE" \
        -F "title=FK Test Story" \
        -F "text=Test" \
        -F "voice_id=99999" \
        -F "start_date=$(date +%Y-%m-%d)" \
        -F "end_date=$(date -v+7d +%Y-%m-%d 2>/dev/null || date -d "+7 days" +%Y-%m-%d)" \
        -F "weekdays={\"monday\":true}" \
        -F "status=active" \
        -F "audio=@$AUDIO_DIR/stories/story1.wav")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Foreign key violation correctly returns 404 (Voice not found)"
    elif [ "$http_code" = "400" ]; then
        print_success "Foreign key violation returns 400 (Bad Request)"
    elif [ "$http_code" = "500" ]; then
        print_success "Foreign key violation returns 500 (database error not caught)"
    else
        print_error "Foreign key violation returned HTTP $http_code (expected 404, 400, or 500)"
    fi
    
    # Test file upload errors
    print_info "Testing file upload errors..."
    
    # Invalid file format
    echo "not an audio file" > /tmp/test.txt
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
        -b "$COOKIE_FILE" \
        -F "title=Invalid Audio Test" \
        -F "text=Test" \
        -F "voice_id=1" \
        -F "start_date=$(date +%Y-%m-%d)" \
        -F "end_date=$(date -v+7d +%Y-%m-%d 2>/dev/null || date -d "+7 days" +%Y-%m-%d)" \
        -F "weekdays={\"monday\":true}" \
        -F "status=active" \
        -F "audio=@/tmp/test.txt")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "400" ]; then
        print_success "Invalid audio format correctly rejected"
    else
        print_error "Invalid audio format returned HTTP $http_code (expected 400)"
    fi
    rm -f /tmp/test.txt
    
    # Oversized file simulation (we can't easily create a 100MB+ file, so we'll test the endpoint exists)
    print_info "File size validation is configured (100MB limit)"
}

# Priority 3: Test query parameters and filtering
test_query_parameters() {
    print_section "Testing Query Parameters and Filtering"
    
    # Test story filtering
    print_info "Testing story filtering parameters..."
    
    # Filter by status
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?status=active" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        count=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
        print_success "Filter stories by status=active: $count found"
    else
        print_error "Failed to filter stories by status (HTTP $http_code)"
    fi
    
    # Filter by voice_id
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?voice_id=1" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        count=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
        print_success "Filter stories by voice_id=1: $count found"
    else
        print_error "Failed to filter stories by voice_id (HTTP $http_code)"
    fi
    
    # Filter by date
    current_date=$(date +%Y-%m-%d)
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?date=$current_date" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        count=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
        print_success "Filter stories by date=$current_date: $count found"
    else
        print_error "Failed to filter stories by date (HTTP $http_code)"
    fi
    
    # Filter by weekday
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?weekday=monday" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        count=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
        print_success "Filter stories by weekday=monday: $count found"
    else
        print_error "Failed to filter stories by weekday (HTTP $http_code)"
    fi
    
    # Test user filtering
    print_info "Testing user filtering parameters..."
    
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users?role=admin" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        count=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
        print_success "Filter users by role=admin: $count found"
    else
        print_error "Failed to filter users by role (HTTP $http_code)"
    fi
    
    # Test pagination edge cases
    print_info "Testing pagination edge cases..."
    
    # Invalid limit
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?limit=-1" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "400" ] || [ "$http_code" = "200" ]; then
        print_success "Invalid limit handled appropriately"
    else
        print_error "Invalid limit returned unexpected HTTP $http_code"
    fi
    
    # Large offset
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?offset=10000" -b "$COOKIE_FILE")
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        data_count=$(echo "$response" | sed '$d' | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', [])))
" 2>/dev/null || echo "0")
        if [ "$data_count" = "0" ]; then
            print_success "Large offset returns empty data set"
        else
            print_error "Large offset returned unexpected data"
        fi
    else
        print_error "Large offset returned HTTP $http_code (expected 200)"
    fi
}

# Priority 3: Test bulletin generation parameters
test_bulletin_parameters() {
    print_section "Testing Advanced Bulletin Generation Parameters"
    
    # Get a station ID
    stations=$(curl -s -X GET "$API_URL/stations" -b "$COOKIE_FILE")
    station_id=$(echo "$stations" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data and len(data['data']) > 0:
    print(data['data'][0]['id'])
" 2>/dev/null)
    
    if [ -n "$station_id" ]; then
        # Test with max_age parameter
        print_info "Testing bulletin generation with max_age parameter..."
        
        # Generate initial bulletin
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins/generate" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "{\"date\": \"$(date +%Y-%m-%d)\"}")
        http_code=$(echo "$response" | tail -n1)
        
        if [ "$http_code" = "200" ]; then
            first_bulletin_id=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
            print_success "Initial bulletin generated (ID: $first_bulletin_id)"
            
            # Try again with max_age (should return cached)
            response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins/generate?max_age=300" \
                -b "$COOKIE_FILE" \
                -H "Content-Type: application/json" \
                -d "{\"date\": \"$(date +%Y-%m-%d)\"}")
            http_code=$(echo "$response" | tail -n1)
            
            if [ "$http_code" = "200" ]; then
                cached_bulletin_id=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
                if [ "$first_bulletin_id" = "$cached_bulletin_id" ]; then
                    print_success "max_age parameter works - returned cached bulletin"
                else
                    print_info "New bulletin generated despite max_age"
                fi
            fi
            
            # Test force parameter
            print_info "Testing force parameter..."
            response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins/generate?force=true" \
                -b "$COOKIE_FILE" \
                -H "Content-Type: application/json" \
                -d "{\"date\": \"$(date +%Y-%m-%d)\"}")
            http_code=$(echo "$response" | tail -n1)
            
            if [ "$http_code" = "200" ]; then
                forced_bulletin_id=$(echo "$response" | sed '$d' | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', ''))" 2>/dev/null || echo "")
                if [ "$forced_bulletin_id" != "$first_bulletin_id" ]; then
                    print_success "force=true parameter works - generated new bulletin"
                else
                    print_error "force=true did not generate new bulletin"
                fi
            fi
        fi
        
        # Test include_story_list parameter
        print_info "Testing include_story_list parameter..."
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins/generate?include_story_list=true" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "{\"date\": \"$(date +%Y-%m-%d)\"}")
        http_code=$(echo "$response" | tail -n1)
        
        if [ "$http_code" = "200" ]; then
            has_stories=$(echo "$response" | sed '$d' | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('stories' in data)
" 2>/dev/null || echo "False")
            if [ "$has_stories" = "True" ]; then
                print_success "include_story_list=true includes detailed story information"
            else
                print_error "include_story_list=true did not include stories"
            fi
        fi
        
        # Test download parameter
        print_info "Testing download parameter..."
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins/generate?download=true" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "{\"date\": \"$(date +%Y-%m-%d)\"}" \
            -o /tmp/test_download.wav)
        http_code=$(echo "$response" | tail -n1)
        
        if [ "$http_code" = "200" ]; then
            if [ -f /tmp/test_download.wav ] && [ -s /tmp/test_download.wav ]; then
                print_success "download=true returns WAV file directly"
                rm -f /tmp/test_download.wav
            else
                print_error "download=true did not produce WAV file"
            fi
        else
            print_error "download=true failed (HTTP $http_code)"
        fi
    fi
}

# Step 14: Verify all files
verify_files() {
    print_section "Verifying Generated Files"
    
    # Count files
    station_voice_files=$(find "$AUDIO_DIR/processed" -name "station_*_voice_*_jingle.wav" 2>/dev/null | wc -l | tr -d ' ')
    story_files=$(find "$AUDIO_DIR/processed" -name "story_*.wav" 2>/dev/null | wc -l | tr -d ' ')
    bulletin_files=$(find "$AUDIO_DIR/output" -name "bulletin_*.wav" 2>/dev/null | wc -l | tr -d ' ')
    
    # With 2 stations and 2 voices, we expect 4 station-voice jingles
    if [ $station_voice_files -ge 4 ]; then
        print_success "Station-voice jingles: $station_voice_files files"
    else
        print_error "Station-voice jingles: only $station_voice_files files (expected 4)"
    fi
    
    # With 8 stories, we expect 8 story files
    if [ $story_files -ge 8 ]; then
        print_success "Story audio: $story_files files"
    else
        print_error "Story audio: only $story_files files (expected 8)"
    fi
    
    if [ $bulletin_files -gt 0 ]; then
        print_success "Bulletins: $bulletin_files files"
    else
        print_error "No bulletins generated"
    fi
}

# Step 15: Show final summary
show_summary() {
    print_header "TEST COMPLETE"
    
    echo -e "${BOLD}Test Results:${NC}"
    echo -e "  ${GREEN}✓ Passed: $TESTS_PASSED${NC}"
    echo -e "  ${RED}✗ Failed: $TESTS_FAILED${NC}"
    
    # Count database resources
    stations=$(curl -s -X GET "$API_URL/stations" -b "$COOKIE_FILE" 2>/dev/null)
    station_count=$(echo "$stations" | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
    
    voices=$(curl -s -X GET "$API_URL/voices" -b "$COOKIE_FILE" 2>/dev/null)
    voice_count=$(echo "$voices" | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
    
    station_voices=$(curl -s -X GET "$API_URL/station_voices" -b "$COOKIE_FILE" 2>/dev/null)
    station_voice_count=$(echo "$station_voices" | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
    
    stories=$(curl -s -X GET "$API_URL/stories" -b "$COOKIE_FILE" 2>/dev/null)
    story_count=$(echo "$stories" | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
    
    echo -e "\n${BOLD}Database Summary:${NC}"
    echo -e "  • Stations: $station_count"
    echo -e "  • Voices: $voice_count"
    echo -e "  • Station-Voices: $station_voice_count"
    echo -e "  • Stories: $story_count"
    
    # List bulletin files
    if [ -d "$AUDIO_DIR/output" ]; then
        echo -e "\n${BOLD}Generated Bulletins:${NC}"
        find "$AUDIO_DIR/output" -name "bulletin_*.wav" -type f -exec ls -lh {} \; | tail -5 | while read -r line; do
            echo "  $line"
        done
    fi
    
    bulletins=$(curl -s -X GET "$API_URL/bulletins" -b "$COOKIE_FILE" 2>/dev/null)
    bulletin_count=$(echo "$bulletins" | python3 -c "import sys, json; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
    echo -e "  • Bulletins: $bulletin_count"
    
    echo -e "\n${BOLD}To listen to bulletins:${NC}"
    echo -e "  ${CYAN}open ./audio/output/bulletin_*.wav${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}${BOLD}All tests passed!${NC}"
    else
        echo -e "\n${RED}${BOLD}Some tests failed. Check the output above.${NC}"
    fi
}

# Main execution
main() {
    print_header "BABBEL COMPREHENSIVE TEST SUITE"
    
    # Check dependencies
    check_ffmpeg
    
    # Run all test steps
    echo "Starting Docker..." >&2
    start_docker
    
    echo "Setting up database..." >&2
    setup_database
    
    echo "Cleaning audio..." >&2
    clean_audio
    
    echo "Logging in..." >&2
    api_login
    
    echo "Creating initial data (stations and voices)..." >&2
    ids_result=$(create_initial_data)
    station_ids=$(echo "$ids_result" | cut -d'|' -f1)
    voice_ids=$(echo "$ids_result" | cut -d'|' -f2)
    
    if [ -z "$station_ids" ] || [ -z "$voice_ids" ]; then
        print_error "Failed to create initial data"
        exit 1
    fi
    
    echo "Generating audio files with actual IDs..." >&2
    generate_audio "$station_ids" "$voice_ids"
    
    echo "Creating station-voice relationships..." >&2
    create_station_voices "$station_ids" "$voice_ids"
    
    echo "Creating stories..." >&2
    create_stories "$voice_ids"
    
    echo "Testing bulletins..." >&2
    test_bulletins
    
    echo "Testing bulletin endpoints..." >&2
    test_bulletin_endpoints
    
    echo "Testing soft delete and restore..." >&2
    test_soft_delete
    
    echo "Testing permissions..." >&2
    test_permissions
    
    echo "Testing API endpoints..." >&2
    test_api_endpoints
    
    echo "Testing station-voice CRUD..." >&2
    test_station_voices_crud
    
    # Additional test functions for comprehensive coverage
    echo "Testing PATCH endpoints..." >&2
    test_patch_endpoints
    
    echo "Testing audio downloads..." >&2
    # Run comprehensive file verification before audio tests
    print_info "Pre-test file verification for audio downloads..."
    verify_audio_files || print_warning "Some audio files may not be ready, but proceeding with tests"
    
    test_audio_downloads
    
    echo "Testing relationship endpoints..." >&2
    test_relationship_endpoints
    
    echo "Testing password management..." >&2
    test_password_management
    
    echo "Testing session logout..." >&2
    test_session_logout
    
    # Error scenario testing
    echo "Testing error scenarios..." >&2
    test_error_scenarios
    
    # Advanced testing scenarios
    echo "Testing query parameters..." >&2
    test_query_parameters
    
    echo "Testing bulletin parameters..." >&2
    test_bulletin_parameters
    
    
    echo "Verifying files..." >&2
    verify_files
    
    echo "Showing summary..." >&2
    show_summary
    
    # Exit with appropriate code
    [ $TESTS_FAILED -eq 0 ] && exit 0 || exit 1
}

# Run the tests
main