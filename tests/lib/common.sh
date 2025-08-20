#!/bin/bash

# Babbel Test Library - Common Functions and Utilities
# This file contains shared functions used across all test modules

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
API_BASE="${API_BASE:-http://localhost:8080}"
API_URL="$API_BASE/api/v1"
AUDIO_DIR="./audio"
COOKIE_FILE="./test_cookies.txt"
MYSQL_USER="${MYSQL_USER:-babbel}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-babbel}"
MYSQL_DATABASE="${MYSQL_DATABASE:-babbel}"

# Test counters - these will be used by individual test modules
TESTS_PASSED=0
TESTS_FAILED=0

# Ensure test counters persist across modules
if [ -f "/tmp/babbel_test_counters" ]; then
    source "/tmp/babbel_test_counters"
fi

# Save counters function
save_test_counters() {
    echo "TESTS_PASSED=$TESTS_PASSED" > "/tmp/babbel_test_counters"
    echo "TESTS_FAILED=$TESTS_FAILED" >> "/tmp/babbel_test_counters"
}

# Reset counters function
reset_test_counters() {
    TESTS_PASSED=0
    TESTS_FAILED=0
    rm -f "/tmp/babbel_test_counters"
}

# Print functions
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
    save_test_counters
}

print_error() {
    echo -e "${RED}✗ $1${NC}" >&2
    ((TESTS_FAILED++))
    save_test_counters
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}" >&2
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}" >&2
}

# Test summary function
print_summary() {
    local total=$((TESTS_PASSED + TESTS_FAILED))
    echo -e "\n${BOLD}Test Summary:${NC}" >&2
    echo -e "${GREEN}✓ Passed: $TESTS_PASSED${NC}" >&2
    echo -e "${RED}✗ Failed: $TESTS_FAILED${NC}" >&2
    echo -e "${CYAN}Total: $total${NC}" >&2
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}${BOLD}All tests passed!${NC}" >&2
        return 0
    else
        echo -e "${RED}${BOLD}Some tests failed!${NC}" >&2
        return 1
    fi
}

# Extract error message from RFC 9457 Problem Details response
extract_error_message() {
    local response="$1"
    
    # RFC 9457 Problem Details format only
    local rfc_error=$(echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    # RFC 9457 format: {\"title\": \"...\", \"detail\": \"...\"}
    if 'title' in data:
        title = data.get('title', '')
        detail = data.get('detail', '')
        if detail:
            print(f'{title}: {detail}')
        else:
            print(title)
    else:
        print('')
except:
    print('')
" 2>/dev/null || echo "")
    
    echo "$rfc_error"
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

# Common curl wrapper for API calls
api_call() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    local cookie_file="${4:-$COOKIE_FILE}"
    
    local curl_args=(-s -w "\n%{http_code}" -X "$method" "$API_URL$endpoint" -b "$cookie_file")
    
    if [ "$method" != "GET" ] && [ "$method" != "DELETE" ] && [ -n "$data" ]; then
        curl_args+=(-H "Content-Type: application/json" -d "$data")
    fi
    
    curl "${curl_args[@]}"
}

# JSON parsing helper
parse_json_field() {
    local json="$1"
    local field="$2"
    echo "$json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('$field', ''))
except:
    pass
" 2>/dev/null || echo ""
}

# Start Docker containers
start_docker() {
    print_section "Starting Docker Services (Full Clean Rebuild)"
    
    print_info "Step 1/5: Stopping existing containers..."
    docker-compose down -v --remove-orphans >/dev/null 2>&1
    print_success "✓ Containers stopped and removed"
    
    print_info "Step 2/5: Removing volumes and networks..."
    docker-compose rm -f -s -v >/dev/null 2>&1
    docker volume prune -f >/dev/null 2>&1
    print_success "✓ Volumes and networks cleaned"
    
    print_info "Step 3/5: Removing old images..."
    docker rmi oszw-zwfm-babbel-babbel:latest >/dev/null 2>&1
    docker rmi oszw-zwfm-babbel-mysql:latest >/dev/null 2>&1
    print_success "✓ Old images removed"
    
    print_info "Step 4/5: Building fresh images (this may take a minute)..."
    if docker-compose build --no-cache >/dev/null 2>&1; then
        print_success "✓ Fresh images built successfully"
    else
        print_error "✗ Failed to build images"
        docker-compose logs --tail=50
        return 1
    fi
    
    print_info "Step 5/5: Starting fresh containers..."
    if docker-compose up -d >/dev/null 2>&1; then
        print_success "✓ Docker containers started"
        
        # Wait for services to be ready
        print_info "Waiting for services to be ready..."
        sleep 10
        
        # Check if API is responding
        local retries=0
        while [ $retries -lt 30 ]; do
            if curl -s "$API_BASE/health" >/dev/null 2>&1; then
                print_success "API is responding"
                return 0
            fi
            sleep 2
            ((retries++))
        done
        
        print_error "API failed to start within timeout"
        return 1
    else
        print_error "Failed to start Docker containers"
        return 1
    fi
}

# Clean audio files
clean_audio() {
    print_section "Cleaning Audio Files"
    
    # Create audio directories if they don't exist
    mkdir -p "$AUDIO_DIR"/{processed,output,stories}
    
    # Remove existing generated files
    rm -f "$AUDIO_DIR"/output/*.wav
    rm -f "$AUDIO_DIR"/processed/station_*_voice_*_jingle.wav
    
    print_success "Audio directories cleaned"
}

# Run a test function with error handling
run_test() {
    local test_function="$1"
    local test_name="${2:-$test_function}"
    
    print_info "Running: $test_name"
    
    if "$test_function"; then
        print_success "$test_name completed"
        return 0
    else
        print_error "$test_name failed"
        return 1
    fi
}