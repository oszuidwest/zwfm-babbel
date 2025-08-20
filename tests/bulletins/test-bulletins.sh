#!/bin/bash

# Babbel Bulletins Tests
# Test bulletin generation and management functionality

# Get the script directory and source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/auth.sh"
source "$SCRIPT_DIR/../lib/assertions.sh"

# Global variables for tracking created resources
CREATED_STORY_IDS=()
CREATED_VOICE_IDS=()
CREATED_STATION_IDS=()
CREATED_STATION_VOICE_IDS=()
CREATED_BULLETIN_IDS=()

# Helper function to create a test station
create_test_station() {
    local name="$1"
    local max_stories="${2:-4}"
    local pause_seconds="${3:-2.0}"
    
    # Add timestamp to ensure uniqueness
    local unique_name="${name}_$(date +%s)_$$"
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$unique_name\", \"max_stories_per_block\": $max_stories, \"pause_seconds\": $pause_seconds}")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "201" ]; then
        local station_id=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'id' in data:
        print(data['id'])
except:
    pass
" 2>/dev/null)
        
        if [ -n "$station_id" ]; then
            CREATED_STATION_IDS+=("$station_id")
            echo "$station_id"
            return 0
        fi
    else
        print_error "Station creation failed - HTTP $http_code: $body"
    fi
    
    return 1
}

# Helper function to create a test voice
create_test_voice() {
    local name="$1"
    
    # Add timestamp to ensure uniqueness
    local unique_name="${name}_$(date +%s)_$$"
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/voices" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$unique_name\"}")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "201" ]; then
        local voice_id=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'id' in data:
        print(data['id'])
except:
    pass
" 2>/dev/null)
        
        if [ -n "$voice_id" ]; then
            CREATED_VOICE_IDS+=("$voice_id")
            echo "$voice_id"
            return 0
        fi
    else
        print_error "Voice creation failed - HTTP $http_code: $body"
    fi
    
    return 1
}

# Helper function to create station-voice relationship with jingle
create_station_voice_with_jingle() {
    local station_id="$1"
    local voice_id="$2"
    local mix_point="${3:-3.0}"
    
    # Create a simple test jingle audio file
    local jingle_file="/tmp/test_jingle_${station_id}_${voice_id}.wav"
    if command -v ffmpeg &> /dev/null; then
        ffmpeg -f lavfi -i "sine=frequency=440:duration=5" -ar 44100 -ac 2 -f wav "$jingle_file" -y 2>/dev/null
        if [ ! -f "$jingle_file" ]; then
            print_warning "Could not create test jingle file"
            return 1
        fi
    else
        print_warning "ffmpeg not available, cannot create jingle"
        return 1
    fi
    
    # Upload the station-voice relationship with jingle
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/station-voices" \
        -b "$COOKIE_FILE" \
        -F "station_id=$station_id" \
        -F "voice_id=$voice_id" \
        -F "mix_point=$mix_point" \
        -F "jingle=@$jingle_file")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    # Clean up temp file
    rm -f "$jingle_file"
    
    if [ "$http_code" = "201" ]; then
        local sv_id=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'id' in data:
        print(data['id'])
except:
    pass
" 2>/dev/null)
        
        if [ -n "$sv_id" ]; then
            CREATED_STATION_VOICE_IDS+=("$sv_id")
            echo "$sv_id"
            return 0
        fi
    else
        print_error "Station-voice creation failed - HTTP $http_code: $body"
    fi
    
    return 1
}

# Helper function to create a test story with audio
create_test_story_with_audio() {
    local title="$1"
    local text="$2"
    local voice_id="$3"
    local weekdays="${4:-monday,tuesday,wednesday,thursday,friday}"
    
    # Create a simple test audio file
    local audio_file="/tmp/test_story_audio_$(date +%s).wav"
    if command -v ffmpeg &> /dev/null; then
        ffmpeg -f lavfi -i "sine=frequency=220:duration=3" -ar 44100 -ac 2 -f wav "$audio_file" -y 2>/dev/null
        if [ ! -f "$audio_file" ]; then
            print_warning "Could not create test audio file"
            return 1
        fi
    else
        print_warning "ffmpeg not available, cannot create test audio"
        return 1
    fi
    
    # Set weekday flags
    local monday="false" tuesday="false" wednesday="false" thursday="false" friday="false" saturday="false" sunday="false"
    IFS=',' read -ra DAYS <<< "$weekdays"
    for day in "${DAYS[@]}"; do
        case "$day" in
            monday) monday="true" ;;
            tuesday) tuesday="true" ;;
            wednesday) wednesday="true" ;;
            thursday) thursday="true" ;;
            friday) friday="true" ;;
            saturday) saturday="true" ;;
            sunday) sunday="true" ;;
        esac
    done
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
        -b "$COOKIE_FILE" \
        -F "title=$title" \
        -F "text=$text" \
        -F "voice_id=$voice_id" \
        -F "status=active" \
        -F "start_date=2025-01-01" \
        -F "end_date=2025-12-31" \
        -F "monday=$monday" \
        -F "tuesday=$tuesday" \
        -F "wednesday=$wednesday" \
        -F "thursday=$thursday" \
        -F "friday=$friday" \
        -F "saturday=$saturday" \
        -F "sunday=$sunday" \
        -F "audio=@$audio_file")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    # Clean up temp file
    rm -f "$audio_file"
    
    if [ "$http_code" = "201" ]; then
        local story_id=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'id' in data:
        print(data['id'])
except:
    pass
" 2>/dev/null)
        
        if [ -n "$story_id" ]; then
            CREATED_STORY_IDS+=("$story_id")
            echo "$story_id"
            return 0
        fi
    else
        print_error "Story creation failed - HTTP $http_code: $body"
    fi
    
    return 1
}

# Test bulletin generation for a station
test_bulletin_generation() {
    print_section "Testing Bulletin Generation"
    
    # Setup test data
    print_info "Setting up test data for bulletin generation..."
    
    # Create a test station
    local station_id=$(create_test_station "Bulletin Test Station" 3 2.0)
    if [ -z "$station_id" ]; then
        print_error "Failed to create test station"
        return 1
    fi
    print_success "Created test station (ID: $station_id)"
    
    # Create test voices
    local voice1_id=$(create_test_voice "Bulletin Voice 1")
    local voice2_id=$(create_test_voice "Bulletin Voice 2")
    if [ -z "$voice1_id" ] || [ -z "$voice2_id" ]; then
        print_error "Failed to create test voices"
        return 1
    fi
    print_success "Created test voices (IDs: $voice1_id, $voice2_id)"
    
    # Create station-voice relationships with jingles
    local sv1_id=$(create_station_voice_with_jingle "$station_id" "$voice1_id" 3.0)
    local sv2_id=$(create_station_voice_with_jingle "$station_id" "$voice2_id" 2.5)
    if [ -z "$sv1_id" ] || [ -z "$sv2_id" ]; then
        print_error "Failed to create station-voice relationships"
        return 1
    fi
    print_success "Created station-voice relationships with jingles"
    
    # Create test stories with audio
    local story1_id=$(create_test_story_with_audio "Breaking News Bulletin Test" "This is a test breaking news story for bulletin generation." "$voice1_id" "monday,tuesday,wednesday,thursday,friday")
    local story2_id=$(create_test_story_with_audio "Weather Update Bulletin Test" "Test weather forecast for bulletin generation." "$voice2_id" "monday,tuesday,wednesday,thursday,friday")
    local story3_id=$(create_test_story_with_audio "Traffic Report Bulletin Test" "Traffic update for bulletin generation testing." "$voice1_id" "monday,wednesday,friday")
    
    if [ -z "$story1_id" ] || [ -z "$story2_id" ] || [ -z "$story3_id" ]; then
        print_error "Failed to create test stories"
        return 1
    fi
    print_success "Created test stories with audio files"
    
    # Wait for audio files to be processed
    print_info "Waiting for audio files to be processed..."
    sleep 3
    
    # Test basic bulletin generation
    print_info "Testing basic bulletin generation..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{}")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
        print_success "Bulletin generated successfully"
        
        # Extract bulletin details
        local bulletin_id=$(parse_json_field "$body" "id")
        local audio_url=$(parse_json_field "$body" "audio_url")
        local duration=$(parse_json_field "$body" "duration")
        local story_count=$(parse_json_field "$body" "story_count")
        local filename=$(parse_json_field "$body" "filename")
        local cached=$(parse_json_field "$body" "cached")
        
        if [ -n "$bulletin_id" ]; then
            CREATED_BULLETIN_IDS+=("$bulletin_id")
        fi
        
        print_info "Bulletin details: ID=$bulletin_id, Duration=${duration}s, Stories=$story_count, Cached=$cached"
        print_info "Audio URL: $audio_url"
        print_info "Filename: $filename"
        
        # Verify required fields are present
        if [ -n "$audio_url" ] && [ -n "$duration" ] && [ -n "$story_count" ] && [ -n "$filename" ]; then
            print_success "Bulletin response contains all required fields"
        else
            print_error "Bulletin response missing required fields"
            return 1
        fi
        
        # Verify the bulletin cached flag is false for new generation
        if [ "$cached" = "false" ]; then
            print_success "New bulletin correctly marked as not cached"
        else
            print_warning "New bulletin marked as cached: $cached"
        fi
        
    else
        print_error "Bulletin generation failed - HTTP $http_code: $body"
        return 1
    fi
    
    # Test bulletin generation with specific date
    print_info "Testing bulletin generation with specific date..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"date\": \"$(date +%Y-%m-%d)\"}")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "200" ]; then
        print_success "Bulletin generation with date works"
    else
        print_error "Bulletin generation with date failed - HTTP $http_code"
        return 1
    fi
    
    # Test bulletin generation with story list inclusion
    print_info "Testing bulletin generation with story list inclusion..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins?include_story_list=true" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{}")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
        # Check if stories are included in response
        local has_stories=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'stories' in data and isinstance(data['stories'], list) and len(data['stories']) > 0:
        print('true')
    else:
        print('false')
except:
    print('false')
" 2>/dev/null)
        
        if [ "$has_stories" = "true" ]; then
            print_success "Bulletin generation with story list inclusion works"
        else
            print_warning "Story list not included in bulletin response"
        fi
    else
        print_error "Bulletin generation with story list failed - HTTP $http_code"
        return 1
    fi
    
    return 0
}

# Test bulletin retrieval and details
test_bulletin_retrieval() {
    print_section "Testing Bulletin Retrieval"
    
    # Test listing all bulletins
    print_info "Testing bulletin listing..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "List bulletins" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        
        # Check for data array and pagination
        local has_data=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'data' in data and isinstance(data['data'], list):
        print('true')
    else:
        print('false')
except:
    print('false')
" 2>/dev/null)
        
        if [ "$has_data" = "true" ]; then
            local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data['data']))
" 2>/dev/null)
            print_success "Bulletin listing returned $count bulletins"
        else
            print_error "Bulletin listing response missing data array"
            return 1
        fi
    else
        return 1
    fi
    
    # Test bulletin pagination
    print_info "Testing bulletin pagination..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins?limit=2&offset=0" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "List bulletins with pagination" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', [])))
" 2>/dev/null)
        
        if [ "$count" -le "2" ]; then
            print_success "Pagination limit respected (returned $count bulletins)"
        else
            print_error "Pagination limit not respected (returned $count bulletins)"
            return 1
        fi
    else
        return 1
    fi
    
    # Test bulletin filtering by station
    if [ ${#CREATED_STATION_IDS[@]} -gt 0 ]; then
        local station_id="${CREATED_STATION_IDS[0]}"
        print_info "Testing bulletin filtering by station..."
        local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins?station_id=$station_id" -b "$COOKIE_FILE")
        
        if check_response "$response" "200" "Filter bulletins by station" >/dev/null; then
            print_success "Bulletin filtering by station works"
        else
            return 1
        fi
    fi
    
    # Test bulletin search
    print_info "Testing bulletin search..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins?search=bulletin" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Search bulletins" >/dev/null; then
        print_success "Bulletin search works"
    else
        return 1
    fi
    
    # Test bulletin sorting
    print_info "Testing bulletin sorting..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins?sort=-created_at" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Sort bulletins" >/dev/null; then
        print_success "Bulletin sorting works"
    else
        return 1
    fi
    
    return 0
}

# Test bulletin audio download
test_bulletin_audio_download() {
    print_section "Testing Bulletin Audio Download"
    
    # Get a bulletin to test audio download
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins?limit=1" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Get bulletins for audio test" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local bulletin_id=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'data' in data and len(data['data']) > 0:
        print(data['data'][0]['id'])
except:
    pass
" 2>/dev/null)
        
        if [ -n "$bulletin_id" ]; then
            print_info "Testing bulletin audio download for ID: $bulletin_id"
            
            # Test audio download
            local download_path="/tmp/test_bulletin_download.wav"
            local download_response=$(curl -s -o "$download_path" -w "%{http_code}" "$API_URL/bulletins/$bulletin_id/audio" -b "$COOKIE_FILE")
            
            if [ "$download_response" = "200" ]; then
                if [ -f "$download_path" ] && [ -s "$download_path" ]; then
                    # Verify it's a valid audio file
                    if command -v file &> /dev/null; then
                        local file_type=$(file "$download_path" 2>/dev/null)
                        if echo "$file_type" | grep -q "WAVE audio\|RIFF"; then
                            print_success "Bulletin audio downloaded successfully and is valid WAV file"
                        else
                            print_warning "Downloaded file may not be valid audio: $file_type"
                        fi
                    else
                        print_success "Bulletin audio downloaded successfully"
                    fi
                    
                    # Check file size
                    local file_size=$(stat -f%z "$download_path" 2>/dev/null || stat -c%s "$download_path" 2>/dev/null || echo "0")
                    if [ "$file_size" -gt 1000 ]; then
                        print_info "Downloaded audio size: $file_size bytes"
                    else
                        print_warning "Downloaded file seems too small: $file_size bytes"
                    fi
                    
                    rm -f "$download_path"
                else
                    print_error "Download failed - file not created or empty"
                    return 1
                fi
            else
                print_error "Audio download failed (HTTP: $download_response)"
                return 1
            fi
            
            # Test audio download with direct download flag
            print_info "Testing bulletin generation with direct download..."
            if [ ${#CREATED_STATION_IDS[@]} -gt 0 ]; then
                local station_id="${CREATED_STATION_IDS[0]}"
                local download_response=$(curl -s -o "$download_path" -w "%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins?download=true" \
                    -b "$COOKIE_FILE" \
                    -H "Content-Type: application/json" \
                    -d "{}")
                
                if [ "$download_response" = "200" ]; then
                    if [ -f "$download_path" ] && [ -s "$download_path" ]; then
                        print_success "Direct bulletin download works"
                        rm -f "$download_path"
                    else
                        print_error "Direct download failed - no file created"
                        return 1
                    fi
                else
                    print_error "Direct bulletin download failed (HTTP: $download_response)"
                    return 1
                fi
            fi
            
        else
            print_warning "No bulletin ID found for audio download test"
        fi
    else
        return 1
    fi
    
    # Test authentication requirement for audio download
    print_info "Testing audio download requires authentication..."
    if [ -n "$bulletin_id" ]; then
        local unauth_response=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/bulletins/$bulletin_id/audio")
        
        if [ "$unauth_response" = "401" ]; then
            print_success "Audio endpoint correctly requires authentication"
        else
            print_warning "Audio endpoint returned unexpected status without auth: $unauth_response"
        fi
    fi
    
    return 0
}

# Test station-specific bulletin endpoints
test_station_bulletin_endpoints() {
    print_section "Testing Station-Specific Bulletin Endpoints"
    
    if [ ${#CREATED_STATION_IDS[@]} -eq 0 ]; then
        print_warning "No test stations available for station bulletin tests"
        return 0
    fi
    
    local station_id="${CREATED_STATION_IDS[0]}"
    
    # Test getting bulletins for a station
    print_info "Testing station bulletins listing..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations/$station_id/bulletins" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Get station bulletins" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        
        # Check if response contains bulletins
        local has_data=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    # Could be paginated response with 'data' array or direct array
    if 'data' in data:
        print('paginated')
    elif isinstance(data, list):
        print('direct')
    elif 'id' in data:
        print('single')
    else:
        print('unknown')
except:
    print('error')
" 2>/dev/null)
        
        print_success "Station bulletins endpoint works (format: $has_data)"
    else
        return 1
    fi
    
    # Test getting latest bulletin for a station
    print_info "Testing latest bulletin for station..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations/$station_id/bulletins?latest=true" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Get latest station bulletin" >/dev/null; then
        print_success "Latest station bulletin endpoint works"
    else
        return 1
    fi
    
    # Test station bulletins with pagination
    print_info "Testing station bulletins pagination..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations/$station_id/bulletins?limit=1&offset=0" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Get paginated station bulletins" >/dev/null; then
        print_success "Station bulletins pagination works"
    else
        return 1
    fi
    
    # Test station bulletins with story inclusion
    print_info "Testing station bulletins with stories..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations/$station_id/bulletins?include_stories=true" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Get station bulletins with stories" >/dev/null; then
        print_success "Station bulletins with stories works"
    else
        return 1
    fi
    
    return 0
}

# Test bulletin history and relationships
test_bulletin_history() {
    print_section "Testing Bulletin History and Relationships"
    
    # Test story-bulletin relationship
    if [ ${#CREATED_STORY_IDS[@]} -gt 0 ]; then
        local story_id="${CREATED_STORY_IDS[0]}"
        
        print_info "Testing story bulletin history..."
        local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories/$story_id/bulletins" -b "$COOKIE_FILE")
        
        if check_response "$response" "200" "Get story bulletin history" >/dev/null; then
            local body=$(echo "$response" | sed '$d')
            
            # Check response structure
            local has_bulletins=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'bulletins' in data:
        print('object_with_bulletins')
    elif 'data' in data:
        print('paginated')
    elif isinstance(data, list):
        print('direct_array')
    else:
        print('unknown')
except:
    print('error')
" 2>/dev/null)
            
            print_success "Story bulletin history works (format: $has_bulletins)"
        else
            return 1
        fi
    fi
    
    # Test bulletin-story relationship
    if [ ${#CREATED_BULLETIN_IDS[@]} -gt 0 ]; then
        local bulletin_id="${CREATED_BULLETIN_IDS[0]}"
        
        print_info "Testing bulletin stories listing..."
        local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins/$bulletin_id/stories" -b "$COOKIE_FILE")
        
        if check_response "$response" "200" "Get bulletin stories" >/dev/null; then
            local body=$(echo "$response" | sed '$d')
            
            # Check for data array
            local has_data=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'data' in data and isinstance(data['data'], list):
        print('true')
    else:
        print('false')
except:
    print('false')
" 2>/dev/null)
            
            if [ "$has_data" = "true" ]; then
                local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data['data']))
" 2>/dev/null)
                print_success "Bulletin stories listing returned $count stories"
            else
                print_error "Bulletin stories response missing data array"
                return 1
            fi
        else
            return 1
        fi
        
        # Test bulletin stories with pagination
        print_info "Testing bulletin stories pagination..."
        local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins/$bulletin_id/stories?limit=1&offset=0" -b "$COOKIE_FILE")
        
        if check_response "$response" "200" "Get paginated bulletin stories" >/dev/null; then
            print_success "Bulletin stories pagination works"
        else
            return 1
        fi
    fi
    
    return 0
}

# Test bulletin caching and optimization
test_bulletin_caching() {
    print_section "Testing Bulletin Caching and Optimization"
    
    if [ ${#CREATED_STATION_IDS[@]} -eq 0 ]; then
        print_warning "No test stations available for caching tests"
        return 0
    fi
    
    local station_id="${CREATED_STATION_IDS[0]}"
    
    # Generate a fresh bulletin
    print_info "Generating fresh bulletin for caching test..."
    local response1=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins?force=true" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{}")
    
    local http_code1=$(echo "$response1" | tail -n1)
    if [ "$http_code1" != "200" ]; then
        print_error "Failed to generate fresh bulletin for caching test"
        return 1
    fi
    
    local body1=$(echo "$response1" | sed '$d')
    local cached1=$(parse_json_field "$body1" "cached")
    
    if [ "$cached1" = "false" ]; then
        print_success "Fresh bulletin correctly marked as not cached"
    else
        print_warning "Fresh bulletin marked as cached: $cached1"
    fi
    
    # Test caching with max_age parameter
    print_info "Testing bulletin caching with max_age parameter..."
    local response2=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins?max_age=300" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{}")
    
    local http_code2=$(echo "$response2" | tail -n1)
    if [ "$http_code2" = "200" ]; then
        local body2=$(echo "$response2" | sed '$d')
        local cached2=$(parse_json_field "$body2" "cached")
        
        if [ "$cached2" = "true" ]; then
            print_success "Cached bulletin correctly returned with max_age parameter"
        else
            print_info "No cached bulletin available or cache miss (cached: $cached2)"
        fi
    else
        print_error "Caching test failed - HTTP $http_code2"
        return 1
    fi
    
    # Test force parameter overrides cache
    print_info "Testing force parameter overrides cache..."
    local response3=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins?force=true&max_age=300" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{}")
    
    local http_code3=$(echo "$response3" | tail -n1)
    if [ "$http_code3" = "200" ]; then
        local body3=$(echo "$response3" | sed '$d')
        local cached3=$(parse_json_field "$body3" "cached")
        
        if [ "$cached3" = "false" ]; then
            print_success "Force parameter correctly overrides cache"
        else
            print_error "Force parameter did not override cache (cached: $cached3)"
            return 1
        fi
    else
        print_error "Force override test failed - HTTP $http_code3"
        return 1
    fi
    
    return 0
}

# Test error cases and edge conditions
test_bulletin_error_cases() {
    print_section "Testing Bulletin Error Cases"
    
    # Test bulletin generation for non-existent station
    print_info "Testing bulletin generation for non-existent station..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/99999/bulletins" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{}")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent station correctly returns 404"
    else
        print_error "Non-existent station returned HTTP $http_code (expected 404)"
        return 1
    fi
    
    # Test bulletin generation with invalid date format
    if [ ${#CREATED_STATION_IDS[@]} -gt 0 ]; then
        local station_id="${CREATED_STATION_IDS[0]}"
        
        print_info "Testing bulletin generation with invalid date..."
        local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations/$station_id/bulletins" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "{\"date\": \"invalid-date\"}")
        
        local http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "400" ]; then
            print_success "Invalid date format correctly returns 400"
        else
            print_warning "Invalid date returned HTTP $http_code (expected 400)"
        fi
    fi
    
    # Test audio download for non-existent bulletin
    print_info "Testing audio download for non-existent bulletin..."
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/bulletins/99999/audio" -b "$COOKIE_FILE")
    
    if [ "$response" = "404" ]; then
        print_success "Non-existent bulletin audio correctly returns 404"
    else
        print_error "Non-existent bulletin audio returned HTTP $response (expected 404)"
        return 1
    fi
    
    # Test bulletin stories for non-existent bulletin
    print_info "Testing stories for non-existent bulletin..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins/99999/stories" -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent bulletin stories correctly returns 404"
    else
        print_error "Non-existent bulletin stories returned HTTP $http_code (expected 404)"
        return 1
    fi
    
    # Test story bulletins for non-existent story
    print_info "Testing bulletins for non-existent story..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories/99999/bulletins" -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent story bulletins correctly returns 404"
    else
        print_error "Non-existent story bulletins returned HTTP $http_code (expected 404)"
        return 1
    fi
    
    # Test station bulletins for non-existent station
    print_info "Testing bulletins for non-existent station..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations/99999/bulletins" -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent station bulletins correctly returns 404"
    else
        print_error "Non-existent station bulletins returned HTTP $http_code (expected 404)"
        return 1
    fi
    
    return 0
}

# Test bulletin metadata and details
test_bulletin_metadata() {
    print_section "Testing Bulletin Metadata and Details"
    
    # Get a bulletin to test metadata
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/bulletins?limit=1" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Get bulletin for metadata test" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local bulletin=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'data' in data and len(data['data']) > 0:
        import json
        print(json.dumps(data['data'][0]))
except:
    print('{}')
" 2>/dev/null)
        
        if [ "$bulletin" != "{}" ]; then
            print_info "Testing bulletin metadata fields..."
            
            # Check required fields
            local required_fields=("id" "station_id" "station_name" "audio_url" "filename" "created_at" "duration" "file_size" "story_count")
            local missing_fields=()
            
            for field in "${required_fields[@]}"; do
                local value=$(echo "$bulletin" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('$field', ''))
" 2>/dev/null)
                
                if [ -n "$value" ] && [ "$value" != "null" ]; then
                    print_success "Field '$field' present: $value"
                else
                    missing_fields+=("$field")
                fi
            done
            
            if [ ${#missing_fields[@]} -eq 0 ]; then
                print_success "All required bulletin metadata fields present"
            else
                print_error "Missing required fields: ${missing_fields[*]}"
                return 1
            fi
            
            # Validate audio URL format
            local audio_url=$(echo "$bulletin" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('audio_url', ''))
" 2>/dev/null)
            
            if [[ "$audio_url" =~ ^/api/v1/bulletins/[0-9]+/audio$ ]]; then
                print_success "Audio URL format is correct: $audio_url"
            else
                print_error "Audio URL format is incorrect: $audio_url"
                return 1
            fi
            
            # Validate duration is numeric and positive
            local duration=$(echo "$bulletin" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('duration', 0))
" 2>/dev/null)
            
            if [ -n "$duration" ] && (( $(echo "$duration > 0" | bc -l 2>/dev/null || echo "0") )); then
                print_success "Duration is valid: ${duration}s"
            else
                print_warning "Duration may be invalid: $duration"
            fi
            
            # Validate story count is numeric and non-negative
            local story_count=$(echo "$bulletin" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('story_count', 0))
" 2>/dev/null)
            
            if [[ "$story_count" =~ ^[0-9]+$ ]] && [ "$story_count" -ge 0 ]; then
                print_success "Story count is valid: $story_count"
            else
                print_error "Story count is invalid: $story_count"
                return 1
            fi
            
        else
            print_warning "No bulletin data available for metadata test"
        fi
    else
        return 1
    fi
    
    return 0
}

# Setup function
setup() {
    print_info "Setting up bulletin tests..."
    restore_admin_session
    
    # Verify FFmpeg is available for audio file creation
    if ! command -v ffmpeg &> /dev/null; then
        print_warning "FFmpeg not available - some audio tests may be skipped"
    fi
    
    return 0
}

# Cleanup function
cleanup() {
    print_info "Cleaning up bulletin tests..."
    
    # Delete all created station-voice relationships
    for sv_id in "${CREATED_STATION_VOICE_IDS[@]}"; do
        curl -s -X DELETE "$API_URL/station-voices/$sv_id" -b "$COOKIE_FILE" >/dev/null 2>&1
        print_info "Cleaned up station-voice: $sv_id"
    done
    
    # Delete all created stories
    for story_id in "${CREATED_STORY_IDS[@]}"; do
        curl -s -X DELETE "$API_URL/stories/$story_id" -b "$COOKIE_FILE" >/dev/null 2>&1
        print_info "Cleaned up story: $story_id"
    done
    
    # Delete all created voices
    for voice_id in "${CREATED_VOICE_IDS[@]}"; do
        curl -s -X DELETE "$API_URL/voices/$voice_id" -b "$COOKIE_FILE" >/dev/null 2>&1
        print_info "Cleaned up voice: $voice_id"
    done
    
    # Delete all created stations
    for station_id in "${CREATED_STATION_IDS[@]}"; do
        curl -s -X DELETE "$API_URL/stations/$station_id" -b "$COOKIE_FILE" >/dev/null 2>&1
        print_info "Cleaned up station: $station_id"
    done
    
    # Clean up test audio files
    rm -f /tmp/test_jingle_*.wav
    rm -f /tmp/test_story_audio_*.wav
    rm -f /tmp/test_bulletin_download.wav
    
    return 0
}

# Main function
main() {
    print_header "Bulletin Tests"
    
    setup
    
    local tests=(
        "test_bulletin_generation"
        "test_bulletin_retrieval"
        "test_bulletin_audio_download"
        "test_station_bulletin_endpoints"
        "test_bulletin_history"
        "test_bulletin_caching"
        "test_bulletin_metadata"
        "test_bulletin_error_cases"
    )
    
    local failed=0
    
    for test in "${tests[@]}"; do
        if run_test "$test"; then
            print_success "✓ $test passed"
        else
            print_error "✗ $test failed"
            failed=$((failed + 1))
        fi
        echo ""
    done
    
    cleanup
    
    print_summary
    
    if [ $failed -eq 0 ]; then
        print_success "All bulletin tests passed!"
        exit 0
    else
        print_error "$failed bulletin tests failed"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi