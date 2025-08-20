#!/bin/bash

# Babbel Station-Voices Tests
# Test station-voice relationship management with jingle uploads

# Get the script directory and source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/auth.sh"
source "$SCRIPT_DIR/../lib/assertions.sh"

# Global variables for tracking created resources
CREATED_STATION_IDS=()
CREATED_VOICE_IDS=()
CREATED_STATION_VOICE_IDS=()

# Helper function to create a station
create_station() {
    local name="$1"
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$name\", \"max_stories_per_block\": 5, \"pause_seconds\": 2.0}")
    
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
    fi
    
    return 1
}

# Helper function to create a voice
create_voice() {
    local name="$1"
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/voices" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$name\"}")
    
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
    fi
    
    return 1
}

# Test creating station-voice relationship
test_create_station_voice() {
    print_section "Testing Station-Voice Creation"
    
    # Create a station and voice first
    print_info "Creating test station..."
    local station_id=$(create_station "SV Test Station")
    if [ -z "$station_id" ]; then
        print_error "Failed to create test station"
        return 1
    fi
    print_success "Created station (ID: $station_id)"
    
    print_info "Creating test voice..."
    local voice_id=$(create_voice "SV Test Voice")
    if [ -z "$voice_id" ]; then
        print_error "Failed to create test voice"
        return 1
    fi
    print_success "Created voice (ID: $voice_id)"
    
    # Test creating station-voice relationship with JSON
    print_info "Creating station-voice relationship with JSON..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/station-voices" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"station_id\": $station_id, \"voice_id\": $voice_id, \"mix_point\": 2.5}")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
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
            print_success "Created station-voice relationship (ID: $sv_id)"
        else
            print_error "Could not extract station-voice ID from response"
            return 1
        fi
    else
        print_error "Failed to create station-voice relationship (HTTP: $http_code)"
        return 1
    fi
    
    # Test creating duplicate relationship (should fail)
    print_info "Testing duplicate station-voice relationship..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/station-voices" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"station_id\": $station_id, \"voice_id\": $voice_id, \"mix_point\": 3.0}")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "409" ]; then
        print_success "Duplicate relationship correctly rejected (409 Conflict)"
    else
        print_error "Duplicate relationship not rejected (HTTP: $http_code)"
        return 1
    fi
    
    return 0
}

# Test creating station-voice with audio file upload
test_create_station_voice_with_audio() {
    print_section "Testing Station-Voice Creation with Audio Upload"
    
    # Create a station and voice first
    print_info "Creating test station for audio upload..."
    local station_id=$(create_station "Audio Test Station")
    if [ -z "$station_id" ]; then
        print_error "Failed to create test station"
        return 1
    fi
    
    print_info "Creating test voice for audio upload..."
    local voice_id=$(create_voice "Audio Test Voice")
    if [ -z "$voice_id" ]; then
        print_error "Failed to create test voice"
        return 1
    fi
    
    # Create a simple test audio file if it doesn't exist
    local test_audio="/tmp/test_jingle.wav"
    if [ ! -f "$test_audio" ]; then
        print_info "Creating test audio file..."
        # Create a 1-second silent WAV file using ffmpeg if available
        if command -v ffmpeg &> /dev/null; then
            ffmpeg -f lavfi -i anullsrc=r=44100:cl=stereo -t 1 -f wav "$test_audio" 2>/dev/null
            if [ -f "$test_audio" ]; then
                print_success "Created test audio file"
            else
                print_warning "Could not create test audio file, skipping audio upload test"
                return 0
            fi
        else
            print_warning "ffmpeg not available, skipping audio upload test"
            return 0
        fi
    fi
    
    # Test creating station-voice with multipart/form-data and audio file
    print_info "Creating station-voice with audio upload..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/station-voices" \
        -b "$COOKIE_FILE" \
        -F "station_id=$station_id" \
        -F "voice_id=$voice_id" \
        -F "mix_point=1.5" \
        -F "jingle=@$test_audio")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
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
            print_success "Created station-voice with audio (ID: $sv_id)"
            
            # Verify the jingle file was saved
            local jingle_path="$AUDIO_DIR/processed/station_${station_id}_voice_${voice_id}_jingle.wav"
            if wait_for_audio_file "$jingle_path" 5; then
                print_success "Jingle file saved successfully"
            else
                print_warning "Jingle file not found at expected location"
            fi
        else
            print_error "Could not extract station-voice ID from response"
            return 1
        fi
    else
        print_error "Failed to create station-voice with audio (HTTP: $http_code)"
        print_error "Response: $body"
        return 1
    fi
    
    return 0
}

# Test listing station-voices
test_list_station_voices() {
    print_section "Testing Station-Voice Listing"
    
    # Create some test data
    print_info "Creating test data for listing..."
    local station1=$(create_station "List Test Station 1")
    local station2=$(create_station "List Test Station 2")
    local voice1=$(create_voice "List Test Voice 1")
    local voice2=$(create_voice "List Test Voice 2")
    
    # Create relationships
    curl -s -X POST "$API_URL/station-voices" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"station_id\": $station1, \"voice_id\": $voice1, \"mix_point\": 1.0}" >/dev/null
    
    curl -s -X POST "$API_URL/station-voices" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"station_id\": $station2, \"voice_id\": $voice2, \"mix_point\": 2.0}" >/dev/null
    
    # Test basic listing
    print_info "Testing basic station-voice listing..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/station-voices" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "List station-voices" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', [])))
" 2>/dev/null)
        print_success "Station-voice listing returned $count relationships"
    else
        return 1
    fi
    
    # Test filtering by station_id
    print_info "Testing filter by station_id..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/station-voices?station_id=$station1" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Filter by station" >/dev/null; then
        print_success "Filtering by station_id works"
    else
        return 1
    fi
    
    # Test filtering by voice_id
    print_info "Testing filter by voice_id..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/station-voices?voice_id=$voice1" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Filter by voice" >/dev/null; then
        print_success "Filtering by voice_id works"
    else
        return 1
    fi
    
    return 0
}

# Test updating station-voice
test_update_station_voice() {
    print_section "Testing Station-Voice Update"
    
    # Create test data
    print_info "Creating test data for update..."
    local station_id=$(create_station "Update Test Station")
    local voice_id=$(create_voice "Update Test Voice")
    
    # Create a station-voice relationship
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/station-voices" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"station_id\": $station_id, \"voice_id\": $voice_id, \"mix_point\": 1.0}")
    
    local sv_id=$(echo "$response" | sed '$d' | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'id' in data:
        print(data['id'])
except:
    pass
" 2>/dev/null)
    
    if [ -z "$sv_id" ]; then
        print_error "Failed to create station-voice for update test"
        return 1
    fi
    
    # Test updating mix_point
    print_info "Updating station-voice mix_point..."
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/station-voices/$sv_id" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"mix_point": 3.5}')
    
    if check_response "$response" "200" "Update station-voice" >/dev/null; then
        print_success "Station-voice updated successfully"
        
        # Verify the update
        local get_response=$(curl -s -X GET "$API_URL/station-voices/$sv_id" -b "$COOKIE_FILE")
        local mix_point=$(echo "$get_response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('mix_point', 0))
" 2>/dev/null)
        
        if [ "$mix_point" = "3.5" ]; then
            print_success "Mix point updated correctly"
        else
            print_error "Mix point not updated correctly (got: $mix_point)"
            return 1
        fi
    else
        return 1
    fi
    
    # Test updating non-existent station-voice
    print_info "Testing update of non-existent station-voice..."
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/station-voices/99999" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"mix_point": 5.0}')
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent station-voice update correctly rejected"
    else
        print_error "Non-existent station-voice update not rejected (HTTP: $http_code)"
        return 1
    fi
    
    return 0
}

# Test deleting station-voice
test_delete_station_voice() {
    print_section "Testing Station-Voice Deletion"
    
    # Create test data
    print_info "Creating test data for deletion..."
    local station_id=$(create_station "Delete Test Station")
    local voice_id=$(create_voice "Delete Test Voice")
    
    # Create a station-voice relationship
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/station-voices" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"station_id\": $station_id, \"voice_id\": $voice_id, \"mix_point\": 2.0}")
    
    local sv_id=$(echo "$response" | sed '$d' | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'id' in data:
        print(data['id'])
except:
    pass
" 2>/dev/null)
    
    if [ -z "$sv_id" ]; then
        print_error "Failed to create station-voice for deletion test"
        return 1
    fi
    
    # Test deleting the station-voice
    print_info "Deleting station-voice..."
    local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/station-voices/$sv_id" -b "$COOKIE_FILE")
    
    if check_response "$response" "204" "Delete station-voice" >/dev/null; then
        print_success "Station-voice deleted successfully"
        
        # Verify it's deleted
        local get_response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/station-voices/$sv_id" -b "$COOKIE_FILE")
        local http_code=$(echo "$get_response" | tail -n1)
        
        if [ "$http_code" = "404" ]; then
            print_success "Deleted station-voice correctly returns 404"
        else
            print_error "Deleted station-voice still accessible (HTTP: $http_code)"
            return 1
        fi
    else
        return 1
    fi
    
    # Test deleting non-existent station-voice
    print_info "Testing deletion of non-existent station-voice..."
    local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/station-voices/99999" -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent station-voice deletion correctly returns 404"
    else
        print_error "Non-existent station-voice deletion returned unexpected code: $http_code"
        return 1
    fi
    
    return 0
}

# Setup function
setup() {
    print_info "Setting up station-voice tests..."
    restore_admin_session
    return 0
}

# Cleanup function
cleanup() {
    print_info "Cleaning up station-voice tests..."
    
    # Delete all created station-voices
    for sv_id in "${CREATED_STATION_VOICE_IDS[@]}"; do
        curl -s -X DELETE "$API_URL/station-voices/$sv_id" -b "$COOKIE_FILE" >/dev/null 2>&1
        print_info "Cleaned up station-voice: $sv_id"
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
    
    # Clean up test audio file
    rm -f /tmp/test_jingle.wav
    
    return 0
}

# Main function
main() {
    print_header "Station-Voice Tests"
    
    setup
    
    local tests=(
        "test_create_station_voice"
        "test_create_station_voice_with_audio"
        "test_list_station_voices"
        "test_update_station_voice"
        "test_delete_station_voice"
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
        print_success "All station-voice tests passed!"
        exit 0
    else
        print_error "$failed station-voice tests failed"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi