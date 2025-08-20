#!/bin/bash

# Babbel Voices Tests
# Test voice management functionality

# Get the script directory and source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/auth.sh"
source "$SCRIPT_DIR/../lib/assertions.sh"

# Global variables for tracking created resources
CREATED_VOICE_IDS=()

# Helper function to create a voice and track its ID
create_voice() {
    local name="$1"
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/voices" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$name\"}")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "201" ]; then
        # API returns {id: X, message: "..."} on creation
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

# Test voice creation
test_voice_creation() {
    print_section "Testing Voice Creation"
    
    # Test creating a valid voice
    print_info "Creating a new voice..."
    local voice_id=$(create_voice "Test Voice 1")
    
    if [ -n "$voice_id" ]; then
        print_success "Voice created successfully (ID: $voice_id)"
        
        # Verify the voice exists
        local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/voices/$voice_id" -b "$COOKIE_FILE")
        if check_response "$response" "200" "Get created voice" >/dev/null; then
            local body=$(echo "$response" | sed '$d')
            local name=$(parse_json_field "$body" "name")
            
            if [ "$name" = "Test Voice 1" ]; then
                print_success "Voice data verified"
            else
                print_error "Voice name mismatch: expected 'Test Voice 1', got '$name'"
                return 1
            fi
        else
            return 1
        fi
    else
        print_error "Failed to create voice"
        return 1
    fi
    
    # Test creating voice with duplicate name
    print_info "Testing duplicate voice name..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/voices" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"name": "Test Voice 1"}')
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "409" ]; then
        print_success "Duplicate voice correctly rejected (409 Conflict)"
    else
        print_error "Duplicate voice not rejected (HTTP: $http_code)"
        return 1
    fi
    
    # Test invalid voice creation (missing name)
    print_info "Testing voice creation without name..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/voices" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{}')
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "422" ]; then
        print_success "Invalid voice correctly rejected (422)"
    else
        print_error "Invalid voice not rejected (HTTP: $http_code)"
        return 1
    fi
    
    return 0
}

# Test voice listing
test_voice_listing() {
    print_section "Testing Voice Listing"
    
    # Create some test voices
    print_info "Creating test voices for listing..."
    create_voice "List Test Voice 1" >/dev/null
    create_voice "List Test Voice 2" >/dev/null
    create_voice "List Test Voice 3" >/dev/null
    
    # Test basic listing
    print_info "Testing basic voice listing..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/voices" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "List voices" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        
        # Check for data array
        if echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data and isinstance(data['data'], list):
    sys.exit(0)
else:
    sys.exit(1)
" 2>/dev/null; then
            local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data['data']))
" 2>/dev/null)
            print_success "Voice listing returned $count voices"
        else
            print_error "Voice listing response missing data array"
            return 1
        fi
    else
        return 1
    fi
    
    # Test pagination
    print_info "Testing voice pagination..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/voices?limit=2&offset=0" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "List voices with pagination" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', [])))
" 2>/dev/null)
        
        if [ "$count" -le "2" ]; then
            print_success "Pagination limit respected (returned $count voices)"
        else
            print_error "Pagination limit not respected (returned $count voices)"
            return 1
        fi
    else
        return 1
    fi
    
    # Test search
    print_info "Testing voice search..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/voices?search=List%20Test" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Search voices" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', [])))
" 2>/dev/null)
        
        if [ "$count" -ge "3" ]; then
            print_success "Search returned $count matching voices"
        else
            print_error "Search returned unexpected number of voices: $count"
            return 1
        fi
    else
        return 1
    fi
    
    # Test sorting
    print_info "Testing voice sorting..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/voices?sort=-name" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Sort voices" >/dev/null; then
        print_success "Voice sorting request succeeded"
    else
        return 1
    fi
    
    return 0
}

# Test voice updates
test_voice_updates() {
    print_section "Testing Voice Updates"
    
    # Create a voice to update
    print_info "Creating voice for update tests..."
    local voice_id=$(create_voice "Update Test Voice")
    
    if [ -z "$voice_id" ]; then
        print_error "Failed to create test voice"
        return 1
    fi
    
    # Test updating voice name
    print_info "Updating voice name..."
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/voices/$voice_id" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"name": "Updated Voice Name"}')
    
    if check_response "$response" "200" "Update voice" >/dev/null; then
        # Verify the update
        local get_response=$(curl -s -X GET "$API_URL/voices/$voice_id" -b "$COOKIE_FILE")
        local name=$(parse_json_field "$get_response" "name")
        
        if [ "$name" = "Updated Voice Name" ]; then
            print_success "Voice name updated successfully"
        else
            print_error "Voice name not updated correctly"
            return 1
        fi
    else
        return 1
    fi
    
    # Test updating with duplicate name
    print_info "Testing update with duplicate name..."
    create_voice "Duplicate Test Voice" >/dev/null
    
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/voices/$voice_id" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"name": "Duplicate Test Voice"}')
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "409" ]; then
        print_success "Duplicate name correctly rejected on update"
    else
        print_error "Duplicate name not rejected (HTTP: $http_code)"
        return 1
    fi
    
    # Test updating non-existent voice
    print_info "Testing update of non-existent voice..."
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/voices/99999" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"name": "Non-existent"}')
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent voice update correctly rejected"
    else
        print_error "Non-existent voice update not rejected (HTTP: $http_code)"
        return 1
    fi
    
    return 0
}

# Test voice deletion
test_voice_deletion() {
    print_section "Testing Voice Deletion"
    
    # Create a voice to delete
    print_info "Creating voice for deletion test..."
    local voice_id=$(create_voice "Delete Test Voice")
    
    if [ -z "$voice_id" ]; then
        print_error "Failed to create test voice"
        return 1
    fi
    
    # Test deleting the voice
    print_info "Deleting voice..."
    local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/voices/$voice_id" -b "$COOKIE_FILE")
    
    if check_response "$response" "204" "Delete voice" >/dev/null; then
        print_success "Voice deleted successfully"
        
        # Verify voice is deleted
        local get_response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/voices/$voice_id" -b "$COOKIE_FILE")
        local http_code=$(echo "$get_response" | tail -n1)
        
        if [ "$http_code" = "404" ]; then
            print_success "Deleted voice correctly returns 404"
        else
            print_error "Deleted voice still accessible (HTTP: $http_code)"
            return 1
        fi
    else
        return 1
    fi
    
    # Test deleting non-existent voice
    print_info "Testing deletion of non-existent voice..."
    local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/voices/99999" -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent voice deletion correctly returns 404"
    else
        print_error "Non-existent voice deletion returned unexpected code: $http_code"
        return 1
    fi
    
    return 0
}

# Test voice with associated stories
test_voice_with_stories() {
    print_section "Testing Voice with Associated Stories"
    
    # Create a voice
    print_info "Creating voice for story association test..."
    local voice_id=$(create_voice "Story Test Voice")
    
    if [ -z "$voice_id" ]; then
        print_error "Failed to create test voice"
        return 1
    fi
    
    # Create a story with this voice (using form data with individual weekday fields)
    print_info "Creating story with voice..."
    local story_response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
        -b "$COOKIE_FILE" \
        -F "title=Test Story with Voice" \
        -F "text=This is a test story." \
        -F "voice_id=$voice_id" \
        -F "status=active" \
        -F "start_date=2024-01-01" \
        -F "end_date=2024-12-31" \
        -F "monday=true" \
        -F "tuesday=true" \
        -F "wednesday=true" \
        -F "thursday=true" \
        -F "friday=true" \
        -F "saturday=false" \
        -F "sunday=false")
    
    local http_code=$(echo "$story_response" | tail -n1)
    if [ "$http_code" = "201" ]; then
        print_success "Story created with voice"
        
        # Try to delete the voice (should fail or handle gracefully)
        print_info "Attempting to delete voice with associated story..."
        local delete_response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/voices/$voice_id" -b "$COOKIE_FILE")
        local delete_code=$(echo "$delete_response" | tail -n1)
        
        # This might return 409 (conflict) or 204 (if cascade delete is enabled)
        if [ "$delete_code" = "409" ]; then
            print_success "Voice with stories correctly protected from deletion"
        elif [ "$delete_code" = "204" ]; then
            print_success "Voice deleted (cascade delete enabled)"
        else
            print_warning "Unexpected response when deleting voice with stories: $delete_code"
        fi
    else
        print_error "Failed to create story with voice (HTTP: $http_code)"
        return 1
    fi
    
    return 0
}

# Setup function
setup() {
    print_info "Setting up voice tests..."
    restore_admin_session
    return 0
}

# Cleanup function
cleanup() {
    print_info "Cleaning up voice tests..."
    
    # Delete all created voices
    for voice_id in "${CREATED_VOICE_IDS[@]}"; do
        curl -s -X DELETE "$API_URL/voices/$voice_id" -b "$COOKIE_FILE" >/dev/null 2>&1
        print_info "Cleaned up voice: $voice_id"
    done
    
    # Clean up any test stories
    local stories_response=$(curl -s -X GET "$API_URL/stories" -b "$COOKIE_FILE")
    if [ $? -eq 0 ]; then
        echo "$stories_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'data' in data:
        for story in data['data']:
            if 'Test' in story.get('title', ''):
                print(story['id'])
except:
    pass
" | while read story_id; do
            if [ -n "$story_id" ]; then
                curl -s -X DELETE "$API_URL/stories/$story_id" -b "$COOKIE_FILE" >/dev/null 2>&1
                print_info "Cleaned up test story: $story_id"
            fi
        done
    fi
    
    return 0
}

# Main function
main() {
    print_header "Voice Tests"
    
    setup
    
    local tests=(
        "test_voice_creation"
        "test_voice_listing"
        "test_voice_updates"
        "test_voice_deletion"
        "test_voice_with_stories"
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
        print_success "All voice tests passed!"
        exit 0
    else
        print_error "$failed voice tests failed"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi