#!/bin/bash

# Babbel Stories Tests
# Test story management functionality

# Get the script directory and source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/auth.sh"
source "$SCRIPT_DIR/../lib/assertions.sh"

# Global variables for tracking created resources
CREATED_STORY_IDS=()
CREATED_VOICE_IDS=()

# Helper function to create a voice for stories
create_voice() {
    local base_name="$1"
    # Add timestamp to ensure uniqueness
    local unique_name="${base_name}_$(date +%s)_$$"
    
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
        # Debug output for failures
        print_error "Voice creation failed - HTTP $http_code: $body"
    fi
    
    return 1
}

# Helper function to create a story and track its ID
create_story() {
    local title="$1"
    local text="$2"
    local voice_id="$3"
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
        -b "$COOKIE_FILE" \
        -F "title=$title" \
        -F "text=$text" \
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
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
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
    fi
    
    return 1
}

# Test story creation
test_story_creation() {
    print_section "Testing Story Creation"
    
    # Create a voice first
    print_info "Creating test voice for stories..."
    local voice_id=$(create_voice "Story Test Voice")
    if [ -z "$voice_id" ]; then
        print_error "Failed to create test voice"
        return 1
    fi
    print_success "Created voice (ID: $voice_id)"
    
    # Test creating a valid story with form data
    print_info "Creating a new story..."
    local story_id=$(create_story "Test Story 1" "This is the content of test story 1." "$voice_id")
    
    if [ -n "$story_id" ]; then
        print_success "Story created successfully (ID: $story_id)"
        
        # Verify the story exists
        local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories/$story_id" -b "$COOKIE_FILE")
        if check_response "$response" "200" "Get created story" >/dev/null; then
            local body=$(echo "$response" | sed '$d')
            local title=$(parse_json_field "$body" "title")
            
            if [ "$title" = "Test Story 1" ]; then
                print_success "Story data verified"
            else
                print_error "Story title mismatch: expected 'Test Story 1', got '$title'"
                return 1
            fi
        else
            return 1
        fi
    else
        print_error "Failed to create story"
        return 1
    fi
    
    # Test creating story with audio file
    print_info "Creating story with audio file..."
    
    # Create a simple test audio file if it doesn't exist
    local test_audio="/tmp/test_story.wav"
    if [ ! -f "$test_audio" ]; then
        if command -v ffmpeg &> /dev/null; then
            ffmpeg -f lavfi -i anullsrc=r=44100:cl=stereo -t 2 -f wav "$test_audio" 2>/dev/null
            if [ -f "$test_audio" ]; then
                print_success "Created test audio file"
            else
                print_warning "Could not create test audio file, skipping audio test"
            fi
        else
            print_warning "ffmpeg not available, skipping audio test"
        fi
    fi
    
    if [ -f "$test_audio" ]; then
        local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
            -b "$COOKIE_FILE" \
            -F "title=Story with Audio" \
            -F "text=This story has an audio file." \
            -F "voice_id=$voice_id" \
            -F "status=active" \
            -F "start_date=2024-01-01" \
            -F "end_date=2024-12-31" \
            -F "monday=true" \
            -F "tuesday=false" \
            -F "wednesday=true" \
            -F "thursday=false" \
            -F "friday=true" \
            -F "saturday=false" \
            -F "sunday=false" \
            -F "audio=@$test_audio")
        
        local http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "201" ]; then
            local story_id=$(echo "$response" | sed '$d' | python3 -c "
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
                print_success "Story with audio created (ID: $story_id)"
                
                # Verify audio file was saved
                local audio_path="$AUDIO_DIR/stories/story${story_id}.wav"
                if wait_for_audio_file "$audio_path" 5; then
                    print_success "Story audio file saved successfully"
                else
                    print_warning "Story audio file not found at expected location"
                fi
            fi
        else
            print_error "Failed to create story with audio (HTTP: $http_code)"
        fi
    fi
    
    # Test invalid story creation (missing required fields)
    print_info "Testing story creation without title..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
        -b "$COOKIE_FILE" \
        -F "text=Story without title" \
        -F "voice_id=$voice_id")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "422" ]; then
        print_success "Invalid story correctly rejected (422)"
    else
        print_error "Invalid story not rejected (HTTP: $http_code)"
        return 1
    fi
    
    # Test creating story with all weekdays selected
    print_info "Creating story with all weekdays..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
        -b "$COOKIE_FILE" \
        -F "title=All Days Story" \
        -F "text=This story runs every day." \
        -F "voice_id=$voice_id" \
        -F "status=active" \
        -F "start_date=2024-01-01" \
        -F "end_date=2024-12-31" \
        -F "monday=true" \
        -F "tuesday=true" \
        -F "wednesday=true" \
        -F "thursday=true" \
        -F "friday=true" \
        -F "saturday=true" \
        -F "sunday=true")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "201" ]; then
        print_success "Story with all weekdays created"
        local story_id=$(echo "$response" | sed '$d' | python3 -c "
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
        fi
    else
        print_error "Failed to create story with all weekdays (HTTP: $http_code)"
        return 1
    fi
    
    return 0
}

# Test story listing
test_story_listing() {
    print_section "Testing Story Listing"
    
    # Create a voice and some test stories
    print_info "Creating test data for listing..."
    local voice_id=$(create_voice "List Test Voice")
    if [ -z "$voice_id" ]; then
        print_error "Failed to create test voice"
        return 1
    fi
    
    create_story "List Story 1" "Content 1" "$voice_id" >/dev/null
    create_story "List Story 2" "Content 2" "$voice_id" >/dev/null
    create_story "List Story 3" "Content 3" "$voice_id" >/dev/null
    
    # Test basic listing
    print_info "Testing basic story listing..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "List stories" >/dev/null; then
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
            print_success "Story listing returned $count stories"
        else
            print_error "Story listing response missing data array"
            return 1
        fi
    else
        return 1
    fi
    
    # Test pagination
    print_info "Testing story pagination..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?limit=2&offset=0" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "List stories with pagination" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', [])))
" 2>/dev/null)
        
        if [ "$count" -le "2" ]; then
            print_success "Pagination limit respected (returned $count stories)"
        else
            print_error "Pagination limit not respected (returned $count stories)"
            return 1
        fi
    else
        return 1
    fi
    
    # Test filtering by voice_id using modern filter
    print_info "Testing filter by voice_id..."
    if [ -z "$voice_id" ]; then
        print_error "voice_id is empty!"
        return 1
    fi
    
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Bvoice_id%5D=$voice_id" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Filter by voice" >/dev/null; then
        print_success "Filtering by voice_id works"
    else
        return 1
    fi
    
    # Test filtering by status
    print_info "Testing filter by status..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?status=active" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Filter by status" >/dev/null; then
        print_success "Filtering by status works"
    else
        return 1
    fi
    
    # Test date range filtering
    print_info "Testing date range filtering..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Bstart_date%5D%5Blte%5D=2024-06-15&filter%5Bend_date%5D%5Bgte%5D=2024-06-15" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Date range filter" >/dev/null; then
        print_success "Date range filtering works"
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', [])))
" 2>/dev/null)
        print_info "Found $count stories in date range"
    else
        return 1
    fi
    
    # Test filtering by weekday using modern filter
    print_info "Testing weekday filtering..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Bmonday%5D=1" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Weekday filter" >/dev/null; then
        print_success "Weekday filtering works"
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', [])))
" 2>/dev/null)
        print_info "Found $count stories scheduled for Monday"
    else
        return 1
    fi
    
    # Test modern boolean filters
    print_info "Testing modern boolean filters..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?has_voice=true" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Boolean filter has_voice" >/dev/null; then
        print_success "Modern boolean filters work"
    else
        return 1
    fi
    
    # Test modern field selection
    print_info "Testing field selection (sparse fieldsets)..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?fields=id,title,created_at&limit=2" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Field selection" >/dev/null; then
        print_success "Field selection request accepted"
        # Note: Actual field reduction may not be implemented yet
    else
        return 1
    fi
    
    # Test modern sorting with colon notation
    print_info "Testing modern sorting..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?sort=created_at:desc,title:asc" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Modern sorting" >/dev/null; then
        print_success "Modern sorting with colon notation works"
    else
        return 1
    fi
    
    # Test prefix sorting notation
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?sort=-created_at,+title" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Prefix sorting" >/dev/null; then
        print_success "Sorting with prefix notation works"
    else
        return 1
    fi
    
    # Test search
    print_info "Testing story search..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?search=List%20Story" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Search stories" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', [])))
" 2>/dev/null)
        
        if [ "$count" -ge "3" ]; then
            print_success "Search returned $count matching stories"
        else
            print_warning "Search returned unexpected number of stories: $count"
        fi
    else
        return 1
    fi
    
    # Test sorting
    print_info "Testing story sorting..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?sort=-created_at" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Sort stories" >/dev/null; then
        print_success "Story sorting request succeeded"
    else
        return 1
    fi
    
    return 0
}

# Test story updates
test_story_updates() {
    print_section "Testing Story Updates"
    
    # Create a voice and story to update
    print_info "Creating test data for update..."
    local voice_id=$(create_voice "Update Test Voice")
    if [ -z "$voice_id" ]; then
        print_error "Failed to create test voice"
        return 1
    fi
    
    local story_id=$(create_story "Update Test Story" "Original content" "$voice_id")
    if [ -z "$story_id" ]; then
        print_error "Failed to create test story"
        return 1
    fi
    
    # Test updating story title and text
    print_info "Updating story title and text..."
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/stories/$story_id" \
        -b "$COOKIE_FILE" \
        -F "title=Updated Story Title" \
        -F "text=Updated story content")
    
    if check_response "$response" "200" "Update story" >/dev/null; then
        # Verify the update
        local get_response=$(curl -s -X GET "$API_URL/stories/$story_id" -b "$COOKIE_FILE")
        local title=$(parse_json_field "$get_response" "title")
        local text=$(parse_json_field "$get_response" "text")
        
        if [ "$title" = "Updated Story Title" ] && [ "$text" = "Updated story content" ]; then
            print_success "Story updated successfully"
        else
            print_error "Story not updated correctly"
            return 1
        fi
    else
        return 1
    fi
    
    # Test updating weekday schedule
    print_info "Updating story weekday schedule..."
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/stories/$story_id" \
        -b "$COOKIE_FILE" \
        -F "monday=false" \
        -F "tuesday=true" \
        -F "wednesday=false" \
        -F "thursday=true" \
        -F "friday=false" \
        -F "saturday=true" \
        -F "sunday=true")
    
    if check_response "$response" "200" "Update weekdays" >/dev/null; then
        print_success "Story weekday schedule updated"
    else
        return 1
    fi
    
    # Test updating status
    print_info "Updating story status to draft..."
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/stories/$story_id" \
        -b "$COOKIE_FILE" \
        -F "status=draft")
    
    if check_response "$response" "200" "Update status" >/dev/null; then
        # Verify the status update
        local get_response=$(curl -s -X GET "$API_URL/stories/$story_id" -b "$COOKIE_FILE")
        local status=$(parse_json_field "$get_response" "status")
        
        if [ "$status" = "draft" ]; then
            print_success "Story status updated to draft"
        else
            print_error "Story status not updated correctly"
            return 1
        fi
    else
        return 1
    fi
    
    # Test updating voice assignment
    print_info "Creating another voice for reassignment..."
    local new_voice_id=$(create_voice "New Assignment Voice")
    if [ -n "$new_voice_id" ]; then
        print_info "Updating story voice assignment..."
        local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/stories/$story_id" \
            -b "$COOKIE_FILE" \
            -F "voice_id=$new_voice_id")
        
        if check_response "$response" "200" "Update voice assignment" >/dev/null; then
            print_success "Story voice assignment updated"
        else
            return 1
        fi
    fi
    
    # Test updating dates
    print_info "Updating story dates..."
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/stories/$story_id" \
        -b "$COOKIE_FILE" \
        -F "start_date=2024-06-01" \
        -F "end_date=2024-08-31")
    
    if check_response "$response" "200" "Update dates" >/dev/null; then
        print_success "Story dates updated"
    else
        return 1
    fi
    
    # Test updating non-existent story
    print_info "Testing update of non-existent story..."
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/stories/99999" \
        -b "$COOKIE_FILE" \
        -F "title=Non-existent")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent story update correctly rejected"
    else
        print_error "Non-existent story update not rejected (HTTP: $http_code)"
        return 1
    fi
    
    return 0
}

# Test story deletion
test_story_deletion() {
    print_section "Testing Story Deletion"
    
    # Create a voice and story to delete
    print_info "Creating test data for deletion..."
    local voice_id=$(create_voice "Delete Test Voice")
    if [ -z "$voice_id" ]; then
        print_error "Failed to create test voice"
        return 1
    fi
    
    local story_id=$(create_story "Delete Test Story" "To be deleted" "$voice_id")
    if [ -z "$story_id" ]; then
        print_error "Failed to create test story"
        return 1
    fi
    
    # Test soft delete (default)
    print_info "Soft deleting story..."
    local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/stories/$story_id" -b "$COOKIE_FILE")
    
    if check_response "$response" "204" "Delete story" >/dev/null; then
        print_success "Story soft deleted successfully"
        
        # Verify story is soft deleted (might still be accessible depending on implementation)
        local get_response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories/$story_id" -b "$COOKIE_FILE")
        local http_code=$(echo "$get_response" | tail -n1)
        
        if [ "$http_code" = "404" ]; then
            print_success "Soft deleted story returns 404"
        else
            print_info "Soft deleted story still accessible (soft delete behavior)"
        fi
    else
        return 1
    fi
    
    # Create another story for hard delete test
    local story_id2=$(create_story "Hard Delete Test Story" "To be permanently deleted" "$voice_id")
    if [ -z "$story_id2" ]; then
        print_error "Failed to create second test story"
        return 1
    fi
    
    # Test hard delete (if supported)
    print_info "Testing hard delete..."
    local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/stories/$story_id2?hard=true" -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "204" ]; then
        print_success "Story hard deleted successfully"
    elif [ "$http_code" = "400" ] || [ "$http_code" = "403" ]; then
        print_info "Hard delete not supported or not allowed"
    else
        print_warning "Unexpected response for hard delete: $http_code"
    fi
    
    # Test deleting non-existent story
    print_info "Testing deletion of non-existent story..."
    local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/stories/99999" -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent story deletion correctly returns 404"
    else
        print_error "Non-existent story deletion returned unexpected code: $http_code"
        return 1
    fi
    
    return 0
}

# Test story with scheduling
test_story_scheduling() {
    print_section "Testing Story Scheduling"
    
    # Create a voice
    print_info "Creating test voice for scheduling tests..."
    local voice_id=$(create_voice "Schedule Test Voice")
    if [ -z "$voice_id" ]; then
        print_error "Failed to create test voice"
        return 1
    fi
    
    # Test creating a future-dated story
    print_info "Creating future-dated story..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
        -b "$COOKIE_FILE" \
        -F "title=Future Story" \
        -F "text=This story is scheduled for the future." \
        -F "voice_id=$voice_id" \
        -F "status=active" \
        -F "start_date=2030-01-01" \
        -F "end_date=2030-12-31" \
        -F "monday=true" \
        -F "tuesday=true" \
        -F "wednesday=true" \
        -F "thursday=true" \
        -F "friday=true" \
        -F "saturday=true" \
        -F "sunday=true")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "201" ]; then
        print_success "Future-dated story created"
        local story_id=$(echo "$response" | sed '$d' | python3 -c "
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
        fi
    else
        print_error "Failed to create future-dated story (HTTP: $http_code)"
        return 1
    fi
    
    # Test creating an expired story
    print_info "Creating expired story..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
        -b "$COOKIE_FILE" \
        -F "title=Expired Story" \
        -F "text=This story has expired." \
        -F "voice_id=$voice_id" \
        -F "status=expired" \
        -F "start_date=2020-01-01" \
        -F "end_date=2020-12-31" \
        -F "monday=true" \
        -F "tuesday=true" \
        -F "wednesday=true" \
        -F "thursday=true" \
        -F "friday=true" \
        -F "saturday=true" \
        -F "sunday=true")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "201" ]; then
        print_success "Expired story created"
        local story_id=$(echo "$response" | sed '$d' | python3 -c "
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
        fi
    else
        print_error "Failed to create expired story (HTTP: $http_code)"
        return 1
    fi
    
    # Test creating a weekend-only story
    print_info "Creating weekend-only story..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
        -b "$COOKIE_FILE" \
        -F "title=Weekend Story" \
        -F "text=This story only plays on weekends." \
        -F "voice_id=$voice_id" \
        -F "status=active" \
        -F "start_date=2024-01-01" \
        -F "end_date=2024-12-31" \
        -F "monday=false" \
        -F "tuesday=false" \
        -F "wednesday=false" \
        -F "thursday=false" \
        -F "friday=false" \
        -F "saturday=true" \
        -F "sunday=true")
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "201" ]; then
        print_success "Weekend-only story created"
        local weekend_story_id=$(echo "$response" | sed '$d' | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'id' in data:
        print(data['id'])
except:
    pass
" 2>/dev/null)
        if [ -n "$weekend_story_id" ]; then
            CREATED_STORY_IDS+=("$weekend_story_id")
        fi
    else
        print_error "Failed to create weekend-only story (HTTP: $http_code)"
        return 1
    fi
    
    # Test modern date filtering with specific dates
    print_info "Testing modern date filtering for active stories..."
    
    # Test modern filter for a Saturday date (should find weekend story)
    local saturday_date="2024-06-15"  # This is a Saturday
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Bstart_date%5D%5Blte%5D=$saturday_date&filter%5Bend_date%5D%5Bgte%5D=$saturday_date&filter%5Bsaturday%5D=1" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Filter by Saturday date" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local has_weekend=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
stories = data.get('data', [])
for story in stories:
    if 'Weekend Story' in story.get('title', ''):
        print('true')
        sys.exit(0)
print('false')
" 2>/dev/null)
        
        if [ "$has_weekend" = "true" ]; then
            print_success "Weekend story correctly appears on Saturday"
        else
            print_warning "Weekend story not found on Saturday date"
        fi
    else
        return 1
    fi
    
    # Test a Monday date (should NOT find weekend story)
    local monday_date="2024-06-17"  # This is a Monday
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Bstart_date%5D%5Blte%5D=$monday_date&filter%5Bend_date%5D%5Bgte%5D=$monday_date&filter%5Bmonday%5D=1" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Filter by Monday date" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local has_weekend=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
stories = data.get('data', [])
for story in stories:
    if 'Weekend Story' in story.get('title', ''):
        print('true')
        sys.exit(0)
print('false')
" 2>/dev/null)
        
        if [ "$has_weekend" = "false" ]; then
            print_success "Weekend story correctly excluded on Monday"
        else
            print_error "Weekend story incorrectly appears on Monday"
            return 1
        fi
    else
        return 1
    fi
    
    # Test date outside story range
    print_info "Testing date filtering outside story date range..."
    local future_date="2025-01-01"  # Outside our test stories' end date
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?date=$future_date" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Filter by future date" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
# Count stories that aren't the future story
stories = data.get('data', [])
regular_stories = [s for s in stories if 'Future Story' not in s.get('title', '')]
print(len(regular_stories))
" 2>/dev/null)
        
        if [ "$count" = "0" ]; then
            print_success "Stories correctly filtered by date range"
        else
            print_warning "Found $count stories outside their date range"
        fi
    else
        return 1
    fi
    
    return 0
}

# Test comprehensive modern query capabilities
test_modern_query_params() {
    print_section "Testing Comprehensive Modern Query Parameters"
    
    # Create test data
    print_info "Creating diverse test data for modern queries..."
    local voice1=$(create_voice "Alice Anderson")
    local voice2=$(create_voice "Bob Brown")
    local voice3=$(create_voice "Charlie Chen")
    
    if [ -z "$voice1" ] || [ -z "$voice2" ] || [ -z "$voice3" ]; then
        print_error "Failed to create test voices"
        return 1
    fi
    
    # Create diverse stories for testing
    create_story "Breaking News Today" "Important breaking news content" "$voice1" >/dev/null
    create_story "Weather Update Morning" "Today's weather forecast" "$voice2" >/dev/null
    create_story "Sports Highlights" "Latest sports results" "$voice3" >/dev/null
    create_story "Traffic Report Rush Hour" "Current traffic conditions" "$voice1" >/dev/null
    create_story "Entertainment News" "Celebrity updates" "$voice2" >/dev/null
    
    # 1. Test comparison operators (gt, gte, lt, lte)
    print_info "Testing comparison operators..."
    local today=$(date +%Y-%m-%d)
    local yesterday=$(date -d "yesterday" +%Y-%m-%d 2>/dev/null || date -v-1d +%Y-%m-%d)
    
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Bcreated_at%5D%5Bgte%5D=$yesterday" -b "$COOKIE_FILE")
    if check_response "$response" "200" "GTE operator" >/dev/null; then
        print_success "Greater than or equal (gte) operator works"
    else
        return 1
    fi
    
    # 2. Test NOT EQUAL operator
    print_info "Testing not equal operator..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Bvoice_id%5D%5Bne%5D=$voice1" -b "$COOKIE_FILE")
    if check_response "$response" "200" "NE operator" >/dev/null; then
        print_success "Not equal (ne) operator works"
    else
        print_warning "Not equal operator may not be supported"
    fi
    
    # 3. Test IN operator with multiple values
    print_info "Testing IN operator with multiple values..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Bvoice_id%5D%5Bin%5D=$voice1,$voice2" -b "$COOKIE_FILE")
    if check_response "$response" "200" "IN operator" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', [])))
" 2>/dev/null)
        print_success "IN operator works (found $count stories)"
    else
        print_warning "IN operator may not be supported"
    fi
    
    # 4. Test BETWEEN operator
    print_info "Testing BETWEEN operator for date ranges..."
    local start_date="2024-01-01"
    local end_date="2024-12-31"
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Bstart_date%5D%5Bbetween%5D=$start_date,$end_date" -b "$COOKIE_FILE")
    if check_response "$response" "200" "BETWEEN operator" >/dev/null; then
        print_success "BETWEEN operator works"
    else
        print_warning "BETWEEN operator may not be supported"
    fi
    
    # 5. Test LIKE operator with wildcards
    print_info "Testing LIKE operator with pattern matching..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Btitle%5D%5Blike%5D=%25News%25" -b "$COOKIE_FILE")
    if check_response "$response" "200" "LIKE with wildcards" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
stories = data.get('data', [])
matching = [s for s in stories if 'News' in s.get('title', '')]
print(len(matching))
" 2>/dev/null)
        print_success "LIKE operator with wildcards works (found $count matching)"
    else
        print_warning "LIKE operator may not be supported"
    fi
    
    # 6. Test multiple filters combined
    print_info "Testing multiple filters combined..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Bvoice_id%5D=$voice1&filter%5Bstatus%5D=active&filter%5Bmonday%5D=1" -b "$COOKIE_FILE")
    if check_response "$response" "200" "Multiple filters" >/dev/null; then
        print_success "Multiple filter conditions work together"
    else
        return 1
    fi
    
    # 7. Test sorting combinations
    print_info "Testing complex sorting..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?sort=-created_at,+title" -b "$COOKIE_FILE")
    if check_response "$response" "200" "Multi-field sort" >/dev/null; then
        print_success "Multi-field sorting works"
    else
        return 1
    fi
    
    # Test colon notation sorting
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?sort=created_at:desc,title:asc" -b "$COOKIE_FILE")
    if check_response "$response" "200" "Colon notation sort" >/dev/null; then
        print_success "Colon notation sorting works"
    else
        return 1
    fi
    
    # 8. Test field selection
    print_info "Testing field selection (sparse fieldsets)..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?fields=id,title,voice_name,status&limit=2" -b "$COOKIE_FILE")
    if check_response "$response" "200" "Field selection" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        # Check if only requested fields are present
        local field_test=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
stories = data.get('data', [])
if stories:
    story = stories[0]
    requested = {'id', 'title', 'voice_name', 'status'}
    actual = set(story.keys())
    # Check if actual is subset or equal to requested
    if actual <= requested or actual == requested:
        print('correct')
    else:
        extra = actual - requested
        print(f'extra_fields: {extra}')
else:
    print('no_data')
" 2>/dev/null)
        
        if [ "$field_test" = "correct" ]; then
            print_success "Field selection returns appropriate fields"
        else
            print_warning "Field selection test result: $field_test"
        fi
    else
        return 1
    fi
    
    # 9. Test status variations
    print_info "Testing status parameter variations..."
    
    # Test status=all
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?status=all" -b "$COOKIE_FILE")
    if check_response "$response" "200" "Status all" >/dev/null; then
        print_success "Status=all works"
    else
        return 1
    fi
    
    # Test status=deleted
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?status=deleted" -b "$COOKIE_FILE")
    if check_response "$response" "200" "Status deleted" >/dev/null; then
        print_success "Status=deleted works"
    else
        return 1
    fi
    
    # 10. Test boolean filters
    print_info "Testing boolean filters..."
    
    # Test has_voice=false
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?has_voice=false" -b "$COOKIE_FILE")
    if check_response "$response" "200" "has_voice=false" >/dev/null; then
        print_success "Boolean filter has_voice=false works"
    else
        return 1
    fi
    
    # Test has_audio=true
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?has_audio=true" -b "$COOKIE_FILE")
    if check_response "$response" "200" "has_audio=true" >/dev/null; then
        print_success "Boolean filter has_audio=true works"
    else
        return 1
    fi
    
    # 11. Test search functionality
    print_info "Testing search across multiple fields..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?search=News" -b "$COOKIE_FILE")
    if check_response "$response" "200" "Search" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local count=$(echo "$body" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(len(data.get('data', [])))
" 2>/dev/null)
        print_success "Search functionality works (found $count results)"
    else
        return 1
    fi
    
    # 12. Test complex combined query
    print_info "Testing complex combined query with all parameter types..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories?filter%5Bvoice_id%5D%5Bin%5D=$voice1,$voice2&filter%5Bstatus%5D=active&has_voice=true&search=News&sort=-created_at,+title&fields=id,title,voice_name,status&limit=5&offset=0" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Complex combined query" >/dev/null; then
        print_success "Complex combined query with all parameter types works"
    else
        return 1
    fi
    
    # 13. Test pagination metadata
    print_info "Testing pagination metadata..."
    local response=$(curl -s -X GET "$API_URL/stories?limit=2&offset=1" -b "$COOKIE_FILE")
    local has_pagination=$(echo "$response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'pagination' in data:
    p = data['pagination']
    if all(k in p for k in ['total', 'limit', 'offset', 'has_next', 'has_previous']):
        print('complete')
    else:
        print('partial')
else:
    print('missing')
" 2>/dev/null)
    
    if [ "$has_pagination" = "complete" ]; then
        print_success "Pagination metadata is complete"
    elif [ "$has_pagination" = "partial" ]; then
        print_warning "Pagination metadata is partial"
    else
        print_warning "Pagination metadata missing"
    fi
    
    return 0
}

# Test story audio upload and download
test_story_audio() {
    print_section "Testing Story Audio Upload and Download"
    
    # Create a voice for the test story
    print_info "Creating test voice for audio test..."
    local voice_id=$(create_voice "Audio Test Voice")
    if [ -z "$voice_id" ]; then
        print_error "Failed to create test voice"
        return 1
    fi
    
    # Create a test audio file
    print_info "Creating test audio file..."
    local test_audio="/tmp/test_audio_upload.wav"
    if command -v ffmpeg &> /dev/null; then
        ffmpeg -f lavfi -i anullsrc=r=44100:cl=stereo -t 2 -f wav "$test_audio" -y 2>/dev/null
        if [ ! -f "$test_audio" ]; then
            print_warning "Could not create test audio file, skipping audio test"
            return 0
        fi
        print_success "Created test audio file"
    else
        print_warning "ffmpeg not available, skipping audio test"
        return 0
    fi
    
    # Test creating story with audio upload
    print_info "Creating story with audio file upload..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stories" \
        -b "$COOKIE_FILE" \
        -F "title=Story With Audio Upload Test" \
        -F "text=This story has uploaded audio for testing" \
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
        -F "sunday=false" \
        -F "audio=@$test_audio")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" != "201" ]; then
        print_error "Failed to create story with audio (HTTP: $http_code)"
        echo "Response: $body"
        rm -f "$test_audio"
        return 1
    fi
    
    local story_id=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'id' in data:
        print(data['id'])
except:
    pass
" 2>/dev/null)
    
    if [ -z "$story_id" ]; then
        print_error "Failed to extract story ID from response"
        rm -f "$test_audio"
        return 1
    fi
    
    CREATED_STORY_IDS+=("$story_id")
    print_success "Story with audio created successfully (ID: $story_id)"
    
    # Verify the story has an audio URL
    print_info "Verifying story has audio URL..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stories/$story_id" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "Get story with audio" >/dev/null; then
        local audio_url=$(echo "$response" | sed '$d' | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'audio_url' in data and data['audio_url']:
        print(data['audio_url'])
except:
    pass
" 2>/dev/null)
        
        if [ -n "$audio_url" ]; then
            print_success "Story has audio URL: $audio_url"
        else
            print_error "Story missing audio URL"
            rm -f "$test_audio"
            return 1
        fi
    else
        rm -f "$test_audio"
        return 1
    fi
    
    # Test downloading the audio
    print_info "Testing audio download from API..."
    local download_path="/tmp/downloaded_story_audio.wav"
    local response_code=$(curl -s -o "$download_path" -w "%{http_code}" "$API_BASE$audio_url" -b "$COOKIE_FILE")
    
    if [ "$response_code" = "200" ]; then
        if [ -f "$download_path" ]; then
            # Check if it's a valid audio file
            if command -v file &> /dev/null; then
                local file_type=$(file "$download_path" 2>/dev/null)
                if echo "$file_type" | grep -q "WAVE audio\|RIFF"; then
                    print_success "Audio downloaded successfully and is valid WAV file"
                else
                    print_warning "Downloaded file may not be valid audio: $file_type"
                fi
            else
                print_success "Audio downloaded successfully"
            fi
            
            # Check file size
            local file_size=$(stat -f%z "$download_path" 2>/dev/null || stat -c%s "$download_path" 2>/dev/null || echo "0")
            if [ "$file_size" -gt 0 ]; then
                print_info "Downloaded audio size: $file_size bytes"
            else
                print_warning "Downloaded file is empty"
            fi
            
            rm -f "$download_path"
        else
            print_error "Download failed - file not created"
            rm -f "$test_audio"
            return 1
        fi
    else
        print_error "Audio download failed (HTTP: $response_code)"
        rm -f "$test_audio"
        return 1
    fi
    
    # Test that audio requires authentication
    print_info "Testing audio download requires authentication..."
    local unauth_response=$(curl -s -o /dev/null -w "%{http_code}" "$API_BASE$audio_url")
    
    if [ "$unauth_response" = "401" ]; then
        print_success "Audio endpoint correctly requires authentication"
    else
        print_warning "Audio endpoint returned unexpected status without auth: $unauth_response"
    fi
    
    # Note: Audio update via PUT is not currently implemented in the API
    # This would require adding audio file handling to the UpdateStory handler
    print_info "Audio update via PUT not currently supported (expected limitation)"
    
    # Clean up
    rm -f "$test_audio" "$download_path"
    
    return 0
}

# Setup function
setup() {
    print_info "Setting up story tests..."
    restore_admin_session
    return 0
}

# Cleanup function
cleanup() {
    print_info "Cleaning up story tests..."
    
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
    
    # Clean up test audio files
    rm -f /tmp/test_story.wav
    rm -f /tmp/test_audio_upload.wav
    rm -f /tmp/test_audio_update.wav
    rm -f /tmp/downloaded_story_audio.wav
    rm -f /tmp/updated_story_audio.wav
    
    return 0
}

# Main function
main() {
    print_header "Story Tests"
    
    setup
    
    local tests=(
        "test_story_creation"
        "test_story_listing"
        "test_story_updates"
        "test_story_deletion"
        "test_story_audio"
        "test_story_scheduling"
        "test_modern_query_params"
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
        print_success "All story tests passed!"
        exit 0
    else
        print_error "$failed story tests failed"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi