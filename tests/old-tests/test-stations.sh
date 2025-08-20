#!/bin/bash

# Babbel Stations Tests
# Test station management functionality

# Get the script directory and source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/auth.sh"
source "$SCRIPT_DIR/../lib/assertions.sh"
source "$SCRIPT_DIR/setup.sh"

# Global variables for cleanup
CREATED_STATION_IDS=()

# Test creating stations
test_create_stations() {
    print_section "Testing Station Creation"
    
    local test_stations=(
        '{"name": "CRUD Test FM", "max_stories_per_block": 5, "pause_seconds": 2.0}'
        '{"name": "Another Test Station", "max_stories_per_block": 3, "pause_seconds": 1.5}'
        '{"name": "Validation Station", "max_stories_per_block": 10, "pause_seconds": 3.0}'
    )
    
    for station_data in "${test_stations[@]}"; do
        local name=$(echo "$station_data" | python3 -c "import sys, json; print(json.load(sys.stdin)['name'])")
        
        print_info "Creating station: $name"
        
        local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "$station_data")
        
        local station_id=$(check_response "$response" "201" "Create station $name")
        if [ -n "$station_id" ]; then
            CREATED_STATION_IDS+=("$station_id")
            print_success "Created station: $name (ID: $station_id)"
            
            # The API returns just {id, message}, so fetch the full station to verify
            print_info "Fetching created station to verify data..."
            local verify_response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations/$station_id" -b "$COOKIE_FILE")
            local verify_code=$(echo "$verify_response" | tail -n1)
            
            if [ "$verify_code" = "200" ]; then
                local station_data=$(echo "$verify_response" | sed '$d')
                assert_json_field_equals "$station_data" "name" "$name" "Station name"
                assert_json_field_equals "$station_data" "id" "$station_id" "Station ID"
                assert_json_field "$station_data" "created_at" "Created timestamp"
                assert_json_field "$station_data" "updated_at" "Updated timestamp"
            else
                print_warning "Could not verify created station data"
            fi
        else
            print_error "Failed to create station: $name"
            return 1
        fi
    done
    
    return 0
}

# Test reading stations
test_read_stations() {
    print_section "Testing Station Reading"
    
    # Test listing all stations
    print_info "Testing list all stations..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations" -b "$COOKIE_FILE")
    
    if check_response "$response" "200" "List all stations" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        assert_json_field "$body" "data" "Stations data array"
        
        local station_count=$(parse_json_nested "$body" "data" | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
        print_success "Listed stations (count: $station_count)"
        
        # Verify structure of first station
        local first_station=$(parse_json_nested "$body" "data.0")
        if [ -n "$first_station" ] && [ "$first_station" != "null" ]; then
            assert_json_field "$first_station" "id" "First station ID"
            assert_json_field "$first_station" "name" "First station name"
            assert_json_field "$first_station" "max_stories_per_block" "First station max stories"
            assert_json_field "$first_station" "pause_seconds" "First station pause seconds"
        fi
    else
        return 1
    fi
    
    # Test getting individual station
    if [ ${#CREATED_STATION_IDS[@]} -gt 0 ]; then
        local station_id="${CREATED_STATION_IDS[0]}"
        print_info "Testing get individual station (ID: $station_id)..."
        
        local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations/$station_id" -b "$COOKIE_FILE")
        
        if check_response "$response" "200" "Get individual station" >/dev/null; then
            local body=$(echo "$response" | sed '$d')
            assert_json_field_equals "$body" "id" "$station_id" "Station ID matches"
            assert_json_field "$body" "name" "Station name"
            print_success "Retrieved individual station"
        else
            return 1
        fi
    fi
    
    return 0
}

# Test updating stations
test_update_stations() {
    print_section "Testing Station Updates"
    
    if [ ${#CREATED_STATION_IDS[@]} -eq 0 ]; then
        print_error "No stations available for update testing"
        return 1
    fi
    
    local station_id="${CREATED_STATION_IDS[0]}"
    print_info "Using station ID: $station_id for update tests"
    
    # Test full update (PUT)
    print_info "Testing station full update (PUT)..."
    local update_data='{"name": "Updated Test Station", "max_stories_per_block": 7, "pause_seconds": 2.5}'
    
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/stations/$station_id" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "$update_data")
    
    if check_response "$response" "200" "Update station (PUT)" >/dev/null; then
        # The API returns just {message}, so fetch the station to verify update
        print_info "Fetching updated station to verify changes..."
        local verify_response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations/$station_id" -b "$COOKIE_FILE")
        local verify_code=$(echo "$verify_response" | tail -n1)
        
        if [ "$verify_code" = "200" ]; then
            local body=$(echo "$verify_response" | sed '$d')
            assert_json_field_equals "$body" "name" "Updated Test Station" "Updated name"
            assert_json_field_equals "$body" "max_stories_per_block" "7" "Updated max stories"
            assert_json_field_equals "$body" "pause_seconds" "2.5" "Updated pause seconds"
            print_success "Station updated successfully"
        else
            print_warning "Could not verify updated station data"
        fi
    else
        return 1
    fi
    
    # Note: Stations API doesn't have PATCH endpoint, only PUT
    # Test another full update to ensure it still works
    print_info "Testing station second update (PUT)..."
    local patch_data='{"name": "Second Update Station", "max_stories_per_block": 8, "pause_seconds": 3.0}'
    
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/stations/$station_id" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "$patch_data")
    
    if check_response "$response" "200" "Second update station (PUT)" >/dev/null; then
        # The API returns just {message}, so fetch the station to verify patch
        print_info "Fetching patched station to verify changes..."
        local verify_response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations/$station_id" -b "$COOKIE_FILE")
        local verify_code=$(echo "$verify_response" | tail -n1)
        
        if [ "$verify_code" = "200" ]; then
            local body=$(echo "$verify_response" | sed '$d')
            assert_json_field_equals "$body" "name" "Second Update Station" "Updated name"
            assert_json_field_equals "$body" "max_stories_per_block" "8" "Updated max stories"
            assert_json_field_equals "$body" "pause_seconds" "3" "Updated pause seconds"
            print_success "Station patched successfully"
        else
            print_warning "Could not verify patched station data"
        fi
    else
        return 1
    fi
    
    return 0
}

# Test station validation
test_station_validation() {
    print_section "Testing Station Validation"
    
    local validation_tests=(
        '{}:Missing required fields'
        '{"name": ""}:Empty name'
        '{"name": "Test", "max_stories_per_block": -1}:Negative max stories'
        '{"name": "Test", "max_stories_per_block": 0}:Zero max stories'
        '{"name": "Test", "max_stories_per_block": 5, "pause_seconds": -1}:Negative pause seconds'
        '{"name": "Test", "max_stories_per_block": 5, "pause_seconds": "invalid"}:Invalid pause seconds type'
    )
    
    for test_case in "${validation_tests[@]}"; do
        IFS=':' read -r data description <<< "$test_case"
        
        print_info "Testing validation: $description"
        
        local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "$data")
        
        local http_code=$(echo "$response" | tail -n1)
        if assert_http_error "$http_code" "Validation: $description"; then
            print_success "Validation correctly rejected: $description"
        else
            print_error "Validation should have rejected: $description"
        fi
    done
    
    return 0
}

# Test station deletion
test_delete_stations() {
    print_section "Testing Station Deletion"
    
    if [ ${#CREATED_STATION_IDS[@]} -eq 0 ]; then
        print_error "No stations available for deletion testing"
        return 1
    fi
    
    # Delete the last created station
    print_info "Available station IDs for deletion: ${CREATED_STATION_IDS[@]}"
    # Get last element (bash 3.x compatible)
    local last_index=$((${#CREATED_STATION_IDS[@]} - 1))
    local station_id="${CREATED_STATION_IDS[$last_index]}"
    
    if [ -z "$station_id" ]; then
        print_error "No valid station ID for deletion test"
        return 1
    fi
    
    print_info "Testing station deletion (ID: $station_id)..."
    
    local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/stations/$station_id" -b "$COOKIE_FILE")
    
    if check_response "$response" "204" "Delete station" >/dev/null; then
        print_success "Station deleted successfully"
        
        # Verify station is no longer accessible
        print_info "Verifying station is deleted..."
        local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/stations/$station_id" -b "$COOKIE_FILE")
        local http_code=$(echo "$response" | tail -n1)
        
        if assert_status_code "$http_code" "404" "Get deleted station"; then
            print_success "Deleted station correctly returns 404"
        else
            print_error "Deleted station still accessible"
            return 1
        fi
        
        # Remove from our tracking array
        CREATED_STATION_IDS=("${CREATED_STATION_IDS[@]:0:$((${#CREATED_STATION_IDS[@]}-1))}")
        
    else
        return 1
    fi
    
    return 0
}

# Test station duplicate names
test_duplicate_names() {
    print_section "Testing Duplicate Station Names"
    
    local station_name="Unique Test Station"
    
    # Create first station
    print_info "Creating first station with name: $station_name"
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$station_name\", \"max_stories_per_block\": 5, \"pause_seconds\": 2.0}")
    
    local first_id=$(check_response "$response" "201" "Create first station")
    if [ -n "$first_id" ]; then
        CREATED_STATION_IDS+=("$first_id")
        print_success "Created first station (ID: $first_id)"
    else
        print_error "Failed to create first station"
        return 1
    fi
    
    # Try to create second station with same name
    print_info "Attempting to create duplicate station..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$station_name\", \"max_stories_per_block\": 3, \"pause_seconds\": 1.5}")
    
    local http_code=$(echo "$response" | tail -n1)
    if assert_http_error "$http_code" "Duplicate station name"; then
        print_success "Duplicate station name correctly rejected"
    else
        print_error "Duplicate station name unexpectedly accepted"
        return 1
    fi
    
    return 0
}

# Setup function
setup() {
    print_info "Setting up station tests..."
    # Ensure we're logged in as admin
    if ! restore_admin_session; then
        print_error "Could not establish admin session"
        return 1
    fi
    return 0
}

# Cleanup function  
cleanup() {
    print_info "Cleaning up station tests..."
    
    # Delete all created stations
    for station_id in "${CREATED_STATION_IDS[@]}"; do
        if [ -n "$station_id" ]; then
            curl -s -X DELETE "$API_URL/stations/$station_id" -b "$COOKIE_FILE" >/dev/null 2>&1
            print_info "Cleaned up station: $station_id"
        fi
    done
    
    CREATED_STATION_IDS=()
    return 0
}

# Main function
main() {
    print_header "Station Tests"
    
    setup
    
    local tests=(
        "test_create_stations"
        "test_read_stations"
        "test_update_stations"
        "test_station_validation"
        "test_duplicate_names"
        "test_delete_stations"
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
        print_success "All station tests passed!"
        exit 0
    else
        print_error "$failed station tests failed"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi