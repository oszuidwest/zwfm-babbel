#!/bin/bash

# Babbel Stations Tests - Setup
# Create test data for station tests

# Get the script directory and source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/auth.sh"
source "$SCRIPT_DIR/../lib/assertions.sh"

# Test station data
setup_stations() {
    print_section "Setting Up Test Stations"
    
    local stations=(
        "Test Station FM:5:2.0"
        "Radio Test:4:1.5"
        "Demo Station:3:2.5"
    )
    
    local created_ids=()
    
    for station in "${stations[@]}"; do
        IFS=':' read -r name max_stories pause_seconds <<< "$station"
        
        print_info "Creating station: $name"
        
        local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"$name\", \"max_stories_per_block\": $max_stories, \"pause_seconds\": $pause_seconds}")
        
        local station_id=$(check_response "$response" "201" "Create station $name")
        if [ -n "$station_id" ]; then
            created_ids+=("$station_id")
            print_success "Created station: $name (ID: $station_id, pause: ${pause_seconds}s)"
        else
            print_error "Failed to create station: $name"
            return 1
        fi
    done
    
    # Return created IDs
    IFS=',' eval 'echo "${created_ids[*]}"'
    return 0
}

# Get test stations
get_test_stations() {
    local response=$(curl -s -X GET "$API_URL/stations" -b "$COOKIE_FILE")
    local http_code=$?
    
    if [ $http_code -eq 0 ]; then
        echo "$response"
        return 0
    else
        return 1
    fi
}

# Main function for standalone execution
main() {
    setup_stations
}

# If script is run directly, execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi