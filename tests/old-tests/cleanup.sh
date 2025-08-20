#!/bin/bash

# Babbel Stations Tests - Cleanup
# Clean up test stations

# Get the script directory and source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/auth.sh"
source "$SCRIPT_DIR/../lib/assertions.sh"

# Clean up test stations
cleanup_stations() {
    print_section "Cleaning Up Test Stations"
    
    # Get all stations
    local response=$(curl -s -X GET "$API_URL/stations" -b "$COOKIE_FILE")
    if [ $? -ne 0 ]; then
        print_error "Could not retrieve stations for cleanup"
        return 1
    fi
    
    # Find stations with "Test" in the name and delete them
    echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'data' in data:
        for station in data['data']:
            name = station.get('name', '')
            if any(word in name for word in ['Test', 'Demo', 'CRUD', 'Unique', 'Updated', 'Patched']):
                print(f\"{station['id']}:{name}\")
except:
    pass
" | while IFS=':' read -r station_id station_name; do
        if [ -n "$station_id" ] && [ -n "$station_name" ]; then
            print_info "Deleting test station: $station_name (ID: $station_id)"
            
            local delete_response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/stations/$station_id" -b "$COOKIE_FILE")
            local http_code=$(echo "$delete_response" | tail -n1)
            
            if [ "$http_code" = "204" ]; then
                print_success "Deleted station: $station_name"
            else
                print_warning "Failed to delete station: $station_name (HTTP $http_code)"
            fi
        fi
    done
    
    print_success "Station cleanup completed"
    return 0
}

# Main function for standalone execution
main() {
    if ! restore_admin_session; then
        print_error "Could not establish admin session for cleanup"
        return 1
    fi
    
    cleanup_stations
}

# If script is run directly, execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi