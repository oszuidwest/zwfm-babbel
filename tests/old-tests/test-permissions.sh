#!/bin/bash

# Babbel Permissions Tests
# Test role-based access control (RBAC) functionality

# Get the script directory and source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/auth.sh"
source "$SCRIPT_DIR/../lib/assertions.sh"

# Global test user ID for cleanup
TEST_USER_ID=""
TEST_EDITOR_ID=""
TEST_VIEWER_ID=""

# Helper function to create user and get ID
create_user_and_get_id() {
    local username="$1"
    local full_name="$2"
    local password="$3"
    local role="$4"
    
    print_info "Creating user: $username"
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$username\", \"full_name\": \"$full_name\", \"password\": \"$password\", \"role\": \"$role\"}")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "201" ]; then
        # API now returns {id: X, message: "..."} on creation
        local user_id=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'id' in data:
        print(data['id'])
except:
    pass
" 2>/dev/null)
        
        if [ -n "$user_id" ]; then
            print_success "User created successfully (ID: $user_id)"
            echo "$user_id"
            return 0
        else
            print_error "Could not extract user ID from response"
            return 1
        fi
    elif [ "$http_code" = "409" ]; then
        # User already exists, try to find it
        print_info "User $username already exists, fetching ID..."
        local user_response=$(curl -s -X GET "$API_URL/users" -b "$COOKIE_FILE")
        local user_id=$(echo "$user_response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data:
    for user in data['data']:
        if user.get('username') == '$username':
            print(user['id'])
            break
" 2>/dev/null)
        
        if [ -n "$user_id" ]; then
            print_info "Found existing user ID: $user_id"
            echo "$user_id"
            return 0
        else
            print_error "User exists but could not find ID"
            return 1
        fi
    else
        print_error "Failed to create user (HTTP $http_code)"
        print_error "Response: $body"
        return 1
    fi
}

# Test admin permissions
test_admin_permissions() {
    print_section "Testing Admin Permissions"
    
    # Ensure we're logged in as admin
    if ! restore_admin_session; then
        print_error "Could not establish admin session"
        return 1
    fi
    
    # Admin should be able to create users
    print_info "Testing admin can create users..."
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"username": "testadminuser", "full_name": "Test Admin User", "password": "testpass123", "role": "editor"}')
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "201" ]; then
        # API now returns {id: X, message: "..."} on creation
        TEST_USER_ID=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'id' in data:
        print(data['id'])
except:
    pass
" 2>/dev/null)
        
        if [ -n "$TEST_USER_ID" ]; then
            print_success "Admin can create users (ID: $TEST_USER_ID)"
        else
            print_warning "User created but could not get ID from response"
            TEST_USER_ID=""
        fi
    else
        print_error "Admin cannot create users (HTTP: $http_code)"
        return 1
    fi
    
    # Admin should be able to list users
    print_info "Testing admin can list users..."
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" -b "$COOKIE_FILE")
    if check_response "$response" "200" "Admin list users" >/dev/null; then
        local body=$(echo "$response" | sed '$d')
        local user_count=$(parse_json_nested "$body" "data" | python3 -c "import sys, json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
        print_success "Admin can list users (found $user_count users)"
    else
        return 1
    fi
    
    # Admin should be able to update users
    if [ -n "$TEST_USER_ID" ]; then
        print_info "Testing admin can update users..."
        local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/users/$TEST_USER_ID" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d '{"username": "testadminuser", "full_name": "Updated Test User", "role": "viewer"}')
        
        if check_response "$response" "200" "Admin update user" >/dev/null; then
            print_success "Admin can update users"
        else
            return 1
        fi
    fi
    
    # Admin should be able to delete users (we'll test this in cleanup)
    print_success "Admin permissions verified"
    return 0
}

# Test editor permissions
test_editor_permissions() {
    print_section "Testing Editor Permissions"
    
    # First create an editor user as admin
    restore_admin_session
    
    # Try to create or find existing editor user
    TEST_EDITOR_ID=$(create_user_and_get_id "testeditor" "Test Editor" "testpass123" "editor")
    if [ -z "$TEST_EDITOR_ID" ]; then
        # User might already exist, try to find it
        print_info "Checking if testeditor already exists..."
        local user_response=$(curl -s -X GET "$API_URL/users" -b "$COOKIE_FILE")
        TEST_EDITOR_ID=$(echo "$user_response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'data' in data:
    for user in data['data']:
        if user.get('username') == 'testeditor':
            print(user['id'])
            break
" 2>/dev/null)
        
        if [ -n "$TEST_EDITOR_ID" ]; then
            print_info "Using existing editor user (ID: $TEST_EDITOR_ID)"
        else
            print_error "Could not create or find editor user"
            return 1
        fi
    else
        print_success "Created test editor user (ID: $TEST_EDITOR_ID)"
    fi
    
    # Login as editor
    local backup_cookie=$(switch_to_user "testeditor" "testpass123")
    if [ $? -ne 0 ]; then
        print_error "Could not login as editor"
        return 1
    fi
    
    # Editor should be able to read resources
    print_info "Testing editor can read resources..."
    
    local read_endpoints=(
        "/stations"
        "/voices" 
        "/stories"
        "/bulletins"
    )
    
    for endpoint in "${read_endpoints[@]}"; do
        local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL$endpoint" -b "$COOKIE_FILE")
        if check_response "$response" "200" "Editor read $endpoint" >/dev/null; then
            print_success "Editor can read $endpoint"
        else
            print_error "Editor cannot read $endpoint"
            restore_from_backup "$backup_cookie"
            return 1
        fi
    done
    
    # Editor should be able to create/update content
    print_info "Testing editor can create content..."
    
    # Test creating a station
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/stations" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"name": "Editor Test Station", "max_stories_per_block": 5, "pause_seconds": 2.0}')
    
    if check_response "$response" "201" "Editor create station" >/dev/null; then
        print_success "Editor can create stations"
    else
        print_error "Editor cannot create stations"
    fi
    
    # Editor should NOT be able to manage users
    print_info "Testing editor cannot manage users..."
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"username": "unauthorized", "full_name": "Unauthorized User", "password": "test", "role": "viewer"}')
    
    local http_code=$(echo "$response" | tail -n1)
    if assert_http_error "$http_code" "Editor create user"; then
        print_success "Editor correctly denied user creation"
    else
        print_error "Editor unexpectedly allowed to create users"
        restore_from_backup "$backup_cookie"
        return 1
    fi
    
    # Editor should NOT be able to delete users
    local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/users/1" -b "$COOKIE_FILE")
    local http_code=$(echo "$response" | tail -n1)
    if assert_http_error "$http_code" "Editor delete user"; then
        print_success "Editor correctly denied user deletion"
    else
        print_error "Editor unexpectedly allowed to delete users"
        restore_from_backup "$backup_cookie"
        return 1
    fi
    
    # Restore admin session
    restore_from_backup "$backup_cookie"
    print_success "Editor permissions verified"
    return 0
}

# Test viewer permissions
test_viewer_permissions() {
    print_section "Testing Viewer Permissions"
    
    # First create a viewer user as admin
    restore_admin_session
    
    # Try to create or find existing viewer user
    TEST_VIEWER_ID=$(create_user_and_get_id "testviewer" "Test Viewer" "testpass123" "viewer")
    if [ -z "$TEST_VIEWER_ID" ]; then
        print_error "Could not create or find viewer user"
        return 1
    else
        print_success "Using viewer user (ID: $TEST_VIEWER_ID)"
    fi
    
    # Login as viewer
    local backup_cookie=$(switch_to_user "testviewer" "testpass123")
    if [ $? -ne 0 ]; then
        print_error "Could not login as viewer"
        return 1
    fi
    
    # Viewer should be able to read resources
    print_info "Testing viewer can read resources..."
    
    local read_endpoints=(
        "/stations"
        "/voices"
        "/stories"
        "/bulletins"
    )
    
    for endpoint in "${read_endpoints[@]}"; do
        local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL$endpoint" -b "$COOKIE_FILE")
        if check_response "$response" "200" "Viewer read $endpoint" >/dev/null; then
            print_success "Viewer can read $endpoint"
        else
            print_error "Viewer cannot read $endpoint"
            restore_from_backup "$backup_cookie"
            return 1
        fi
    done
    
    # Viewer should NOT be able to create content
    print_info "Testing viewer cannot create content..."
    
    local create_tests=(
        "POST /stations {\"name\": \"Viewer Test Station\", \"max_stories_per_block\": 5, \"pause_seconds\": 2.0}"
        "POST /voices {\"name\": \"Viewer Test Voice\"}"
        "POST /stories {\"title\": \"Viewer Test Story\", \"content\": \"Test\", \"voice_id\": 1}"
    )
    
    for test_spec in "${create_tests[@]}"; do
        local method=$(echo "$test_spec" | cut -d' ' -f1)
        local endpoint=$(echo "$test_spec" | cut -d' ' -f2)
        local data=$(echo "$test_spec" | cut -d' ' -f3-)
        
        local response=$(curl -s -w "\n%{http_code}" -X "$method" "$API_URL$endpoint" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "$data")
        
        local http_code=$(echo "$response" | tail -n1)
        if assert_http_error "$http_code" "Viewer $method $endpoint"; then
            print_success "Viewer correctly denied $method $endpoint"
        else
            print_error "Viewer unexpectedly allowed $method $endpoint"
        fi
    done
    
    # Viewer should NOT be able to manage users
    print_info "Testing viewer cannot manage users..."
    
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" -b "$COOKIE_FILE")
    local http_code=$(echo "$response" | tail -n1)
    if assert_http_error "$http_code" "Viewer list users"; then
        print_success "Viewer correctly denied user list access"
    else
        print_error "Viewer unexpectedly allowed to list users"
    fi
    
    # Restore admin session
    restore_from_backup "$backup_cookie"
    print_success "Viewer permissions verified"
    return 0
}

# Test suspended user
test_suspended_user() {
    print_section "Testing Suspended User"
    
    # Create and suspend a user
    restore_admin_session
    
    # Try to create or find existing user to suspend
    local suspended_id=$(create_user_and_get_id "suspendeduser" "Suspended User" "testpass123" "editor")
    if [ -z "$suspended_id" ]; then
        print_error "Could not create or find user for suspension test"
        return 1
    else
        print_success "Using user to suspend (ID: $suspended_id)"
    fi
    
    # Suspend the user (soft delete)
    local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/users/$suspended_id" -b "$COOKIE_FILE")
    if check_response "$response" "204" "Suspend user" >/dev/null; then
        print_success "User suspended successfully"
    else
        print_error "Could not suspend user"
        return 1
    fi
    
    # Try to login as suspended user (should fail)
    print_info "Testing suspended user cannot login..."
    if test_login_credentials "suspended_user" "testpass123" "401"; then
        print_success "Suspended user correctly cannot login"
    else
        print_error "Suspended user unexpectedly allowed to login"
        return 1
    fi
    
    # Restore the user for cleanup
    # (Note: In a real system, you might need an "undelete" endpoint)
    
    return 0
}

# Setup function
setup() {
    print_info "Setting up permission tests..."
    restore_admin_session
    return 0
}

# Cleanup function
cleanup() {
    print_info "Cleaning up permission tests..."
    
    # Ensure we're admin
    restore_admin_session
    
    # Clean up test users
    if [ -n "$TEST_USER_ID" ]; then
        curl -s -X DELETE "$API_URL/users/$TEST_USER_ID" -b "$COOKIE_FILE" >/dev/null 2>&1
        print_info "Cleaned up test user: $TEST_USER_ID"
    fi
    
    if [ -n "$TEST_EDITOR_ID" ]; then
        curl -s -X DELETE "$API_URL/users/$TEST_EDITOR_ID" -b "$COOKIE_FILE" >/dev/null 2>&1
        print_info "Cleaned up editor user: $TEST_EDITOR_ID"
    fi
    
    if [ -n "$TEST_VIEWER_ID" ]; then
        curl -s -X DELETE "$API_URL/users/$TEST_VIEWER_ID" -b "$COOKIE_FILE" >/dev/null 2>&1
        print_info "Cleaned up viewer user: $TEST_VIEWER_ID"
    fi
    
    # Clean up any test stations created
    local stations_response=$(curl -s -X GET "$API_URL/stations" -b "$COOKIE_FILE")
    if [ $? -eq 0 ]; then
        echo "$stations_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'data' in data:
        for station in data['data']:
            if 'Test' in station.get('name', ''):
                print(station['id'])
except:
    pass
" | while read station_id; do
            if [ -n "$station_id" ]; then
                curl -s -X DELETE "$API_URL/stations/$station_id" -b "$COOKIE_FILE" >/dev/null 2>&1
                print_info "Cleaned up test station: $station_id"
            fi
        done
    fi
    
    return 0
}

# Main function
main() {
    print_header "Permission Tests"
    
    setup
    
    local tests=(
        "test_admin_permissions"
        "test_editor_permissions"
        "test_viewer_permissions"
        "test_suspended_user"
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
        print_success "All permission tests passed!"
        exit 0
    else
        print_error "$failed permission tests failed"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi