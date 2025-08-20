#!/bin/bash

# Babbel Users Tests
# Test user management functionality including CRUD operations, roles, permissions, and status management

# Get the script directory and source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/auth.sh"
source "$SCRIPT_DIR/../lib/assertions.sh"

# Global variables for tracking created resources
CREATED_USER_IDS=()
CREATED_USERNAMES=()

# Global variable to store last created user info
LAST_CREATED_USER_ID=""
LAST_CREATED_USERNAME=""

# Helper function to create a user and track its ID
create_user() {
    local username="$1"
    local full_name="$2"
    local password="$3"
    local email="$4"
    local role="$5"
    local metadata="$6"
    
    # Add timestamp to ensure uniqueness (alphanumeric only)
    local unique_username="${username}$(date +%s)$$"
    
    local json_data="{\"username\": \"$unique_username\", \"full_name\": \"$full_name\", \"password\": \"$password\", \"role\": \"$role\""
    
    if [ -n "$email" ]; then
        json_data="$json_data, \"email\": \"$email\""
    fi
    
    if [ -n "$metadata" ] && [ "$metadata" != "" ]; then
        json_data="$json_data, \"metadata\": $metadata"
    fi
    
    json_data="$json_data}"
    
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "$json_data")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "201" ]; then
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
            CREATED_USER_IDS+=("$user_id")
            CREATED_USERNAMES+=("$unique_username")
            # Store in global variables 
            LAST_CREATED_USER_ID="$user_id"
            LAST_CREATED_USERNAME="$unique_username"
            # Return the ID via echo for backward compatibility
            echo "$user_id"
            return 0
        fi
    else
        # Debug output for failures
        print_error "User creation failed - HTTP $http_code: $body"
    fi
    
    return 1
}

# Helper function to get user details
get_user() {
    local user_id="$1"
    
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users/$user_id" \
        -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
        echo "$body"
        return 0
    fi
    
    return 1
}

# Helper function to update user status (suspend/restore)
update_user_status() {
    local user_id="$1"
    local action="$2"  # suspend or restore
    
    local response=$(curl -s -w "\n%{http_code}" -X PATCH "$API_URL/users/$user_id" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d "{\"action\": \"$action\"}")
    
    local http_code=$(echo "$response" | tail -n1)
    
    # Accept either 200 or 204 as success
    [ "$http_code" = "200" ] || [ "$http_code" = "204" ]
}

# Test user creation
test_create_user() {
    print_info "Creating a new user"
    
    local timestamp=$(date +%s)$$
    local user_id=$(create_user "testuser" "Test User" "password123" "test${timestamp}@example.com" "viewer" "")
    
    if [ -n "$user_id" ] && [ "$user_id" -gt 0 ]; then
        print_success "User created with ID: $user_id"
        return 0
    else
        print_error "Failed to create user"
        return 1
    fi
}

# Test user creation with minimal data
test_create_user_minimal() {
    print_info "Creating user with minimal required data"
    
    local user_id=$(create_user "minimaluser" "Minimal User" "password456" "" "editor")
    
    if [ -n "$user_id" ] && [ "$user_id" -gt 0 ]; then
        print_success "Minimal user created with ID: $user_id"
        return 0
    else
        print_error "Failed to create minimal user"
        return 1
    fi
}

# Test user creation with different roles
test_create_users_different_roles() {
    print_info "Creating users with different roles"
    
    local timestamp=$(date +%s)$$
    local admin_id=$(create_user "adminuser" "Admin User" "adminpass123" "admin${timestamp}@example.com" "admin")
    local editor_id=$(create_user "editoruser" "Editor User" "editorpass123" "editor${timestamp}@example.com" "editor")
    local viewer_id=$(create_user "vieweruser" "Viewer User" "viewerpass123" "viewer${timestamp}@example.com" "viewer")
    
    local success=0
    
    if [ -n "$admin_id" ] && [ "$admin_id" -gt 0 ]; then
        print_success "Admin user created with ID: $admin_id"
        ((success++))
    else
        print_error "Failed to create admin user"
    fi
    
    if [ -n "$editor_id" ] && [ "$editor_id" -gt 0 ]; then
        print_success "Editor user created with ID: $editor_id"
        ((success++))
    else
        print_error "Failed to create editor user"
    fi
    
    if [ -n "$viewer_id" ] && [ "$viewer_id" -gt 0 ]; then
        print_success "Viewer user created with ID: $viewer_id"
        ((success++))
    else
        print_error "Failed to create viewer user"
    fi
    
    [ "$success" -eq 3 ]
}

# Test invalid user creation (validation errors)
test_create_user_validation_errors() {
    print_info "Testing user creation validation errors"
    
    local success=0
    
    # Test invalid username (too short)
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"username": "ab", "full_name": "Test", "password": "password123", "role": "viewer"}')
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "422" ]; then
        print_success "Username too short validation works (HTTP 422)"
        ((success++))
    else
        print_error "Expected 422 for short username, got $http_code"
    fi
    
    # Test invalid role
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"username": "testuser123", "full_name": "Test", "password": "password123", "role": "invalid"}')
    
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "422" ]; then
        print_success "Invalid role validation works (HTTP 422)"
        ((success++))
    else
        print_error "Expected 422 for invalid role, got $http_code"
    fi
    
    # Test weak password
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"username": "testuser456", "full_name": "Test", "password": "weak", "role": "viewer"}')
    
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "422" ]; then
        print_success "Weak password validation works (HTTP 422)"
        ((success++))
    else
        print_error "Expected 422 for weak password, got $http_code"
    fi
    
    # Test invalid email format
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"username": "testuser789", "full_name": "Test", "password": "password123", "email": "invalid-email", "role": "viewer"}')
    
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "422" ]; then
        print_success "Invalid email validation works (HTTP 422)"
        ((success++))
    else
        print_error "Expected 422 for invalid email, got $http_code"
    fi
    
    [ "$success" -eq 4 ]
}

# Test duplicate username/email
test_duplicate_user_constraints() {
    print_info "Testing duplicate username/email constraints"
    
    local success=0
    
    # Generate a unique timestamp for this test
    local timestamp=$(date +%s)$$
    local test_username="duplicatetest${timestamp}"
    local test_email="dup${timestamp}@example.com"
    
    # Create a user first with unique email to ensure success
    # Call create_user without subshell to preserve global variables
    create_user "duplicatetest" "Duplicate Test" "password123" "$test_email" "viewer"
    local user_id="$LAST_CREATED_USER_ID"
    
    if [ -n "$user_id" ] && [ "$user_id" -gt 0 ]; then
        # Use the LAST_CREATED_USERNAME which was set by create_user
        local created_username="$LAST_CREATED_USERNAME"
        
        # Try to create user with same username if we have one
        if [ -n "$created_username" ]; then
            local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
                -b "$COOKIE_FILE" \
                -H "Content-Type: application/json" \
                -d "{\"username\": \"$created_username\", \"full_name\": \"Duplicate\", \"password\": \"password123\", \"role\": \"viewer\"}")
        
            local http_code=$(echo "$response" | tail -n1)
            if [ "$http_code" = "409" ]; then
                print_success "Duplicate username constraint works (HTTP 409)"
                ((success++))
            else
                print_error "Expected 409 for duplicate username, got $http_code"
            fi
        else
            print_error "No username tracked for duplicate test"
        fi
        
        # Try to create user with same email
        local unique_user="uniqueuser$(date +%s)$$"
        response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/users" \
            -b "$COOKIE_FILE" \
            -H "Content-Type: application/json" \
            -d "{\"username\": \"$unique_user\", \"full_name\": \"Unique\", \"password\": \"password123\", \"email\": \"$test_email\", \"role\": \"viewer\"}")
        
        http_code=$(echo "$response" | tail -n1)
        if [ "$http_code" = "409" ]; then
            print_success "Duplicate email constraint works (HTTP 409)"
            ((success++))
        else
            print_error "Expected 409 for duplicate email, got $http_code"
        fi
        
        [ "$success" -eq 2 ]
    else
        print_error "Failed to create initial user for duplicate tests"
        return 1
    fi
}

# Test listing users
test_list_users() {
    print_info "Listing all users"
    
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" \
        -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
        local total=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('total', 0))
except:
    print(0)
" 2>/dev/null)
        
        if [ "$total" -gt 0 ]; then
            print_success "Users list retrieved with $total users"
            return 0
        else
            print_error "Users list is empty"
            return 1
        fi
    else
        print_error "Failed to list users (HTTP $http_code)"
        return 1
    fi
}

# Test listing users with role filter
test_list_users_role_filter() {
    print_info "Listing users with role filter"
    
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users?role=admin" \
        -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
        local admin_count=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    users = data.get('data', [])
    admin_users = [u for u in users if u.get('role') == 'admin']
    print(len(admin_users))
except:
    print(0)
" 2>/dev/null)
        
        print_success "Found $admin_count admin users"
        return 0
    else
        print_error "Failed to list users with role filter (HTTP $http_code)"
        return 1
    fi
}

# Test getting user by ID
test_get_user() {
    print_info "Getting user by ID"
    
    if [ ${#CREATED_USER_IDS[@]} -eq 0 ]; then
        print_error "No users created to test"
        return 1
    fi
    
    local user_id="${CREATED_USER_IDS[0]}"
    local user_data=$(get_user "$user_id")
    
    if [ -n "$user_data" ]; then
        local retrieved_id=$(echo "$user_data" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('id', ''))
except:
    pass
" 2>/dev/null)
        
        if [ "$retrieved_id" = "$user_id" ]; then
            print_success "User retrieved successfully with ID: $retrieved_id"
            return 0
        else
            print_error "Retrieved user ID mismatch"
            return 1
        fi
    else
        print_error "Failed to retrieve user"
        return 1
    fi
}

# Test getting non-existent user
test_get_nonexistent_user() {
    print_info "Getting non-existent user"
    
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users/99999" \
        -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent user returns 404"
        return 0
    else
        print_error "Expected 404 for non-existent user, got $http_code"
        return 1
    fi
}

# Test updating user
test_update_user() {
    print_info "Updating user information"
    
    if [ ${#CREATED_USER_IDS[@]} -eq 0 ]; then
        print_error "No users created to test"
        return 1
    fi
    
    local user_id="${CREATED_USER_IDS[0]}"
    
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/users/$user_id" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"full_name": "Updated Name", "role": "editor"}')
    
    local http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        # Verify the update
        local user_data=$(get_user "$user_id")
        local updated_name=$(echo "$user_data" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('full_name', ''))
except:
    pass
" 2>/dev/null)
        
        if [ "$updated_name" = "Updated Name" ]; then
            print_success "User updated successfully"
            return 0
        else
            print_error "User update not reflected"
            return 1
        fi
    else
        print_error "Failed to update user (HTTP $http_code)"
        return 1
    fi
}

# Test user suspension
test_suspend_user() {
    print_info "Suspending user"
    
    if [ ${#CREATED_USER_IDS[@]} -eq 0 ]; then
        print_error "No users created to test"
        return 1
    fi
    
    local user_id="${CREATED_USER_IDS[0]}"
    
    if update_user_status "$user_id" "suspend"; then
        # Verify suspension
        local user_data=$(get_user "$user_id")
        local suspended_at=$(echo "$user_data" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('suspended_at', ''))
except:
    pass
" 2>/dev/null)
        
        if [ -n "$suspended_at" ] && [ "$suspended_at" != "null" ]; then
            print_success "User suspended successfully"
            return 0
        else
            print_error "User suspension not reflected"
            return 1
        fi
    else
        print_error "Failed to suspend user"
        return 1
    fi
}

# Test user restoration
test_restore_user() {
    print_info "Restoring suspended user"
    
    if [ ${#CREATED_USER_IDS[@]} -eq 0 ]; then
        print_error "No users created to test"
        return 1
    fi
    
    local user_id="${CREATED_USER_IDS[0]}"
    
    # First ensure the user is suspended
    if ! update_user_status "$user_id" "suspend"; then
        print_warning "Could not suspend user before restore test"
    fi
    
    # Now restore the user
    if update_user_status "$user_id" "restore"; then
        # Verify restoration
        local user_data=$(get_user "$user_id")
        local suspended_at=$(echo "$user_data" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    val = data.get('suspended_at')
    if val is None:
        print('null')
    else:
        print(val)
except:
    print('error')
" 2>/dev/null)
        
        if [ "$suspended_at" = "null" ] || [ "$suspended_at" = "None" ]; then
            print_success "User restored successfully"
            return 0
        else
            print_error "User restoration not reflected (suspended_at: $suspended_at)"
            return 1
        fi
    else
        print_error "Failed to restore user"
        return 1
    fi
}

# Test user field validation
test_user_field_validation() {
    print_info "Testing user field validation"
    
    if [ ${#CREATED_USER_IDS[@]} -eq 0 ]; then
        print_error "No users created to test"
        return 1
    fi
    
    local user_id="${CREATED_USER_IDS[0]}"
    local success=0
    
    # Test empty update (should fail)
    local response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/users/$user_id" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{}')
    
    local http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "400" ]; then
        print_success "Empty update validation works (HTTP 400)"
        ((success++))
    else
        print_error "Expected 400 for empty update, got $http_code"
    fi
    
    # Test invalid email in update
    response=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/users/$user_id" \
        -b "$COOKIE_FILE" \
        -H "Content-Type: application/json" \
        -d '{"email": "invalid-email-format"}')
    
    http_code=$(echo "$response" | tail -n1)
    if [ "$http_code" = "422" ]; then
        print_success "Invalid email update validation works (HTTP 422)"
        ((success++))
    else
        print_error "Expected 422 for invalid email update, got $http_code"
    fi
    
    [ "$success" -eq 2 ]
}

# Test deleting user
test_delete_user() {
    print_info "Deleting user"
    
    # Create a dedicated user for deletion
    local timestamp=$(date +%s)$$
    local user_id=$(create_user "deletetest" "Delete Test" "password123" "delete${timestamp}@example.com" "viewer")
    
    if [ -n "$user_id" ] && [ "$user_id" -gt 0 ]; then
        local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/users/$user_id" \
            -b "$COOKIE_FILE")
        
        local http_code=$(echo "$response" | tail -n1)
        
        if [ "$http_code" = "204" ]; then
            # Verify deletion
            local verify_response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users/$user_id" \
                -b "$COOKIE_FILE")
            
            local verify_code=$(echo "$verify_response" | tail -n1)
            
            if [ "$verify_code" = "404" ]; then
                print_success "User deleted successfully"
                # Remove from tracking array since it's deleted
                CREATED_USER_IDS=("${CREATED_USER_IDS[@]/$user_id}")
                return 0
            else
                print_error "User still exists after deletion"
                return 1
            fi
        else
            print_error "Failed to delete user (HTTP $http_code)"
            return 1
        fi
    else
        print_error "Failed to create user for deletion test"
        return 1
    fi
}

# Test deleting non-existent user
test_delete_nonexistent_user() {
    print_info "Deleting non-existent user"
    
    local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/users/99999" \
        -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "404" ]; then
        print_success "Non-existent user deletion returns 404"
        return 0
    else
        print_error "Expected 404 for non-existent user deletion, got $http_code"
        return 1
    fi
}

# Test last admin deletion protection
test_last_admin_protection() {
    print_info "Testing last admin deletion protection"
    
    # First, count how many admin users exist
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users?role=admin" \
        -b "$COOKIE_FILE")
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" = "200" ]; then
        local admin_count=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    users = data.get('data', [])
    print(len(users))
except:
    print(0)
" 2>/dev/null)
        
        # If there's more than one admin, delete all but one to test protection
        if [ "$admin_count" -gt 1 ]; then
            print_info "Found $admin_count admins, reducing to 1 for test"
            
            # Get all admin IDs
            local admin_ids=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    users = data.get('data', [])
    # Skip the first one to keep it
    for user in users[1:]:
        print(user.get('id', ''))
except:
    pass
" 2>/dev/null)
            
            # Delete extra admins
            for admin_id in $admin_ids; do
                if [ -n "$admin_id" ]; then
                    curl -s -X DELETE "$API_URL/users/$admin_id" -b "$COOKIE_FILE" > /dev/null 2>&1
                fi
            done
        fi
        
        # Now get the last remaining admin
        response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users?role=admin" \
            -b "$COOKIE_FILE")
        
        http_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | sed '$d')
        
        local admin_id=$(echo "$body" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    users = data.get('data', [])
    if users:
        print(users[0].get('id', ''))
except:
    pass
" 2>/dev/null)
        
        if [ -n "$admin_id" ]; then
            # Try to delete the last admin
            local delete_response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/users/$admin_id" \
                -b "$COOKIE_FILE")
            
            local delete_code=$(echo "$delete_response" | tail -n1)
            
            if [ "$delete_code" = "409" ]; then
                print_success "Last admin deletion protection works (HTTP 409)"
                return 0
            else
                print_error "Expected 409 for last admin deletion, got $delete_code"
                return 1
            fi
        else
            print_error "Could not find admin user"
            return 1
        fi
    else
        print_error "Failed to list admin users"
        return 1
    fi
}

# Test password security (password not in responses)
test_password_security() {
    print_info "Testing password security in responses"
    
    if [ ${#CREATED_USER_IDS[@]} -eq 0 ]; then
        print_error "No users created to test"
        return 1
    fi
    
    local user_id="${CREATED_USER_IDS[0]}"
    local user_data=$(get_user "$user_id")
    
    if [ -n "$user_data" ]; then
        local has_password=$(echo "$user_data" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'password' in data or 'password_hash' in data:
        print('true')
    else:
        print('false')
except:
    print('false')
" 2>/dev/null)
        
        if [ "$has_password" = "false" ]; then
            print_success "Password/hash not exposed in user response"
            return 0
        else
            print_error "Password/hash exposed in user response - security issue!"
            return 1
        fi
    else
        print_error "Failed to retrieve user for password security test"
        return 1
    fi
}

# Test authentication fields presence
test_authentication_fields() {
    print_info "Testing authentication-related fields presence"
    
    if [ ${#CREATED_USER_IDS[@]} -eq 0 ]; then
        print_error "No users created to test"
        return 1
    fi
    
    local user_id="${CREATED_USER_IDS[0]}"
    local user_data=$(get_user "$user_id")
    
    if [ -n "$user_data" ]; then
        local has_auth_fields=$(echo "$user_data" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    required_fields = ['login_count', 'failed_login_attempts', 'last_login_at', 'locked_until', 'password_changed_at']
    missing_fields = [field for field in required_fields if field not in data]
    if not missing_fields:
        print('true')
    else:
        print('false')
        print('Missing fields: ' + ', '.join(missing_fields), file=sys.stderr)
except Exception as e:
    print('false')
    print(f'Error: {e}', file=sys.stderr)
" 2>/dev/null)
        
        if [ "$has_auth_fields" = "true" ]; then
            print_success "All authentication fields present in response"
            return 0
        else
            print_error "Missing authentication fields in response"
            return 1
        fi
    else
        print_error "Failed to retrieve user for authentication fields test"
        return 1
    fi
}

# Cleanup function
cleanup_users() {
    print_section "Cleaning up created users"
    
    local cleanup_count=0
    
    for user_id in "${CREATED_USER_IDS[@]}"; do
        if [ -n "$user_id" ]; then
            local response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/users/$user_id" \
                -b "$COOKIE_FILE")
            
            local http_code=$(echo "$response" | tail -n1)
            
            if [ "$http_code" = "204" ] || [ "$http_code" = "404" ]; then
                ((cleanup_count++))
            else
                print_warning "Failed to cleanup user $user_id (HTTP $http_code)"
            fi
        fi
    done
    
    print_info "Cleaned up $cleanup_count users"
    CREATED_USER_IDS=()
    CREATED_USERNAMES=()
}

# Main test runner
main() {
    print_header "Babbel Users API Tests"
    
    # Ensure we're logged in as admin
    if ! api_login; then
        print_error "Failed to authenticate as admin"
        exit 1
    fi
    
    # Track test results
    local tests_passed=0
    local tests_failed=0
    
    # Test functions array
    declare -a test_functions=(
        "test_create_user"
        "test_create_user_minimal"
        "test_create_users_different_roles"
        "test_create_user_validation_errors"
        "test_duplicate_user_constraints"
        "test_list_users"
        "test_list_users_role_filter"
        "test_get_user"
        "test_get_nonexistent_user"
        "test_update_user"
        "test_suspend_user"
        "test_restore_user"
        "test_user_field_validation"
        "test_delete_user"
        "test_delete_nonexistent_user"
        "test_last_admin_protection"
        "test_password_security"
        "test_authentication_fields"
    )
    
    # Run all tests
    for test_func in "${test_functions[@]}"; do
        if $test_func; then
            ((tests_passed++))
        else
            ((tests_failed++))
        fi
        echo  # Add spacing between tests
    done
    
    # Cleanup
    cleanup_users
    
    # Print summary
    print_section "Test Summary"
    print_info "Tests passed: $tests_passed"
    print_info "Tests failed: $tests_failed"
    print_info "Total tests: $((tests_passed + tests_failed))"
    
    if [ $tests_failed -eq 0 ]; then
        print_success "All user tests passed! 🎉"
        exit 0
    else
        print_error "Some user tests failed"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi