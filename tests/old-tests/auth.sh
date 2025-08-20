#!/bin/bash

# Babbel Test Library - Authentication Functions
# This file contains authentication-related functions

# Ensure common.sh is loaded for dependencies
if [ -z "$API_URL" ]; then
    echo "Error: common.sh must be sourced before auth.sh" >&2
    exit 1
fi

# Default credentials
DEFAULT_ADMIN_USERNAME="admin"
DEFAULT_ADMIN_PASSWORD="admin"

# Login to the API as admin
api_login() {
    local username="${1:-$DEFAULT_ADMIN_USERNAME}"
    local password="${2:-$DEFAULT_ADMIN_PASSWORD}"
    local cookie_file="${3:-$COOKIE_FILE}"
    
    print_section "API Authentication"
    
    rm -f "$cookie_file"
    
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/sessions" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$username\", \"password\": \"$password\"}" \
        -c "$cookie_file")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "201" ]; then
        print_success "Logged in as $username"
        return 0
    else
        print_error "Login failed for $username (HTTP $http_code)"
        local error_msg=$(echo "$response" | sed '$d' | extract_error_message)
        if [ -n "$error_msg" ]; then
            print_error "Error: $error_msg"
        fi
        return 1
    fi
}

# Logout from the API
api_logout() {
    local cookie_file="${1:-$COOKIE_FILE}"
    
    print_section "API Logout"
    
    if [ ! -f "$cookie_file" ]; then
        print_warning "No cookie file found - already logged out"
        return 0
    fi
    
    response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/sessions/current" \
        -b "$cookie_file")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "204" ]; then
        print_success "Logged out successfully"
        rm -f "$cookie_file"
        return 0
    else
        print_warning "Logout response: HTTP $http_code (removing cookie anyway)"
        rm -f "$cookie_file"
        return 1
    fi
}

# Get current session info
get_current_session() {
    local cookie_file="${1:-$COOKIE_FILE}"
    
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/sessions/current" \
        -b "$cookie_file")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        echo "$response" | sed '$d'  # Return response body without HTTP code
        return 0
    else
        return 1
    fi
}

# Check if session is active
is_session_active() {
    local cookie_file="${1:-$COOKIE_FILE}"
    
    if get_current_session "$cookie_file" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Login as a specific user (creates temp cookie file)
login_as_user() {
    local username="$1"
    local password="$2"
    local temp_cookie="${3:-/tmp/temp_user_cookie_$$.txt}"
    
    print_info "Logging in as $username"
    
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/sessions" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$username\", \"password\": \"$password\"}" \
        -c "$temp_cookie")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "201" ]; then
        print_success "$username logged in"
        echo "$temp_cookie"  # Return the temp cookie file path
        return 0
    else
        print_error "Failed to login as $username (HTTP $http_code)"
        local error_msg=$(echo "$response" | sed '$d' | extract_error_message)
        if [ -n "$error_msg" ]; then
            print_error "Error: $error_msg"
        fi
        rm -f "$temp_cookie"
        return 1
    fi
}

# Logout from a specific cookie file and clean up
logout_from_cookie() {
    local cookie_file="$1"
    
    if [ -f "$cookie_file" ]; then
        response=$(curl -s -w "\n%{http_code}" -X DELETE "$API_URL/sessions/current" \
            -b "$cookie_file")
        
        http_code=$(echo "$response" | tail -n1)
        
        if [ "$http_code" = "204" ]; then
            print_success "Logged out from session"
        else
            print_warning "Logout response: HTTP $http_code"
        fi
        
        rm -f "$cookie_file"
    fi
}

# Test login with credentials
test_login_credentials() {
    local username="$1"
    local password="$2"
    local expected_status="${3:-201}"
    local temp_cookie="/tmp/test_login_$$.txt"
    
    response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/sessions" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$username\", \"password\": \"$password\"}" \
        -c "$temp_cookie")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "$expected_status" ]; then
        if [ "$expected_status" = "201" ]; then
            print_success "Login successful for $username"
            # Clean up the successful login
            logout_from_cookie "$temp_cookie"
        else
            print_success "Login correctly failed for $username (HTTP $http_code)"
            rm -f "$temp_cookie"
        fi
        return 0
    else
        print_error "Unexpected login result for $username: expected $expected_status, got $http_code"
        rm -f "$temp_cookie"
        return 1
    fi
}

# Get authentication configuration
get_auth_config() {
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/auth/config")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        echo "$response" | sed '$d'  # Return response body without HTTP code
        return 0
    else
        print_error "Failed to get auth config (HTTP $http_code)"
        return 1
    fi
}

# Check if a user has admin privileges with current session
check_admin_privileges() {
    local cookie_file="${1:-$COOKIE_FILE}"
    
    # Try to access an admin-only endpoint (like creating users)
    response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users" \
        -b "$cookie_file")
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "200" ]; then
        return 0  # Has admin privileges
    else
        return 1  # No admin privileges or not authenticated
    fi
}

# Restore admin session (use this after testing with different users)
restore_admin_session() {
    if ! is_session_active; then
        print_info "Restoring admin session"
        api_login
    else
        if check_admin_privileges; then
            print_info "Admin session already active"
        else
            print_info "Non-admin session active, re-logging as admin"
            api_logout
            api_login
        fi
    fi
}

# Save current cookie and switch to different user
switch_to_user() {
    local username="$1"
    local password="$2"
    local backup_cookie="${COOKIE_FILE}.backup"
    
    # Backup current admin cookie
    if [ -f "$COOKIE_FILE" ]; then
        cp "$COOKIE_FILE" "$backup_cookie"
    fi
    
    # Login as different user
    if api_login "$username" "$password"; then
        echo "$backup_cookie"  # Return backup cookie path
        return 0
    else
        # Restore backup if login failed
        if [ -f "$backup_cookie" ]; then
            cp "$backup_cookie" "$COOKIE_FILE"
            rm -f "$backup_cookie"
        fi
        return 1
    fi
}

# Restore from backup cookie
restore_from_backup() {
    local backup_cookie="$1"
    
    if [ -f "$backup_cookie" ]; then
        cp "$backup_cookie" "$COOKIE_FILE"
        rm -f "$backup_cookie"
        print_info "Session restored from backup"
        return 0
    else
        print_warning "No backup cookie found, logging in as admin"
        api_login
    fi
}