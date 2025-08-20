#!/bin/bash

# Babbel Authentication Tests
# Test basic authentication functionality

# Get the script directory and source libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/auth.sh"
source "$SCRIPT_DIR/../lib/assertions.sh"

# Test successful login
test_successful_login() {
    print_section "Testing Successful Login"
    
    # Test admin login
    if api_login "admin" "admin"; then
        print_success "Admin login successful"
        
        # Verify session is active
        if is_session_active; then
            print_success "Session is active after login"
        else
            print_error "Session not active after successful login"
            return 1
        fi
        
        # Get session info
        local session_info=$(get_current_session)
        if [ -n "$session_info" ]; then
            local username=$(parse_json_field "$session_info" "username")
            local role=$(parse_json_field "$session_info" "role")
            
            assert_json_field_equals "$session_info" "username" "admin" "Session username"
            assert_json_field_equals "$session_info" "role" "admin" "Session role"
        else
            print_error "Could not retrieve session information"
            return 1
        fi
    else
        print_error "Admin login failed"
        return 1
    fi
    
    return 0
}

# Test login failures
test_login_failures() {
    print_section "Testing Login Failures"
    
    # Test with invalid username
    if test_login_credentials "nonexistent" "password" "401"; then
        print_success "Invalid username correctly rejected"
    else
        print_error "Invalid username test failed"
        return 1
    fi
    
    # Test with invalid password
    if test_login_credentials "admin" "wrongpassword" "401"; then
        print_success "Invalid password correctly rejected"
    else
        print_error "Invalid password test failed"
        return 1
    fi
    
    # Test with empty credentials
    local response=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/sessions" \
        -H "Content-Type: application/json" \
        -d '{}')
    
    local http_code=$(echo "$response" | tail -n1)
    if assert_http_error "$http_code" "Empty credentials"; then
        print_success "Empty credentials correctly rejected"
    else
        return 1
    fi
    
    return 0
}

# Test session management
test_session_management() {
    print_section "Testing Session Management"
    
    # Login to create session
    if ! api_login "admin" "admin"; then
        print_error "Could not login for session tests"
        return 1
    fi
    
    # Test getting current session
    local session_info=$(get_current_session)
    if assert_not_empty "$session_info" "Current session info"; then
        print_success "Can retrieve current session"
    else
        return 1
    fi
    
    # Test session logout
    if api_logout; then
        print_success "Logout successful"
        
        # Verify session is destroyed
        if ! is_session_active; then
            print_success "Session correctly destroyed after logout"
        else
            print_error "Session still active after logout"
            return 1
        fi
        
        # Test accessing protected endpoint after logout
        local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/sessions/current" \
            -b "$COOKIE_FILE")
        local http_code=$(echo "$response" | tail -n1)
        
        if assert_http_error "$http_code" "Access after logout"; then
            print_success "Protected endpoint correctly rejects after logout"
        else
            return 1
        fi
    else
        print_error "Logout failed"
        return 1
    fi
    
    return 0
}

# Test unauthorized access
test_unauthorized_access() {
    print_section "Testing Unauthorized Access"
    
    # Ensure we're logged out
    api_logout >/dev/null 2>&1
    
    local protected_endpoints=(
        "GET /stations"
        "GET /voices"
        "GET /stories"
        "GET /users"
        "GET /sessions/current"
    )
    
    for endpoint_spec in "${protected_endpoints[@]}"; do
        local method=$(echo "$endpoint_spec" | cut -d' ' -f1)
        local endpoint=$(echo "$endpoint_spec" | cut -d' ' -f2)
        
        print_info "Testing unauthorized access to $method $endpoint"
        
        local response=$(api_call "$method" "$endpoint")
        local http_code=$(echo "$response" | tail -n1)
        
        if assert_http_error "$http_code" "Unauthorized $method $endpoint"; then
            print_success "Unauthorized access correctly rejected for $endpoint"
        else
            print_error "Unauthorized access unexpectedly allowed for $endpoint"
        fi
    done
    
    return 0
}

# Test invalid session token
test_invalid_session() {
    print_section "Testing Invalid Session Token"
    
    # Test with completely invalid session token
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/sessions/current" \
        -H "Cookie: babbel_session=invalid_session_token_12345")
    local http_code=$(echo "$response" | tail -n1)
    
    if assert_http_error "$http_code" "Invalid session token"; then
        print_success "Invalid session token correctly rejected"
    else
        return 1
    fi
    
    # Test with malformed cookie
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/sessions/current" \
        -H "Cookie: babbel_session=malformed")
    local http_code=$(echo "$response" | tail -n1)
    
    if assert_http_error "$http_code" "Malformed session token"; then
        print_success "Malformed session token correctly rejected"
    else
        return 1
    fi
    
    return 0
}

# Test auth config endpoint
test_auth_config() {
    print_section "Testing Auth Configuration"
    
    # Auth config should be publicly accessible
    local response=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/auth/config")
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if assert_status_code "$http_code" "200" "Auth config endpoint"; then
        print_success "Auth config endpoint accessible"
        
        # Should have expected fields
        if assert_json_field "$body" "local_auth_enabled" "Local auth enabled field"; then
            local local_auth=$(parse_json_field "$body" "local_auth_enabled")
            print_info "Local auth enabled: $local_auth"
        fi
        
        if assert_json_field "$body" "oauth_enabled" "OAuth enabled field"; then
            local oauth=$(parse_json_field "$body" "oauth_enabled")
            print_info "OAuth enabled: $oauth"
        fi
    else
        return 1
    fi
    
    return 0
}

# Setup function
setup() {
    print_info "Setting up authentication tests..."
    # Ensure we start with a clean session
    api_logout >/dev/null 2>&1
    return 0
}

# Cleanup function
cleanup() {
    print_info "Cleaning up authentication tests..."
    # Ensure we're logged back in as admin for other tests
    api_login "admin" "admin" >/dev/null 2>&1
    return 0
}

# Main function
main() {
    print_header "Authentication Tests"
    
    setup
    
    local tests=(
        "test_auth_config"
        "test_login_failures"
        "test_successful_login"
        "test_session_management"
        "test_unauthorized_access"
        "test_invalid_session"
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
        print_success "All authentication tests passed!"
        exit 0
    else
        print_error "$failed authentication tests failed"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi