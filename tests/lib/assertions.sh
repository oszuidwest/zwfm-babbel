#!/bin/bash

# Babbel Test Library - Test Assertion Functions
# This file contains assertion functions for testing API responses and data

# Ensure common.sh is loaded for dependencies
if [ -z "$API_URL" ]; then
    echo "Error: common.sh must be sourced before assertions.sh" >&2
    exit 1
fi

# Assert HTTP status code
assert_status_code() {
    local actual_code="$1"
    local expected_code="$2"
    local test_description="${3:-HTTP status code}"
    
    if [ "$actual_code" = "$expected_code" ]; then
        print_success "$test_description: expected $expected_code, got $actual_code"
        return 0
    else
        print_error "$test_description: expected $expected_code, got $actual_code"
        return 1
    fi
}

# Assert HTTP response is successful (200-299)
assert_http_success() {
    local http_code="$1"
    local test_description="${2:-HTTP success}"
    
    if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
        print_success "$test_description: HTTP $http_code (success)"
        return 0
    else
        print_error "$test_description: HTTP $http_code (not success)"
        return 1
    fi
}

# Assert HTTP response is an error (400-599)
assert_http_error() {
    local http_code="$1"
    local test_description="${2:-HTTP error}"
    
    if [[ "$http_code" =~ ^[4-5][0-9][0-9]$ ]]; then
        print_success "$test_description: HTTP $http_code (error as expected)"
        return 0
    else
        print_error "$test_description: HTTP $http_code (expected error status)"
        return 1
    fi
}

# Parse JSON field from response
parse_json_field() {
    local json="$1"
    local field="$2"
    
    echo "$json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('$field', ''))
except Exception as e:
    print('', file=sys.stderr)
" 2>/dev/null || echo ""
}

# Parse nested JSON field (e.g., "data.0.id")
parse_json_nested() {
    local json="$1"
    local field_path="$2"
    
    echo "$json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    keys = '$field_path'.split('.')
    current = data
    for key in keys:
        if key.isdigit():
            current = current[int(key)]
        else:
            current = current.get(key, {})
    print(current if isinstance(current, (str, int, float, bool)) else '')
except:
    print('')
" 2>/dev/null || echo ""
}

# Assert JSON field exists and is not empty
assert_json_field() {
    local json="$1"
    local field="$2"
    local test_description="${3:-Field $field}"
    
    local value=$(parse_json_field "$json" "$field")
    
    if [ -n "$value" ] && [ "$value" != "null" ]; then
        print_success "$test_description: has value '$value'"
        return 0
    else
        print_error "$test_description: missing or empty"
        return 1
    fi
}

# Assert JSON field has specific value
assert_json_field_equals() {
    local json="$1"
    local field="$2"
    local expected_value="$3"
    local test_description="${4:-Field $field}"
    
    local actual_value=$(parse_json_field "$json" "$field")
    
    if [ "$actual_value" = "$expected_value" ]; then
        print_success "$test_description: expected '$expected_value', got '$actual_value'"
        return 0
    else
        print_error "$test_description: expected '$expected_value', got '$actual_value'"
        return 1
    fi
}

# Assert string contains substring
assert_contains() {
    local text="$1"
    local substring="$2"
    local test_description="${3:-String contains}"
    
    if [[ "$text" == *"$substring"* ]]; then
        print_success "$test_description: contains '$substring'"
        return 0
    else
        print_error "$test_description: does not contain '$substring'"
        return 1
    fi
}

# Assert string does not contain substring
assert_not_contains() {
    local text="$1"
    local substring="$2"
    local test_description="${3:-String does not contain}"
    
    if [[ "$text" != *"$substring"* ]]; then
        print_success "$test_description: does not contain '$substring'"
        return 0
    else
        print_error "$test_description: unexpectedly contains '$substring'"
        return 1
    fi
}

# Assert value is not empty
assert_not_empty() {
    local value="$1"
    local test_description="${2:-Value}"
    
    if [ -n "$value" ]; then
        print_success "$test_description: is not empty ('$value')"
        return 0
    else
        print_error "$test_description: is empty"
        return 1
    fi
}

# Assert value is empty
assert_empty() {
    local value="$1"
    local test_description="${2:-Value}"
    
    if [ -z "$value" ]; then
        print_success "$test_description: is empty"
        return 0
    else
        print_error "$test_description: is not empty ('$value')"
        return 1
    fi
}

# Assert file exists
assert_file_exists() {
    local file_path="$1"
    local test_description="${2:-File exists}"
    
    if [ -f "$file_path" ]; then
        print_success "$test_description: $file_path exists"
        return 0
    else
        print_error "$test_description: $file_path does not exist"
        return 1
    fi
}

# Assert file does not exist
assert_file_not_exists() {
    local file_path="$1"
    local test_description="${2:-File does not exist}"
    
    if [ ! -f "$file_path" ]; then
        print_success "$test_description: $file_path does not exist"
        return 0
    else
        print_error "$test_description: $file_path exists"
        return 1
    fi
}

# Assert file is not empty
assert_file_not_empty() {
    local file_path="$1"
    local test_description="${2:-File not empty}"
    
    if [ -f "$file_path" ] && [ -s "$file_path" ]; then
        local size=$(stat -c%s "$file_path" 2>/dev/null || stat -f%z "$file_path" 2>/dev/null || echo "0")
        print_success "$test_description: $file_path has size $size bytes"
        return 0
    else
        print_error "$test_description: $file_path is empty or does not exist"
        return 1
    fi
}

# Assert audio file is valid
assert_valid_audio() {
    local file_path="$1"
    local test_description="${2:-Valid audio file}"
    
    if [ -f "$file_path" ]; then
        if ffprobe -v quiet -select_streams a:0 -show_entries stream=codec_type -of csv=p=0 "$file_path" >/dev/null 2>&1; then
            local size=$(stat -c%s "$file_path" 2>/dev/null || stat -f%z "$file_path" 2>/dev/null || echo "0")
            print_success "$test_description: $file_path is valid audio (${size} bytes)"
            return 0
        else
            print_error "$test_description: $file_path is not valid audio"
            return 1
        fi
    else
        print_error "$test_description: $file_path does not exist"
        return 1
    fi
}

# Check API response and extract common information
check_response() {
    local response="$1"
    local expected_status="$2"
    local test_description="${3:-API response}"
    
    local http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | sed '$d')
    
    if assert_status_code "$http_code" "$expected_status" "$test_description"; then
        # If successful, try to extract common fields
        if [ "$expected_status" = "201" ] || [ "$expected_status" = "200" ]; then
            local id=$(parse_json_field "$body" "id")
            if [ -n "$id" ] && [ "$id" != "null" ]; then
                print_info "Created/Retrieved ID: $id"
                echo "$id"  # Return the ID for use in other tests
            fi
        fi
        return 0
    else
        # On error, try to extract error message
        local error_msg=$(extract_error_message "$body")
        if [ -n "$error_msg" ]; then
            print_error "Error message: $error_msg"
        fi
        return 1
    fi
}

# Test API endpoint with common pattern
test_api_endpoint() {
    local method="$1"
    local endpoint="$2"
    local expected_status="$3"
    local data="$4"
    local test_description="${5:-$method $endpoint}"
    local cookie_file="${6:-$COOKIE_FILE}"
    
    print_info "Testing: $test_description"
    
    local response=$(api_call "$method" "$endpoint" "$data" "$cookie_file")
    
    if check_response "$response" "$expected_status" "$test_description"; then
        return 0
    else
        return 1
    fi
}

# Assert array length from JSON response
assert_array_length() {
    local json="$1"
    local array_field="$2"
    local expected_length="$3"
    local test_description="${4:-Array length}"
    
    local actual_length=$(echo "$json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    arr = data.get('$array_field', [])
    print(len(arr) if isinstance(arr, list) else 0)
except:
    print(0)
" 2>/dev/null || echo "0")
    
    if [ "$actual_length" = "$expected_length" ]; then
        print_success "$test_description: expected length $expected_length, got $actual_length"
        return 0
    else
        print_error "$test_description: expected length $expected_length, got $actual_length"
        return 1
    fi
}

# Assert numeric value is greater than
assert_greater_than() {
    local actual="$1"
    local threshold="$2"
    local test_description="${3:-Numeric comparison}"
    
    if (( $(echo "$actual > $threshold" | bc -l 2>/dev/null || echo "0") )); then
        print_success "$test_description: $actual > $threshold"
        return 0
    else
        print_error "$test_description: $actual <= $threshold"
        return 1
    fi
}

# Assert numeric value is less than
assert_less_than() {
    local actual="$1"
    local threshold="$2"
    local test_description="${3:-Numeric comparison}"
    
    if (( $(echo "$actual < $threshold" | bc -l 2>/dev/null || echo "0") )); then
        print_success "$test_description: $actual < $threshold"
        return 0
    else
        print_error "$test_description: $actual >= $threshold"
        return 1
    fi
}