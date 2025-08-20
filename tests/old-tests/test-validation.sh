#!/bin/bash

# Babbel Validation Tests - Node.js Implementation Wrapper
# This wrapper script maintains compatibility with the existing bash test orchestrator
# while using the new Node.js implementation for improved JSON handling and reliability.

# Get the script directory and source libraries for compatibility
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"

# Check if Node.js is available
check_nodejs() {
    if ! command -v node &> /dev/null; then
        print_error "Node.js is required but not found. Please install Node.js."
        exit 1
    fi
    
    # Check Node.js version (require at least Node 12 for modern features)
    local node_version=$(node --version | sed 's/v//' | cut -d. -f1)
    if [ "$node_version" -lt 12 ]; then
        print_error "Node.js version 12 or higher is required. Found version: $(node --version)"
        exit 1
    fi
}

# Main function - wrapper for Node.js implementation
main() {
    print_header "Comprehensive Validation Tests (Node.js Implementation)"
    
    # Check dependencies
    check_nodejs
    
    # Ensure we have the required environment variables and cookie file
    if [ ! -f "$COOKIE_FILE" ]; then
        print_error "Cookie file not found: $COOKIE_FILE"
        print_info "Please ensure you have authenticated first by running other tests."
        exit 1
    fi
    
    # Set environment variables for Node.js script
    export API_BASE="${API_BASE:-http://localhost:8080}"
    
    # Execute the Node.js validation script
    local nodejs_script="$SCRIPT_DIR/validation-tests.js"
    
    if [ ! -f "$nodejs_script" ]; then
        print_error "Node.js validation script not found: $nodejs_script"
        exit 1
    fi
    
    # Make sure the Node.js script is executable
    chmod +x "$nodejs_script"
    
    print_info "Executing Node.js validation tests..."
    
    # Run the Node.js script and capture its exit code
    node "$nodejs_script"
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        print_success "All Node.js validation tests completed successfully"
        return 0
    else
        print_error "Node.js validation tests failed with exit code $exit_code"
        return 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi