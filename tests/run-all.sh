#!/bin/bash

# Babbel Test Suite - Orchestrator
# Runs all tests in the correct order

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Source required libraries
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/auth.sh"
source "$SCRIPT_DIR/lib/assertions.sh"

# Test suites configuration (using simple approach for bash 3.x compatibility)
get_suite_script() {
    local suite="$1"
    case "$suite" in
        "setup") echo "setup/database.sh setup" ;;
        "auth") echo "auth/test-auth.sh" ;;
        "permissions") echo "auth/test-permissions.sh" ;;
        "stations") echo "stations/test-stations.sh" ;;
        "voices") echo "voices/test-voices.sh" ;;
        "station-voices") echo "station-voices/test-station-voices.sh" ;;
        "stories") echo "stories/test-stories.sh" ;;
        "bulletins") echo "bulletins/test-bulletins.sh" ;;
        "users") echo "users/test-users.sh" ;;
        "validation") echo "validation/test-validation.sh" ;;
        # "integration") echo "integration/test-full-flow.sh" ;;
        *) echo "" ;;
    esac
}

# Available test suites
AVAILABLE_SUITES=("setup" "auth" "permissions" "stations" "voices" "station-voices" "stories" "bulletins" "users" "validation")

# Test suite order (ensures dependencies are met)
TEST_ORDER=(
    "setup"
    "auth"
    "permissions"
    "stations"
    "voices"
    "station-voices"
    "stories"
    "bulletins"
    "users"
    "validation"
    # "integration"
)

# Global test tracking
SUITE_RESULTS=()
TOTAL_SUITES=0
PASSED_SUITES=0
FAILED_SUITES=0

# Check dependencies
check_dependencies() {
    print_section "Checking Dependencies"
    
    # Check for required tools
    local required_tools=("curl" "python3" "docker" "docker-compose")
    local missing=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        print_error "Missing required tools: ${missing[*]}"
        return 1
    fi
    
    # Check if FFmpeg is available
    check_ffmpeg
    
    # Check if we're in the project root
    if [ ! -f "$PROJECT_ROOT/docker-compose.yml" ]; then
        print_error "docker-compose.yml not found. Please run from project root."
        return 1
    fi
    
    print_success "All dependencies available"
    return 0
}

# Start Docker services
start_services() {
    print_section "Starting Docker Services"
    
    # Change to project root
    cd "$PROJECT_ROOT" || {
        print_error "Could not change to project root: $PROJECT_ROOT"
        return 1
    }
    
    # Start services
    if start_docker; then
        print_success "Docker services started"
        return 0
    else
        print_error "Failed to start Docker services"
        return 1
    fi
}

# Initialize test environment
initialize_environment() {
    print_section "Initializing Test Environment"
    
    # Reset test counters
    reset_test_counters
    
    # Clean audio directories
    clean_audio
    
    # Initialize database
    if "$SCRIPT_DIR/setup/database.sh" setup; then
        print_success "Database initialized"
    else
        print_error "Database initialization failed"
        return 1
    fi
    
    # Initial admin login
    if api_login; then
        print_success "Initial authentication successful"
        return 0
    else
        print_error "Initial authentication failed"
        return 1
    fi
}

# Run a single test suite
run_test_suite() {
    local suite_name="$1"
    local suite_script=$(get_suite_script "$suite_name")
    
    if [ -z "$suite_script" ]; then
        print_error "Unknown test suite: $suite_name"
        return 1
    fi
    
    print_header "Running Test Suite: $suite_name"
    
    # Parse script path and arguments
    read -r script_path script_args <<< "$suite_script"
    local full_script_path="$SCRIPT_DIR/$script_path"
    
    if [ ! -f "$full_script_path" ]; then
        print_error "Test script not found: $full_script_path"
        SUITE_RESULTS+=("$suite_name:MISSING")
        return 1
    fi
    
    # Run the test suite
    local start_time=$(date +%s)
    
    if [ -n "$script_args" ]; then
        bash "$full_script_path" $script_args
    else
        bash "$full_script_path"
    fi
    
    local exit_code=$?
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Record results
    if [ $exit_code -eq 0 ]; then
        SUITE_RESULTS+=("$suite_name:PASSED:${duration}s")
        print_success "✓ Test suite '$suite_name' PASSED (${duration}s)"
        PASSED_SUITES=$((PASSED_SUITES + 1))
    else
        SUITE_RESULTS+=("$suite_name:FAILED:${duration}s")
        print_error "✗ Test suite '$suite_name' FAILED (${duration}s)"
        FAILED_SUITES=$((FAILED_SUITES + 1))
    fi
    
    TOTAL_SUITES=$((TOTAL_SUITES + 1))
    
    return $exit_code
}

# Run all test suites
run_all_suites() {
    local specific_suite="$1"
    
    if [ -n "$specific_suite" ]; then
        # Run specific suite
        if [[ " ${AVAILABLE_SUITES[*]} " =~ " $specific_suite " ]]; then
            run_test_suite "$specific_suite"
        else
            print_error "Unknown test suite: $specific_suite"
            print_info "Available suites: ${AVAILABLE_SUITES[*]}"
            return 1
        fi
    else
        # Run all suites in order
        for suite in "${TEST_ORDER[@]}"; do
            local script=$(get_suite_script "$suite")
            if [[ -n "$script" ]]; then
                run_test_suite "$suite"
                echo ""  # Add spacing between suites
                
                # Allow early exit on critical failures
                if [ "$suite" = "setup" ] && [ $? -ne 0 ]; then
                    print_error "Critical setup failure - stopping test run"
                    break
                fi
            fi
        done
    fi
}

# Print final summary
print_final_summary() {
    print_header "Test Suite Summary"
    
    echo -e "\n${CYAN}Suite${NC}\t\t\t${CYAN}Result${NC}\t${CYAN}Duration${NC}"
    echo -e "${CYAN}-----${NC}\t\t\t${CYAN}------${NC}\t${CYAN}--------${NC}"
    
    for result in "${SUITE_RESULTS[@]}"; do
        IFS=':' read -r suite status duration <<< "$result"
        
        local color=""
        case "$status" in
            "PASSED") color="$GREEN" ;;
            "FAILED") color="$RED" ;;
            "MISSING") color="$YELLOW" ;;
        esac
        
        printf "%-20s\t${color}%s${NC}\t%s\n" "$suite" "$status" "${duration:-N/A}"
    done
    
    echo ""
    echo -e "${BOLD}Total Suites:${NC} $TOTAL_SUITES"
    echo -e "${GREEN}Passed:${NC} $PASSED_SUITES"
    echo -e "${RED}Failed:${NC} $FAILED_SUITES"
    
    if [ $FAILED_SUITES -eq 0 ]; then
        print_success "🎉 ALL TEST SUITES PASSED!"
        return 0
    else
        print_error "❌ $FAILED_SUITES TEST SUITE(S) FAILED"
        return 1
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [SUITE]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  -l, --list     List available test suites"
    echo "  --no-docker    Skip Docker startup (assume services are running)"
    echo "  --no-setup     Skip database setup (assume database is ready)"
    echo "  --quick        Skip Docker startup and database setup"
    echo ""
    echo "Test Suites:"
    for suite in "${AVAILABLE_SUITES[@]}"; do
        echo "  $suite"
    done
    echo ""
    echo "Examples:"
    echo "  $0                  # Run all test suites"
    echo "  $0 auth             # Run only authentication tests"
    echo "  $0 --quick auth     # Run auth tests without Docker/DB setup"
    echo "  $0 --list           # List available test suites"
}

# List available test suites
list_suites() {
    echo "Available test suites:"
    for suite in "${AVAILABLE_SUITES[@]}"; do
        local script=$(get_suite_script "$suite")
        if [[ -n "$script" ]]; then
            echo "  $suite - $script"
        fi
    done
}

# Main function
main() {
    local target_suite=""
    local skip_docker=false
    local skip_setup=false
    local quick_mode=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -l|--list)
                list_suites
                exit 0
                ;;
            --no-docker)
                skip_docker=true
                shift
                ;;
            --no-setup)
                skip_setup=true
                shift
                ;;
            --quick)
                quick_mode=true
                skip_docker=true
                skip_setup=true
                shift
                ;;
            -*)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                target_suite="$1"
                shift
                ;;
        esac
    done
    
    # Quick mode info
    if [ "$quick_mode" = true ]; then
        print_info "Quick mode: Skipping Docker and database setup"
        print_warning "Ensure services are already running and database is initialized"
    fi
    
    local start_time=$(date +%s)
    
    print_header "BABBEL MODULAR TEST SUITE"
    
    # Check dependencies
    if ! check_dependencies; then
        exit 1
    fi
    
    # Start Docker services
    if [ "$skip_docker" = false ]; then
        if ! start_services; then
            exit 1
        fi
    else
        print_info "Skipping Docker service startup"
    fi
    
    # Initialize test environment
    if [ "$skip_setup" = false ]; then
        if ! initialize_environment; then
            exit 1
        fi
    else
        print_info "Skipping database setup"
        # Still try to login
        api_login >/dev/null 2>&1
    fi
    
    # Run test suites
    run_all_suites "$target_suite"
    
    # Print summary
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    echo ""
    print_final_summary
    
    echo ""
    print_info "Total execution time: ${total_duration}s"
    
    # Exit with appropriate code
    if [ $FAILED_SUITES -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi