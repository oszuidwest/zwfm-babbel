#!/bin/bash

# Babbel Test Setup - Database Management
# This file contains functions for database setup and cleanup

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source required libraries
source "$SCRIPT_DIR/../lib/common.sh"

# Setup clean database
setup_database() {
    print_section "Setting Up Database"
    
    # Ensure Docker is running and MySQL container is available
    if ! docker ps | grep -q "babbel-mysql"; then
        print_error "MySQL container not running. Please run 'docker-compose up -d' first."
        return 1
    fi
    
    # Wait for MySQL to be ready
    print_info "Waiting for MySQL to be ready..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "SELECT 1" >/dev/null 2>&1; then
            break
        fi
        retries=$((retries - 1))
        sleep 1
    done
    
    if [ $retries -eq 0 ]; then
        print_error "MySQL failed to become ready"
        return 1
    fi
    
    print_success "MySQL is ready"
    
    # Drop and recreate database
    print_info "Dropping database..."
    if ! docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "DROP DATABASE IF EXISTS $MYSQL_DATABASE;" 2>/dev/null; then
        print_error "Failed to drop database"
        return 1
    fi
    
    print_info "Creating database..."
    if ! docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "CREATE DATABASE $MYSQL_DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/dev/null; then
        print_error "Failed to create database"
        return 1
    fi
    
    # Apply schema
    print_info "Applying schema..."
    local schema_file="$PROJECT_ROOT/migrations/001_complete_schema.sql"
    if [ ! -f "$schema_file" ]; then
        print_error "Schema file not found: $schema_file"
        return 1
    fi
    
    if ! docker exec -i babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" < "$schema_file" 2>/dev/null; then
        print_error "Failed to apply schema"
        return 1
    fi
    
    # Load fixtures if requested
    local fixtures_file="$SCRIPT_DIR/fixtures.sql"
    if [ -f "$fixtures_file" ] && [ "${LOAD_FIXTURES:-false}" = "true" ]; then
        print_info "Loading test fixtures..."
        if docker exec -i babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" < "$fixtures_file" 2>/dev/null; then
            print_success "Test fixtures loaded"
        else
            print_warning "Failed to load test fixtures"
        fi
    fi
    
    # Restart API to ensure clean state
    print_info "Restarting API..."
    if ! docker-compose restart babbel >/dev/null 2>&1; then
        print_warning "Failed to restart API container"
    fi
    
    # Wait for API to be ready
    print_info "Waiting for API to be ready..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if curl -s "$API_BASE/health" >/dev/null 2>&1; then
            print_success "Database setup complete"
            return 0
        fi
        retries=$((retries - 1))
        sleep 2
    done
    
    print_error "API failed to restart after database setup"
    return 1
}

# Clean all data from database (keeping schema)
clean_database() {
    print_section "Cleaning Database Data"
    
    # List of tables to clean (order matters due to foreign keys)
    local tables=(
        "bulletin_stories"
        "bulletins"
        "stories"
        "station_voices"
        "voices"
        "stations"
        "user_sessions"
        "users"
    )
    
    print_info "Disabling foreign key checks..."
    docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "SET FOREIGN_KEY_CHECKS = 0;" 2>/dev/null
    
    for table in "${tables[@]}"; do
        print_info "Cleaning table: $table"
        docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "DELETE FROM \`$table\`;" 2>/dev/null
        
        # Reset auto-increment if table has an ID column
        docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "ALTER TABLE \`$table\` AUTO_INCREMENT = 1;" 2>/dev/null
    done
    
    print_info "Re-enabling foreign key checks..."
    docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "SET FOREIGN_KEY_CHECKS = 1;" 2>/dev/null
    
    print_success "Database cleaned"
}

# Execute SQL query and return result
execute_sql() {
    local query="$1"
    local format="${2:-table}"  # table, vertical, or raw
    
    case "$format" in
        "vertical")
            docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "$query" --vertical 2>/dev/null
            ;;
        "raw")
            docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "$query" --raw --skip-column-names 2>/dev/null
            ;;
        *)
            docker exec babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" -e "$query" 2>/dev/null
            ;;
    esac
}

# Get count of records in a table
get_table_count() {
    local table="$1"
    execute_sql "SELECT COUNT(*) FROM \`$table\`;" raw
}

# Check if database has expected tables
verify_schema() {
    print_section "Verifying Database Schema"
    
    local expected_tables=(
        "users"
        "user_sessions"
        "stations"
        "voices"
        "station_voices"
        "stories"
        "bulletins"
        "bulletin_stories"
    )
    
    local errors=0
    
    for table in "${expected_tables[@]}"; do
        if execute_sql "SHOW TABLES LIKE '$table';" raw | grep -q "$table"; then
            print_success "Table exists: $table"
        else
            print_error "Table missing: $table"
            errors=$((errors + 1))
        fi
    done
    
    if [ $errors -eq 0 ]; then
        print_success "All expected tables found"
        return 0
    else
        print_error "Schema verification failed: $errors missing tables"
        return 1
    fi
}

# Show database status
show_database_status() {
    print_section "Database Status"
    
    local tables=(
        "users"
        "stations"
        "voices"
        "station_voices"
        "stories"
        "bulletins"
    )
    
    echo -e "\n${CYAN}Table${NC}\t\t${CYAN}Count${NC}"
    echo -e "${CYAN}-----${NC}\t\t${CYAN}-----${NC}"
    
    for table in "${tables[@]}"; do
        local count=$(get_table_count "$table")
        printf "%-15s\t%s\n" "$table" "$count"
    done
    
    echo ""
}

# Create admin user (if not exists)
create_admin_user() {
    print_section "Creating Admin User"
    
    # Check if admin user already exists
    local admin_exists=$(execute_sql "SELECT COUNT(*) FROM users WHERE username = 'admin';" raw)
    
    if [ "$admin_exists" -gt 0 ]; then
        print_info "Admin user already exists"
        return 0
    fi
    
    # Create admin user directly in database
    # Password hash for "admin" using bcrypt
    local password_hash='$2a$10$rN7VcT2/jAZGZN5XG8rR7eDvKBQB7.e9z7IpxTKx3FzjQKGvh5zFq'
    
    if execute_sql "INSERT INTO users (username, full_name, password_hash, role, created_at, updated_at) VALUES ('admin', 'Administrator', '$password_hash', 'admin', NOW(), NOW());" >/dev/null 2>&1; then
        print_success "Admin user created"
    else
        print_error "Failed to create admin user"
        return 1
    fi
}

# Backup database
backup_database() {
    local backup_file="${1:-/tmp/babbel_backup_$(date +%Y%m%d_%H%M%S).sql}"
    
    print_info "Backing up database to: $backup_file"
    
    if docker exec babbel-mysql mysqldump -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" > "$backup_file" 2>/dev/null; then
        print_success "Database backed up to: $backup_file"
        echo "$backup_file"
        return 0
    else
        print_error "Database backup failed"
        return 1
    fi
}

# Restore database from backup
restore_database() {
    local backup_file="$1"
    
    if [ ! -f "$backup_file" ]; then
        print_error "Backup file not found: $backup_file"
        return 1
    fi
    
    print_info "Restoring database from: $backup_file"
    
    if docker exec -i babbel-mysql mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE" < "$backup_file" 2>/dev/null; then
        print_success "Database restored from: $backup_file"
        return 0
    else
        print_error "Database restore failed"
        return 1
    fi
}

# Main function for standalone execution
main() {
    local action="${1:-setup}"
    
    case "$action" in
        "setup")
            setup_database
            ;;
        "clean")
            clean_database
            ;;
        "verify")
            verify_schema
            ;;
        "status")
            show_database_status
            ;;
        "admin")
            create_admin_user
            ;;
        "backup")
            backup_database "$2"
            ;;
        "restore")
            restore_database "$2"
            ;;
        *)
            echo "Usage: $0 {setup|clean|verify|status|admin|backup|restore}"
            echo "  setup   - Create clean database with schema"
            echo "  clean   - Clean all data from database"
            echo "  verify  - Verify database schema"
            echo "  status  - Show table counts"
            echo "  admin   - Create admin user"
            echo "  backup  - Backup database to file"
            echo "  restore - Restore database from file"
            exit 1
            ;;
    esac
}

# If script is run directly, execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi