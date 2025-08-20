#!/usr/bin/env node

/**
 * Load test fixtures into the database
 * This script can be run to populate the database with test data
 */

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const fixtureFile = path.join(__dirname, 'test-data.sql');

// Check if fixture file exists
if (!fs.existsSync(fixtureFile)) {
    console.error('❌ Fixture file not found:', fixtureFile);
    process.exit(1);
}

// MySQL connection parameters
const mysqlUser = process.env.MYSQL_USER || 'babbel';
const mysqlPassword = process.env.MYSQL_PASSWORD || 'babbel';
const mysqlDatabase = process.env.MYSQL_DATABASE || 'babbel';
const mysqlHost = process.env.MYSQL_HOST || 'localhost';

console.log('Loading test fixtures into database...');

try {
    // Load fixtures using docker exec if container is running
    const isDockerRunning = () => {
        try {
            execSync('docker ps | grep babbel-mysql', { stdio: 'ignore' });
            return true;
        } catch {
            return false;
        }
    };

    if (isDockerRunning()) {
        console.log('Using Docker container babbel-mysql...');
        execSync(
            `docker exec -i babbel-mysql mysql -u ${mysqlUser} -p${mysqlPassword} ${mysqlDatabase} < ${fixtureFile}`,
            { stdio: 'inherit' }
        );
    } else {
        console.log('Connecting directly to MySQL...');
        execSync(
            `mysql -h ${mysqlHost} -u ${mysqlUser} -p${mysqlPassword} ${mysqlDatabase} < ${fixtureFile}`,
            { stdio: 'inherit' }
        );
    }

    console.log('✅ Test fixtures loaded successfully!');
    console.log('\nTest data includes:');
    console.log('  - 3 test users (editor_user, viewer_user, suspended_user)');
    console.log('  - 3 test stations');
    console.log('  - 5 test voices');
    console.log('  - 8 test stories with various schedules');
    console.log('  - Station-voice relationships');
    console.log('  - Sample bulletins for history testing');
    console.log('\nAll test users have password: testpass123');
    
} catch (error) {
    console.error('❌ Failed to load fixtures:', error.message);
    process.exit(1);
}