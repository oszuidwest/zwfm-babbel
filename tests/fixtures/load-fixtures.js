#!/usr/bin/env node

// Load test fixtures into the database.
// This script populates the database with test data for consistent testing.

const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const fixtureFile = path.join(__dirname, 'test-data.sql');

// Verify that the test data fixture file exists.
if (!fs.existsSync(fixtureFile)) {
    console.error('❌ Fixture file not found:', fixtureFile);
    process.exit(1);
}

// Configure MySQL connection parameters from environment or defaults.
const mysqlUser = process.env.MYSQL_USER || 'babbel';
const mysqlPassword = process.env.MYSQL_PASSWORD || 'babbel';
const mysqlDatabase = process.env.MYSQL_DATABASE || 'babbel';
const mysqlHost = process.env.MYSQL_HOST || 'localhost';
const mysqlContainer = process.env.MYSQL_CONTAINER || 'babbel-mysql';

console.log('Loading test fixtures into database...');

try {
    // Load fixtures using docker exec if container is running
    const isDockerRunning = () => {
        try {
            const containers = execFileSync('docker', ['ps', '--format', '{{.Names}}'], {
                encoding: 'utf-8',
                stdio: ['ignore', 'pipe', 'ignore']
            }).trim().split('\n');
            return containers.includes(mysqlContainer);
        } catch {
            return false;
        }
    };

    const fixtureSQL = fs.readFileSync(fixtureFile);

    if (isDockerRunning()) {
        console.log(`Using Docker container ${mysqlContainer}...`);
        execFileSync(
            'docker',
            ['exec', '-i', mysqlContainer, 'mysql', '-u', mysqlUser, `-p${mysqlPassword}`, mysqlDatabase],
            { input: fixtureSQL, stdio: ['pipe', 'inherit', 'inherit'] }
        );
    } else {
        console.log('Connecting directly to MySQL...');
        execFileSync(
            'mysql',
            ['-h', mysqlHost, '-u', mysqlUser, `-p${mysqlPassword}`, mysqlDatabase],
            { input: fixtureSQL, stdio: ['pipe', 'inherit', 'inherit'] }
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
