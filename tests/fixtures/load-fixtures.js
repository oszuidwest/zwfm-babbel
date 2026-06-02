#!/usr/bin/env node

// Load test fixtures into the database.
// This script populates the database with test data for consistent testing.

const path = require('path');
const fs = require('fs');
const { createMySQLExecutor } = require('../lib/MySQLHelper');

const fixtureFile = path.join(__dirname, 'test-data.sql');

// Verify that the test data fixture file exists.
if (!fs.existsSync(fixtureFile)) {
    console.error('[ERROR] Fixture file not found:', fixtureFile);
    process.exit(1);
}

const mysql = createMySQLExecutor();

console.log('Loading test fixtures into database...');

try {
    const fixtureSQL = fs.readFileSync(fixtureFile);
    console.log(`Using ${mysql.describeTarget()}...`);
    mysql.execSQLScript(fixtureSQL);

    console.log('[OK] Test fixtures loaded successfully!');
    console.log('\nTest data includes:');
    console.log('  - 3 test users (editor_user, viewer_user, suspended_user)');
    console.log('  - 3 test stations');
    console.log('  - 5 test voices');
    console.log('  - 8 test stories with various schedules');
    console.log('  - Station-voice relationships');
    console.log('  - Sample bulletins for history testing');
    console.log('\nAll test users have password: testpass123');
    
} catch (error) {
    console.error('[ERROR] Failed to load fixtures:', error.message);
    process.exit(1);
}
