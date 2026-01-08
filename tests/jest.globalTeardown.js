// Jest global teardown - cleanup after all tests
const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const PROJECT_ROOT = path.join(__dirname, '..');
const COOKIE_FILE = path.join(__dirname, 'test_cookies.txt');

async function globalTeardown() {
  console.log('\n========================================');
  console.log('  Test Cleanup');
  console.log('========================================\n');

  // Clean up cookie file
  try {
    if (fs.existsSync(COOKIE_FILE)) {
      fs.unlinkSync(COOKIE_FILE);
      console.log('Cleaned up cookie file');
    }
  } catch (error) {
    // Ignore cleanup errors
  }

  // Optionally stop Docker (controlled by env var)
  if (process.env.JEST_STOP_DOCKER === 'true') {
    console.log('Stopping Docker containers...');
    try {
      execSync('docker compose down', {
        cwd: PROJECT_ROOT,
        stdio: 'inherit'
      });
      console.log('Docker containers stopped');
    } catch (error) {
      console.error('Failed to stop Docker:', error.message);
    }
  } else {
    console.log('Leaving Docker containers running (set JEST_STOP_DOCKER=true to stop)');
  }

  console.log('\n========================================');
  console.log('  Teardown Complete');
  console.log('========================================\n');
}

module.exports = globalTeardown;
