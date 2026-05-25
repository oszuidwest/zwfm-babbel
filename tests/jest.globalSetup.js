// Jest global setup - Docker orchestration
// Starts Docker containers before any tests run
const { execFileSync } = require('child_process');
const axios = require('axios');
const path = require('path');

const PROJECT_ROOT = path.join(__dirname, '..');
const API_BASE = process.env.API_BASE || 'http://localhost:8080';

function describeRequestError(error) {
  if (!error) {
    return 'unknown error';
  }
  if (error.response) {
    return `HTTP ${error.response.status} ${error.response.statusText || ''}`.trim();
  }
  if (error.code) {
    return `${error.code}: ${error.message}`;
  }
  return error.message || String(error);
}

async function waitForApi(maxRetries = 30, retryDelay = 2000) {
  let lastError = null;
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await axios.get(`${API_BASE}/api/v1/auth/config`, { timeout: 2000 });
      if (response.status === 200) {
        console.log('API is responding');
        return true;
      }
    } catch (error) {
      lastError = error;
      console.log(`Waiting for API... (attempt ${i + 1}/${maxRetries}: ${describeRequestError(error)})`);
      await new Promise(resolve => setTimeout(resolve, retryDelay));
    }
  }
  throw new Error(`API failed to start within timeout. Last error: ${describeRequestError(lastError)}`);
}

async function globalSetup() {
  // Check for quick mode (skip Docker)
  if (process.env.JEST_SKIP_DOCKER === 'true') {
    console.log('\nSkipping Docker setup (JEST_SKIP_DOCKER=true)');
    console.log('Checking API readiness...');
    try {
      await waitForApi(5, 1000);
    } catch (error) {
      throw new Error(
        `API is not reachable. Start the API before running with JEST_SKIP_DOCKER=true. ${error.message}`
      );
    }
    return;
  }

  console.log('\n========================================');
  console.log('  Starting Docker Services');
  console.log('========================================\n');

  try {
    // Step 1: Stop and clean existing containers
    console.log('Step 1/4: Cleaning Docker environment...');
    execFileSync('docker', ['compose', 'down', '-v'], {
      cwd: PROJECT_ROOT,
      stdio: 'inherit'
    });

    // Step 2: Build fresh images
    console.log('\nStep 2/4: Building Docker images...');
    execFileSync('docker', ['compose', 'build'], {
      cwd: PROJECT_ROOT,
      stdio: 'inherit'
    });

    // Step 3: Start containers
    console.log('\nStep 3/4: Starting Docker containers...');
    execFileSync('docker', ['compose', 'up', '-d'], {
      cwd: PROJECT_ROOT,
      stdio: 'inherit'
    });

    // Step 4: Wait for API
    console.log('\nStep 4/4: Waiting for API to be ready...');
    await waitForApi();

    console.log('\n========================================');
    console.log('  Docker Setup Complete');
    console.log('========================================\n');

  } catch (error) {
    console.error('\nDocker setup failed:', error.message);

    // Show logs for debugging
    try {
      console.log('\n--- Docker logs ---');
      execFileSync('docker', ['compose', 'logs', '--tail=50'], {
        cwd: PROJECT_ROOT,
        stdio: 'inherit'
      });
    } catch (logError) {
      console.error(`Failed to collect Docker logs: ${logError.message}`);
    }

    throw error;
  }
}

module.exports = globalSetup;
