// Jest configuration for Babbel API integration tests
module.exports = {
  // Run tests from the tests directory
  rootDir: '.',

  // Test file pattern - .test.js files
  testMatch: ['**/*.test.js'],

  // Exclude pure-unit tests under tests/lib/ that use jest.mock() to stub
  // modules like child_process. setupFilesAfterEnv loads TestHelpers (which
  // requires MySQLHelper -> child_process) before the test file's jest.mock
  // can take effect, so the mock is silently bypassed and the real binaries
  // run. These tests are covered by tests/jest.unit.config.js instead.
  testPathIgnorePatterns: [
    '/node_modules/',
    '/lib/MySQLHelper\\.test\\.js$',
    '/lib/TestHelpers\\.test\\.js$',
    '/lib/numeric\\.test\\.js$'
  ],

  // CRITICAL: Sequential execution (shared database state)
  maxWorkers: 1,

  // Test order - explicit sequencing for dependencies
  testSequencer: './jest.testSequencer.js',

  // Global setup/teardown for Docker
  globalSetup: './jest.globalSetup.js',
  globalTeardown: './jest.globalTeardown.js',

  // Per-file setup hooks
  setupFilesAfterEnv: ['./jest.setupAfterEnv.js'],

  // Environment
  testEnvironment: 'node',

  // Timeout - increased for API calls and audio processing
  testTimeout: 60000,

  // Verbose output for debugging
  verbose: true,

  // Force exit after tests complete (required for integration tests with DB connections)
  forceExit: true,

  // Transform (none needed for pure Node.js)
  transform: {}
};
