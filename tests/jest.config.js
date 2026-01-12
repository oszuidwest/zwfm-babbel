// Jest configuration for Babbel API integration tests
module.exports = {
  // Run tests from the tests directory
  rootDir: '.',

  // Test file pattern - .test.js files
  testMatch: ['**/*.test.js'],

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

  // Force exit after tests complete
  forceExit: true,

  // Detect open handles (useful for debugging hanging tests)
  detectOpenHandles: true,

  // Module paths
  moduleDirectories: ['node_modules', 'lib'],

  // Transform (none needed for pure Node.js)
  transform: {}
};
