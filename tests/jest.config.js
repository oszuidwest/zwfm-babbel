module.exports = {
  rootDir: '.',

  testMatch: ['**/*.test.js'],

  // Exclude pure-unit tests under tests/lib/. setupFilesAfterEnv loads shared
  // integration helpers before test-file-level jest.mock() calls can run, so
  // helper tests belong in tests/jest.unit.config.js instead.
  testPathIgnorePatterns: [
    '/node_modules/',
    '<rootDir>/lib/.*\\.test\\.js$'
  ],

  // Shared database state requires serial execution and explicit ordering.
  maxWorkers: 1,
  testSequencer: './jest.testSequencer.js',

  globalSetup: './jest.globalSetup.js',
  globalTeardown: './jest.globalTeardown.js',

  setupFilesAfterEnv: ['./jest.setupAfterEnv.js'],

  testEnvironment: 'node',

  // Audio processing can exceed Jest's default timeout.
  testTimeout: 60000,

  verbose: true,

  // Database clients may retain handles after the suites finish.
  forceExit: true,

  transform: {}
};
