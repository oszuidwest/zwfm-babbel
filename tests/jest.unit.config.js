// Jest configuration for pure-unit tests under tests/lib/.
// No Docker, no globalSetup, no API readiness check -- runs offline.
module.exports = {
  rootDir: '.',
  testMatch: ['**/lib/**/*.test.js'],
  testEnvironment: 'node',
  testTimeout: 10000,
  verbose: true,
  transform: {}
};
