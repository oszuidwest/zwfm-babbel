// Pure unit tests run without Docker or API setup.
module.exports = {
  rootDir: '.',
  testMatch: ['**/lib/**/*.test.js'],
  testEnvironment: 'node',
  testTimeout: 10000,
  verbose: true,
  transform: {}
};
