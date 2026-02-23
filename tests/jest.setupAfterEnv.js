// Jest setup after environment - runs before each test file
// Provides global access to ApiHelper, ResourceManager, and TestHelpers
const ApiHelper = require('./lib/ApiHelper');
const ResourceManager = require('./lib/ResourceManager');
const TestHelpers = require('./lib/TestHelpers');

// Create shared instances for each test file
let apiHelper;
let resourceManager;
let testHelpers;

beforeAll(async () => {
  // Initialize API helper
  apiHelper = new ApiHelper();
  resourceManager = new ResourceManager(apiHelper);
  testHelpers = new TestHelpers(apiHelper);

  // Make available globally for tests
  global.api = apiHelper;
  global.resources = resourceManager;
  global.helpers = testHelpers;

  // Establish admin session (skip for auth tests which test login itself)
  const testPath = expect.getState().testPath || '';
  const isAuthTest = testPath.includes('/auth/auth.test.js');

  if (!isAuthTest) {
    const loginResponse = await apiHelper.apiLogin();
    if (loginResponse.status < 200 || loginResponse.status > 299) {
      throw new Error(`Could not establish admin session (HTTP ${loginResponse.status}). Is the API running?`);
    }
  }
});

afterAll(async () => {
  // Clean up all tracked resources in FK order
  if (resourceManager) {
    await resourceManager.cleanupAll();
  }
});

