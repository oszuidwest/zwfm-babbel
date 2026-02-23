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
  // Initialize API helper with cookie persistence
  apiHelper = new ApiHelper();
  resourceManager = new ResourceManager(apiHelper);
  testHelpers = new TestHelpers(apiHelper);

  // Make available globally for tests
  global.api = apiHelper;
  global.resources = resourceManager;
  global.helpers = testHelpers;

  // Load existing cookies (for session persistence across test files)
  await apiHelper.loadCookies();

  // Ensure admin session exists (skip for auth tests which test login itself)
  const testPath = expect.getState().testPath || '';
  const isAuthTest = testPath.includes('/auth/auth.test.js');

  if (!isAuthTest) {
    const isActive = await apiHelper.isSessionActive();
    if (!isActive) {
      const loginResponse = await apiHelper.apiLogin();
      if (loginResponse.status < 200 || loginResponse.status > 299) {
        throw new Error(`Could not establish admin session (HTTP ${loginResponse.status}). Is the API running?`);
      }
    }
  }
});

afterAll(async () => {
  // Clean up all tracked resources in FK order
  if (resourceManager) {
    await resourceManager.cleanupAll();
  }

  // Save cookies for next test file
  if (apiHelper) {
    await apiHelper.saveCookies();
  }
});

// Add custom matchers for API testing
expect.extend({
  /**
   * Check if HTTP status code is an error (4xx or 5xx)
   */
  toBeHttpError(received) {
    const pass = received >= 400 && received <= 599;
    return {
      message: () =>
        `expected ${received} ${pass ? 'not ' : ''}to be HTTP error (4xx/5xx)`,
      pass
    };
  }
});
