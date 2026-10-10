// Provides one shared helper set per integration-test file.
const ApiHelper = require('./lib/ApiHelper');
const ResourceManager = require('./lib/ResourceManager');
const TestHelpers = require('./lib/TestHelpers');

let apiHelper;
let resourceManager;
let testHelpers;

beforeAll(async () => {
  apiHelper = new ApiHelper();
  resourceManager = new ResourceManager(apiHelper);
  testHelpers = new TestHelpers(apiHelper);

  global.api = apiHelper;
  global.resources = resourceManager;
  global.helpers = testHelpers;

  // Authentication tests manage their own session state.
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
  if (resourceManager) {
    await resourceManager.cleanupAll();
  }
});
