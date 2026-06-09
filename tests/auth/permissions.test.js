const ApiHelper = require('../lib/ApiHelper');

describe('Permissions', () => {
  // Helper to create a user
  const createUser = async (username, fullName, password, role) => {
    const response = await global.api.apiCall('POST', '/users', {
      username,
      full_name: fullName,
      password,
      role
    });

    if (response.status === 201 && response.data?.id) {
      global.resources.track('users', response.data.id);
      return response.data.id;
    } else if (response.status === 409) {
      // User already exists, find it
      const userResponse = await global.api.apiCall('GET', '/users');
      if (userResponse.status === 200 && userResponse.data.data) {
        const user = userResponse.data.data.find(u => u.username === username);
        if (user) return user.id;
      }
    }
    return null;
  };

  // Helper to switch user session
  const switchToUser = async (username, password) => {
    const loginResponse = await global.api.apiLogin(username, password);
    return loginResponse.status === 201;
  };

  // Restore admin session
  const restoreAdmin = async () => {
    await global.api.apiLogin('admin', 'admin');
  };

  beforeAll(async () => {
    await restoreAdmin();
    const response = await global.api.apiCall('GET', '/settings/tts');
    expect(response.status).toBe(200);
  });

  afterAll(async () => {
    await restoreAdmin();
  });

  describe('Admin Permissions', () => {
    beforeAll(async () => {
      await restoreAdmin();
    });

    test('when admin creates user, then succeeds', async () => {
      // Arrange: valid payload (same structure as editor/viewer tests to prove RBAC)
      const uniqueUsername = `testadminuser${Date.now()}`;

      // Act
      const response = await global.api.apiCall('POST', '/users', {
        username: uniqueUsername,
        full_name: 'Test Admin User',
        password: 'TestPass123!',
        role: 'editor'
      });

      // Assert
      expect(response.status).toBe(201);

      // Cleanup
      if (response.data?.id) {
        global.resources.track('users', response.data.id);
      }
    });

    test('when admin lists users, then returns list', async () => {
      // Arrange: Admin session from beforeAll

      // Act
      const response = await global.api.apiCall('GET', '/users');

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
    });

    test('when admin updates user, then succeeds', async () => {
      // Arrange
      const userId = await createUser(`updatetest${Date.now()}`, 'Update Test', 'TestPass123!', 'viewer');
      expect(userId).not.toBeNull();

      // Act
      const response = await global.api.apiCall('PUT', `/users/${userId}`, {
        full_name: 'Updated Test User',
        role: 'viewer'
      });

      // Assert
      expect(response.status).toBe(200);
    });

    test('when admin manages pronunciation rules, then reaches handler', async () => {
      const getResponse = await global.api.apiCall('GET', '/settings/tts/pronunciations');
      expect(getResponse.status).toBe(200);

      const putResponse = await global.api.apiCall('PUT', '/settings/tts/pronunciations', { rules: [] });
      expect(putResponse.status).toBe(200);
    });
  });

  describe('Editor Permissions', () => {
    let editorUsername;

    beforeAll(async () => {
      // Arrange: Create editor and switch session
      await restoreAdmin();

      editorUsername = `testeditor${Date.now()}`;
      const editorId = await createUser(editorUsername, 'Test Editor', 'TestPass123!', 'editor');
      expect(editorId).not.toBeNull();

      const switched = await switchToUser(editorUsername, 'TestPass123!');
      expect(switched).toBe(true);
    });

    afterAll(async () => {
      await restoreAdmin();
    });

    const readEndpoints = ['/stations', '/voices', '/stories', '/bulletins'];

    test.each(readEndpoints)('when editor reads %s, then succeeds', async (endpoint) => {
      // Arrange: Editor session from beforeAll

      // Act
      const response = await global.api.apiCall('GET', endpoint);

      // Assert
      expect(response.status).toBe(200);
    });

    test('when editor creates station, then succeeds', async () => {
      // Arrange
      const stationData = {
        name: `Editor Test Station ${Date.now()}`,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      };

      // Act
      const response = await global.api.apiCall('POST', '/stations', stationData);

      // Assert
      expect(response.status).toBe(201);

      // Cleanup
      if (response.status === 201 && response.data?.id) {
        global.resources.track('stations', response.data.id);
      }
    });

    test('when editor creates user, then forbidden', async () => {
      // Arrange: valid payload ensures 403 is from RBAC, not validation
      const userData = {
        username: `editortest${Date.now()}`,
        full_name: 'Editor Test User',
        password: 'TestPass123!',
        role: 'viewer'
      };

      // Act
      const response = await global.api.apiCall('POST', '/users', userData);

      // Assert
      expect(response.status).toBe(403);
    });

    test('when editor deletes user, then forbidden', async () => {
      // Arrange: Editor session from beforeAll (no delete permission)

      // Act
      const response = await global.api.apiCall('DELETE', '/users/1');

      // Assert
      expect(response.status).toBe(403);
    });

    test('when editor manages pronunciation rules, then reaches handler', async () => {
      const getResponse = await global.api.apiCall('GET', '/settings/tts/pronunciations');
      expect(getResponse.status).toBe(200);

      const putResponse = await global.api.apiCall('PUT', '/settings/tts/pronunciations', { rules: [] });
      expect(putResponse.status).toBe(200);
    });
  });

  describe('Viewer Permissions', () => {
    let viewerUsername;

    beforeAll(async () => {
      // Arrange: Create viewer and switch session
      await restoreAdmin();

      viewerUsername = `testviewer${Date.now()}`;
      const viewerId = await createUser(viewerUsername, 'Test Viewer', 'TestPass123!', 'viewer');
      expect(viewerId).not.toBeNull();

      const switched = await switchToUser(viewerUsername, 'TestPass123!');
      expect(switched).toBe(true);
    });

    afterAll(async () => {
      await restoreAdmin();
    });

    const readEndpoints = ['/stations', '/voices', '/stories', '/bulletins'];

    test.each(readEndpoints)('when viewer reads %s, then succeeds', async (endpoint) => {
      // Arrange: Viewer session from beforeAll

      // Act
      const response = await global.api.apiCall('GET', endpoint);

      // Assert
      expect(response.status).toBe(200);
    });

    test.each([
      ['when viewer creates station, then forbidden', 'POST', '/stations', () => ({
        name: `ViewerStation_${Date.now()}`,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      })],
      ['when viewer creates voice, then forbidden', 'POST', '/voices', () => ({
        name: `ViewerVoice_${Date.now()}`
      })],
      ['when viewer creates story, then forbidden', 'POST', '/stories', () => {
        const today = new Date().toISOString().split('T')[0];
        const nextYear = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        return {
          title: 'Viewer Test Story',
          text: 'Valid story content for RBAC test.',
          start_date: today,
          end_date: nextYear
        };
      }],
      ['when viewer lists users, then forbidden', 'GET', '/users', () => undefined]
    ])('%s', async (_name, method, endpoint, bodyFactory) => {
      const response = await global.api.apiCall(method, endpoint, bodyFactory());
      expect(response.status).toBe(403);
    });

    test('when viewer reads pronunciation rules, then reaches handler', async () => {
      const response = await global.api.apiCall('GET', '/settings/tts/pronunciations');
      expect(response.status).toBe(200);
    });

    test('when viewer writes pronunciation rules, then forbidden before handler', async () => {
      const response = await global.api.apiCall('PUT', '/settings/tts/pronunciations', { rules: [] });
      expect(response.status).toBe(403);
    });
  });

  describe('Unauthenticated Permissions', () => {
    afterAll(async () => {
      await restoreAdmin();
    });

    test.each([
      ['GET', '/settings/tts/pronunciations', undefined],
      ['PUT', '/settings/tts/pronunciations', { rules: [] }]
    ])('when unauthenticated user calls %s %s, then unauthorized', async (method, endpoint, body) => {
      global.api.clearCookies();

      const response = await global.api.apiCall(method, endpoint, body);
      expect(response.status).toBe(401);
    });
  });

  describe('Suspended User', () => {
    let suspendedUsername;

    beforeAll(async () => {
      // Arrange: Create and suspend a user
      await restoreAdmin();

      suspendedUsername = `suspendeduser${Date.now()}`;
      const suspendedId = await createUser(suspendedUsername, 'Suspended User', 'TestPass123!', 'editor');
      expect(suspendedId).not.toBeNull();

      // Suspend the user (soft delete)
      const response = await global.api.apiCall('DELETE', `/users/${suspendedId}`);
      expect(response.status).toBe(204);
    });

    test('when suspended user logs in, then rejected', async () => {
      // Arrange: Suspended user created in beforeAll

      // Act
      const response = await global.api.apiCall('POST', '/sessions', {
        username: suspendedUsername,
        password: 'TestPass123!'
      });

      // Assert
      expect(response.status).toBe(401);
    });

    test('when suspended admin has an existing session, then pronunciation routes are unauthorized', async () => {
      await restoreAdmin();

      const username = `suspendedadmin${Date.now()}`;
      const suspendedAdminId = await createUser(username, 'Suspended Admin', 'TestPass123!', 'admin');
      expect(suspendedAdminId).not.toBeNull();

      const suspendedAdminApi = new ApiHelper();
      const login = await suspendedAdminApi.apiLogin(username, 'TestPass123!');
      expect(login.status).toBe(201);

      const suspendResponse = await global.api.apiCall('PUT', `/users/${suspendedAdminId}`, { suspended: true });
      expect(suspendResponse.status).toBe(200);

      const getResponse = await suspendedAdminApi.apiCall('GET', '/settings/tts/pronunciations');
      expect(getResponse.status).toBe(401);

      const putResponse = await suspendedAdminApi.apiCall('PUT', '/settings/tts/pronunciations', { rules: [] });
      expect(putResponse.status).toBe(401);
    });
  });
});
