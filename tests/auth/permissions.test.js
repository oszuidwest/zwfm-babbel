/**
 * Babbel permissions tests.
 * Tests role-based access control (RBAC) functionality across different user roles.
 */

describe('Permissions', () => {
  // Track created users for cleanup
  const createdUserIds = [];

  // Helper to create a user
  const createUser = async (username, fullName, password, role) => {
    const response = await global.api.apiCall('POST', '/users', {
      username,
      full_name: fullName,
      password,
      role
    });

    if (response.status === 201) {
      const userId = global.api.parseJsonField(response.data, 'id');
      if (userId) {
        createdUserIds.push(userId);
        return userId;
      }
    } else if (response.status === 409) {
      // User already exists, find it
      const userResponse = await global.api.apiCall('GET', '/users');
      if (userResponse.status === 200 && userResponse.data.data) {
        const user = userResponse.data.data.find(u => u.username === username);
        if (user) return String(user.id);
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

  afterAll(async () => {
    // Ensure admin session for cleanup
    await restoreAdmin();

    // Delete created users
    for (const userId of createdUserIds) {
      await global.api.apiCall('DELETE', `/users/${userId}`);
    }
  });

  describe('Admin Permissions', () => {
    beforeAll(async () => {
      await restoreAdmin();
    });

    test('admin can create users', async () => {
      const uniqueUsername = `testadminuser${Date.now()}`;
      const response = await global.api.apiCall('POST', '/users', {
        username: uniqueUsername,
        full_name: 'Test Admin User',
        password: 'testpass123',
        role: 'editor'
      });

      expect([201, 409]).toContain(response.status);

      if (response.status === 201) {
        const userId = global.api.parseJsonField(response.data, 'id');
        if (userId) createdUserIds.push(userId);
      }
    });

    test('admin can list users', async () => {
      const response = await global.api.apiCall('GET', '/users');

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
    });

    test('admin can update users', async () => {
      const userId = await createUser(`updatetest${Date.now()}`, 'Update Test', 'testpass123', 'viewer');
      expect(userId).not.toBeNull();

      const response = await global.api.apiCall('PUT', `/users/${userId}`, {
        full_name: 'Updated Test User',
        role: 'viewer'
      });

      expect(response.status).toBe(200);
    });
  });

  describe('Editor Permissions', () => {
    let editorUsername;

    beforeAll(async () => {
      await restoreAdmin();

      editorUsername = `testeditor${Date.now()}`;
      const editorId = await createUser(editorUsername, 'Test Editor', 'testpass123', 'editor');
      expect(editorId).not.toBeNull();

      // Switch to editor
      const switched = await switchToUser(editorUsername, 'testpass123');
      expect(switched).toBe(true);
    });

    afterAll(async () => {
      await restoreAdmin();
    });

    const readEndpoints = ['/stations', '/voices', '/stories', '/bulletins'];

    test.each(readEndpoints)('editor can read %s', async (endpoint) => {
      const response = await global.api.apiCall('GET', endpoint);

      expect(response.status).toBe(200);
    });

    test('editor can create stations', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: `Editor Test Station ${Date.now()}`,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });

      expect(response.status).toBe(201);

      // Track for cleanup
      if (response.status === 201) {
        const id = global.api.parseJsonField(response.data, 'id');
        if (id) global.resources.track('stations', id);
      }
    });

    test('editor cannot create users', async () => {
      const response = await global.api.apiCall('POST', '/users', {
        username: 'unauthorized',
        full_name: 'Unauthorized User',
        password: 'test',
        role: 'viewer'
      });

      expect(response.status).toBeHttpError();
    });

    test('editor cannot delete users', async () => {
      const response = await global.api.apiCall('DELETE', '/users/1');

      expect(response.status).toBeHttpError();
    });
  });

  describe('Viewer Permissions', () => {
    let viewerUsername;

    beforeAll(async () => {
      await restoreAdmin();

      viewerUsername = `testviewer${Date.now()}`;
      const viewerId = await createUser(viewerUsername, 'Test Viewer', 'testpass123', 'viewer');
      expect(viewerId).not.toBeNull();

      // Switch to viewer
      const switched = await switchToUser(viewerUsername, 'testpass123');
      expect(switched).toBe(true);
    });

    afterAll(async () => {
      await restoreAdmin();
    });

    const readEndpoints = ['/stations', '/voices', '/stories', '/bulletins'];

    test.each(readEndpoints)('viewer can read %s', async (endpoint) => {
      const response = await global.api.apiCall('GET', endpoint);

      expect(response.status).toBe(200);
    });

    test('viewer cannot create stations', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: 'Viewer Test Station',
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });

      expect(response.status).toBeHttpError();
    });

    test('viewer cannot create voices', async () => {
      const response = await global.api.apiCall('POST', '/voices', {
        name: 'Viewer Test Voice'
      });

      expect(response.status).toBeHttpError();
    });

    test('viewer cannot create stories', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Viewer Test Story',
        content: 'Test',
        voice_id: 1
      });

      expect(response.status).toBeHttpError();
    });

    test('viewer cannot list users', async () => {
      const response = await global.api.apiCall('GET', '/users');

      expect(response.status).toBeHttpError();
    });
  });

  describe('Suspended User', () => {
    let suspendedUsername;

    beforeAll(async () => {
      await restoreAdmin();

      suspendedUsername = `suspendeduser${Date.now()}`;
      const suspendedId = await createUser(suspendedUsername, 'Suspended User', 'testpass123', 'editor');
      expect(suspendedId).not.toBeNull();

      // Suspend the user (soft delete)
      const response = await global.api.apiCall('DELETE', `/users/${suspendedId}`);
      expect(response.status).toBe(204);
    });

    test('suspended user cannot login', async () => {
      const response = await global.api.apiCall('POST', '/sessions', {
        username: suspendedUsername,
        password: 'testpass123'
      });

      expect(response.status).toBe(401);
    });
  });
});
