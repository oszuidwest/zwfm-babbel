/**
 * Babbel permissions tests.
 * Tests role-based access control (RBAC) functionality across different user roles.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
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

    test('when admin creates user, then succeeds', async () => {
      // Arrange
      const uniqueUsername = `testadminuser${Date.now()}`;

      // Act
      const response = await global.api.apiCall('POST', '/users', {
        username: uniqueUsername,
        full_name: 'Test Admin User',
        password: 'testpass123',
        role: 'editor'
      });

      // Assert
      expect([201, 409]).toContain(response.status);

      // Cleanup
      if (response.status === 201) {
        const userId = global.api.parseJsonField(response.data, 'id');
        if (userId) createdUserIds.push(userId);
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
      const userId = await createUser(`updatetest${Date.now()}`, 'Update Test', 'testpass123', 'viewer');
      expect(userId).not.toBeNull();

      // Act
      const response = await global.api.apiCall('PUT', `/users/${userId}`, {
        full_name: 'Updated Test User',
        role: 'viewer'
      });

      // Assert
      expect(response.status).toBe(200);
    });
  });

  describe('Editor Permissions', () => {
    let editorUsername;

    beforeAll(async () => {
      // Arrange: Create editor and switch session
      await restoreAdmin();

      editorUsername = `testeditor${Date.now()}`;
      const editorId = await createUser(editorUsername, 'Test Editor', 'testpass123', 'editor');
      expect(editorId).not.toBeNull();

      const switched = await switchToUser(editorUsername, 'testpass123');
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
      if (response.status === 201) {
        const id = global.api.parseJsonField(response.data, 'id');
        if (id) global.resources.track('stations', id);
      }
    });

    test('when editor creates user, then forbidden', async () => {
      // Arrange
      const userData = {
        username: 'unauthorized',
        full_name: 'Unauthorized User',
        password: 'test',
        role: 'viewer'
      };

      // Act
      const response = await global.api.apiCall('POST', '/users', userData);

      // Assert
      expect(response.status).toBeHttpError();
    });

    test('when editor deletes user, then forbidden', async () => {
      // Arrange: Editor session from beforeAll (no delete permission)

      // Act
      const response = await global.api.apiCall('DELETE', '/users/1');

      // Assert
      expect(response.status).toBeHttpError();
    });
  });

  describe('Viewer Permissions', () => {
    let viewerUsername;

    beforeAll(async () => {
      // Arrange: Create viewer and switch session
      await restoreAdmin();

      viewerUsername = `testviewer${Date.now()}`;
      const viewerId = await createUser(viewerUsername, 'Test Viewer', 'testpass123', 'viewer');
      expect(viewerId).not.toBeNull();

      const switched = await switchToUser(viewerUsername, 'testpass123');
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

    test('when viewer creates station, then forbidden', async () => {
      // Arrange
      const stationData = {
        name: 'Viewer Test Station',
        max_stories_per_block: 5,
        pause_seconds: 2.0
      };

      // Act
      const response = await global.api.apiCall('POST', '/stations', stationData);

      // Assert
      expect(response.status).toBeHttpError();
    });

    test('when viewer creates voice, then forbidden', async () => {
      // Arrange
      const voiceData = { name: 'Viewer Test Voice' };

      // Act
      const response = await global.api.apiCall('POST', '/voices', voiceData);

      // Assert
      expect(response.status).toBeHttpError();
    });

    test('when viewer creates story, then forbidden', async () => {
      // Arrange
      const storyData = {
        title: 'Viewer Test Story',
        content: 'Test',
        voice_id: 1
      };

      // Act
      const response = await global.api.apiCall('POST', '/stories', storyData);

      // Assert
      expect(response.status).toBeHttpError();
    });

    test('when viewer lists users, then forbidden', async () => {
      // Arrange: Viewer session from beforeAll (no user access)

      // Act
      const response = await global.api.apiCall('GET', '/users');

      // Assert
      expect(response.status).toBeHttpError();
    });
  });

  describe('Suspended User', () => {
    let suspendedUsername;

    beforeAll(async () => {
      // Arrange: Create and suspend a user
      await restoreAdmin();

      suspendedUsername = `suspendeduser${Date.now()}`;
      const suspendedId = await createUser(suspendedUsername, 'Suspended User', 'testpass123', 'editor');
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
        password: 'testpass123'
      });

      // Assert
      expect(response.status).toBe(401);
    });
  });
});
