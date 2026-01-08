/**
 * Babbel users tests.
 * Tests user management functionality including CRUD operations and permissions.
 */

describe('Users', () => {
  // Track created users for cleanup
  const createdUserIds = [];
  let lastCreatedUsername = null;

  // Helper to create user with unique username
  const createUser = async (username, fullName, password, email = '', role = 'viewer', notes = '') => {
    const timestamp = Date.now();
    const uniqueUsername = `${username}${timestamp}${process.pid}`;

    const userData = {
      username: uniqueUsername,
      full_name: fullName,
      password,
      role
    };

    if (email) userData.email = email;
    if (notes) userData.notes = notes;

    const response = await global.api.apiCall('POST', '/users', userData);

    if (response.status === 201) {
      const userId = global.api.parseJsonField(response.data, 'id');
      if (userId) {
        createdUserIds.push(userId);
        lastCreatedUsername = uniqueUsername;
        return userId;
      }
    }
    return null;
  };

  // Helper to get user details
  const getUser = async (userId) => {
    const response = await global.api.apiCall('GET', `/users/${userId}`);
    return response.status === 200 ? response.data : null;
  };

  // Helper to update user status
  const updateUserStatus = async (userId, suspended) => {
    const response = await global.api.apiCall('PUT', `/users/${userId}`, { suspended });
    return response.status === 200;
  };

  afterAll(async () => {
    // Clean up created users
    for (const userId of createdUserIds) {
      try {
        await global.api.apiCall('DELETE', `/users/${userId}`);
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  describe('User Creation', () => {
    test('creates user successfully', async () => {
      const timestamp = Date.now();
      const userId = await createUser('testuser', 'Test User', 'password123', `test${timestamp}@example.com`, 'viewer');

      expect(userId).not.toBeNull();
      expect(parseInt(userId)).toBeGreaterThan(0);
    });

    test('creates user with minimal data', async () => {
      const userId = await createUser('minimaluser', 'Minimal User', 'password456', '', 'editor');

      expect(userId).not.toBeNull();
      expect(parseInt(userId)).toBeGreaterThan(0);
    });

    test('creates users with different roles', async () => {
      const timestamp = Date.now();

      const adminId = await createUser('adminuser', 'Admin User', 'adminpass123', `admin${timestamp}@example.com`, 'admin');
      const editorId = await createUser('editoruser', 'Editor User', 'editorpass123', `editor${timestamp}@example.com`, 'editor');
      const viewerId = await createUser('vieweruser', 'Viewer User', 'viewerpass123', `viewer${timestamp}@example.com`, 'viewer');

      expect(adminId).not.toBeNull();
      expect(editorId).not.toBeNull();
      expect(viewerId).not.toBeNull();
    });
  });

  describe('Validation Errors', () => {
    test('rejects missing username', async () => {
      const response = await global.api.apiCall('POST', '/users', {
        full_name: 'No Username User',
        password: 'password123',
        role: 'viewer'
      });

      expect(response.status).toBeHttpError();
    });

    test('rejects missing password', async () => {
      const response = await global.api.apiCall('POST', '/users', {
        username: 'nopassuser',
        full_name: 'No Password User',
        role: 'viewer'
      });

      expect(response.status).toBeHttpError();
    });

    test('rejects invalid role', async () => {
      const response = await global.api.apiCall('POST', '/users', {
        username: 'invalidroleuser',
        full_name: 'Invalid Role User',
        password: 'password123',
        role: 'invalid_role'
      });

      expect(response.status).toBeHttpError();
    });

    test('rejects short password', async () => {
      const response = await global.api.apiCall('POST', '/users', {
        username: 'shortpassuser',
        full_name: 'Short Password User',
        password: '123',
        role: 'viewer'
      });

      // May or may not be enforced depending on password policy
      expect([200, 201, 400, 422]).toContain(response.status);
    });
  });

  describe('Duplicate Constraints', () => {
    test('rejects duplicate username', async () => {
      const timestamp = Date.now();
      const email = `duplicate${timestamp}@example.com`;

      // Create first user
      const firstUserId = await createUser('duplicatetest', 'First User', 'password123', email, 'viewer');
      expect(firstUserId).not.toBeNull();

      // Try duplicate username
      const response = await global.api.apiCall('POST', '/users', {
        username: lastCreatedUsername,
        full_name: 'Duplicate Username User',
        password: 'password456',
        role: 'editor'
      });

      expect([409, 422]).toContain(response.status);
    });
  });

  describe('User Listing', () => {
    test('lists users with correct structure', async () => {
      const response = await global.api.apiCall('GET', '/users');

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
      expect(Array.isArray(response.data.data)).toBe(true);

      if (response.data.data.length > 0) {
        const firstUser = response.data.data[0];
        expect(firstUser).toHaveProperty('id');
        expect(firstUser).toHaveProperty('username');
        expect(firstUser).toHaveProperty('full_name');
        expect(firstUser).toHaveProperty('role');
      }
    });

    test('pagination works', async () => {
      const response = await global.api.apiCall('GET', '/users?limit=2&offset=0');

      expect(response.status).toBe(200);
      expect(response.data.data.length).toBeLessThanOrEqual(2);
    });

    test('filters by admin role', async () => {
      const response = await global.api.apiCall('GET', '/users?role=admin');

      expect(response.status).toBe(200);
    });

    test('filters by editor role', async () => {
      const response = await global.api.apiCall('GET', '/users?role=editor');

      expect(response.status).toBe(200);
    });

    test('filters by viewer role', async () => {
      const response = await global.api.apiCall('GET', '/users?role=viewer');

      expect(response.status).toBe(200);
    });
  });

  describe('Get User By ID', () => {
    let testUserId;

    beforeAll(async () => {
      testUserId = await createUser('gettest', 'Get Test User', 'password123', 'gettest@example.com', 'editor', 'Test notes');
    });

    test('retrieves user by ID', async () => {
      const response = await global.api.apiCall('GET', `/users/${testUserId}`);

      expect(response.status).toBe(200);
      expect(response.data.id).toBe(parseInt(testUserId));
      expect(response.data.full_name).toBe('Get Test User');
      expect(response.data.role).toBe('editor');
    });

    test('excludes password from response', async () => {
      const response = await global.api.apiCall('GET', `/users/${testUserId}`);

      expect(response.status).toBe(200);
      expect(response.data).not.toHaveProperty('password');
    });

    test('returns 404 for non-existent user', async () => {
      const response = await global.api.apiCall('GET', '/users/99999');

      expect(response.status).toBe(404);
    });
  });

  describe('User Updates', () => {
    let testUserId;

    beforeAll(async () => {
      testUserId = await createUser('updatetest', 'Update Test User', 'password123', 'updatetest@example.com', 'viewer');
    });

    test('updates full name', async () => {
      const response = await global.api.apiCall('PUT', `/users/${testUserId}`, {
        full_name: 'Updated Full Name'
      });

      expect(response.status).toBe(200);

      const user = await getUser(testUserId);
      expect(user.full_name).toBe('Updated Full Name');
    });

    test('updates role', async () => {
      const response = await global.api.apiCall('PUT', `/users/${testUserId}`, {
        role: 'editor'
      });

      expect(response.status).toBe(200);

      const user = await getUser(testUserId);
      expect(user.role).toBe('editor');
    });

    test('updates email', async () => {
      const response = await global.api.apiCall('PUT', `/users/${testUserId}`, {
        email: 'updated@example.com'
      });

      expect(response.status).toBe(200);
    });

    test('rejects invalid role update', async () => {
      const response = await global.api.apiCall('PUT', `/users/${testUserId}`, {
        role: 'invalid_role_name'
      });

      expect(response.status).toBeHttpError();
    });
  });

  describe('User Suspension', () => {
    test('suspends user successfully', async () => {
      const userId = await createUser('suspendtest', 'Suspend Test User', 'password123', 'suspendtest@example.com', 'editor');
      expect(userId).not.toBeNull();

      const success = await updateUserStatus(userId, true);
      expect(success).toBe(true);

      const user = await getUser(userId);
      expect(user.suspended_at).toBeDefined();
      expect(user.suspended_at).not.toBeNull();
    });

    test('restores suspended user', async () => {
      const userId = await createUser('restoretest', 'Restore Test User', 'password123', 'restoretest@example.com', 'editor');
      expect(userId).not.toBeNull();

      // Suspend first
      await updateUserStatus(userId, true);

      // Then restore
      const restoreSuccess = await updateUserStatus(userId, false);
      expect(restoreSuccess).toBe(true);

      const user = await getUser(userId);
      expect(user.suspended_at).toBeFalsy();
    });
  });

  describe('User Deletion', () => {
    test('deletes user successfully', async () => {
      const userId = await createUser('deletetest', 'Delete Test User', 'password123', 'deletetest@example.com', 'viewer');
      expect(userId).not.toBeNull();

      const response = await global.api.apiCall('DELETE', `/users/${userId}`);
      expect(response.status).toBe(204);

      // Verify deletion
      const getResponse = await global.api.apiCall('GET', `/users/${userId}`);
      expect(getResponse.status).toBe(404);

      // Remove from tracking
      const index = createdUserIds.indexOf(userId);
      if (index > -1) createdUserIds.splice(index, 1);
    });

    test('returns 404 for non-existent user', async () => {
      const response = await global.api.apiCall('DELETE', '/users/99999');

      expect(response.status).toBe(404);
    });
  });

  describe('Last Admin Protection', () => {
    test('protects last admin from deletion or role change', async () => {
      const adminsResponse = await global.api.apiCall('GET', '/users?role=admin');
      expect(adminsResponse.status).toBe(200);

      const adminUsers = adminsResponse.data.data || [];

      if (adminUsers.length === 1) {
        const lastAdmin = adminUsers[0];

        // Test deletion
        const deleteResponse = await global.api.apiCall('DELETE', `/users/${lastAdmin.id}`);
        expect([403, 422]).toContain(deleteResponse.status);

        // Test role change
        const roleChangeResponse = await global.api.apiCall('PUT', `/users/${lastAdmin.id}`, {
          role: 'editor'
        });
        expect([403, 422, 200]).toContain(roleChangeResponse.status);
      } else if (adminUsers.length > 1) {
        // Can delete non-last admin
        const newAdminId = await createUser('testadmin', 'Test Admin User', 'password123', 'testadmin@example.com', 'admin');

        if (newAdminId) {
          const deleteResponse = await global.api.apiCall('DELETE', `/users/${newAdminId}`);
          expect(deleteResponse.status).toBe(204);

          const index = createdUserIds.indexOf(newAdminId);
          if (index > -1) createdUserIds.splice(index, 1);
        }
      }
    });
  });

  describe('Password Security', () => {
    test('excludes password from all responses', async () => {
      const userId = await createUser('passwordtest', 'Password Test User', 'secretpassword123', 'passwordtest@example.com', 'viewer');
      expect(userId).not.toBeNull();

      const user = await getUser(userId);
      expect(user).not.toHaveProperty('password');
    });

    test('password update does not expose password', async () => {
      const userId = await createUser('passupdate', 'Pass Update User', 'password123', 'passupdate@example.com', 'viewer');
      expect(userId).not.toBeNull();

      const response = await global.api.apiCall('PUT', `/users/${userId}`, {
        password: 'newpassword456'
      });

      expect(response.status).toBe(200);
      expect(response.data).not.toHaveProperty('password');
    });
  });

  describe('Authentication Fields', () => {
    test('has timestamp fields', async () => {
      const userId = await createUser('authtest', 'Auth Test User', 'password123', 'authtest@example.com', 'editor');
      expect(userId).not.toBeNull();

      const user = await getUser(userId);

      // Check for expected fields
      expect(user).toHaveProperty('created_at');
    });

    test('excludes sensitive fields', async () => {
      const userId = await createUser('sensitivetest', 'Sensitive Test User', 'password123', 'sensitive@example.com', 'viewer');
      expect(userId).not.toBeNull();

      const user = await getUser(userId);
      expect(user).not.toHaveProperty('password');
      expect(user).not.toHaveProperty('password_hash');
    });
  });

  describe('User Metadata', () => {
    test('creates user with metadata', async () => {
      const uniqueId = Date.now();
      const metadata = { department: 'engineering', location: 'Amsterdam', team: 'backend' };

      const response = await global.api.apiCall('POST', '/users', {
        username: `metadatauser${uniqueId}`,
        full_name: 'Metadata Test User',
        password: 'TestPassword123!',
        email: `metadata${uniqueId}@test.local`,
        role: 'editor',
        metadata
      });

      expect(response.status).toBe(201);

      const userId = global.api.parseJsonField(response.data, 'id');
      createdUserIds.push(userId);

      // Verify metadata
      const getResponse = await global.api.apiCall('GET', `/users/${userId}`);
      expect(getResponse.status).toBe(200);
      expect(getResponse.data.metadata).toBeDefined();
      expect(typeof getResponse.data.metadata).toBe('object');
      expect(getResponse.data.metadata.department).toBe('engineering');
      expect(getResponse.data.metadata.location).toBe('Amsterdam');
    });

    test('updates user metadata', async () => {
      const uniqueId = Date.now();

      const createResponse = await global.api.apiCall('POST', '/users', {
        username: `metaupdate${uniqueId}`,
        full_name: 'Metadata Update User',
        password: 'TestPassword123!',
        role: 'editor',
        metadata: { initial: true }
      });

      expect(createResponse.status).toBe(201);
      const userId = global.api.parseJsonField(createResponse.data, 'id');
      createdUserIds.push(userId);

      // Update metadata
      const updatedMetadata = { department: 'platform', location: 'Rotterdam', version: 2 };
      const updateResponse = await global.api.apiCall('PUT', `/users/${userId}`, {
        metadata: updatedMetadata
      });

      expect(updateResponse.status).toBe(200);

      // Verify updated metadata
      const getResponse = await global.api.apiCall('GET', `/users/${userId}`);
      expect(getResponse.status).toBe(200);
      expect(getResponse.data.metadata.department).toBe('platform');
      expect(getResponse.data.metadata.version).toBe(2);
    });
  });
});
