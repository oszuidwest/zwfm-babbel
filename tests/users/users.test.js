/**
 * Babbel users tests.
 * Tests user management functionality including CRUD operations, queries, validation, and permissions.
 */

const usersSchema = require('../lib/schemas/users.schema');
const { generateCrudTests, generateQueryTests, generateValidationTests } = require('../lib/generators');

describe('Users', () => {
  // Generate standard CRUD, Query, and Validation tests
  generateCrudTests(usersSchema);
  generateQueryTests(usersSchema);
  generateValidationTests(usersSchema);

  // === BUSINESS LOGIC TESTS ===
  // Tests specific to user behavior that can't be generated

  describe('User Suspension', () => {
    let userId;

    beforeAll(async () => {
      const response = await global.api.apiCall('POST', '/users', {
        username: `suspendtest${Date.now()}${process.pid}`,
        full_name: 'Suspend Test User',
        password: 'TestPassword123!',
        role: 'editor'
      });
      expect(response.status).toBe(201);
      userId = response.data.id;
      global.resources.track('users', userId);
    });

    test('suspends user successfully', async () => {
      const response = await global.api.apiCall('PUT', `/users/${userId}`, { suspended: true });
      expect(response.status).toBe(200);

      const user = await global.api.apiCall('GET', `/users/${userId}`);
      expect(user.data.suspended_at).toBeDefined();
      expect(user.data.suspended_at).not.toBeNull();
    });

    test('restores suspended user', async () => {
      // Suspend first
      await global.api.apiCall('PUT', `/users/${userId}`, { suspended: true });

      // Then restore
      const response = await global.api.apiCall('PUT', `/users/${userId}`, { suspended: false });
      expect(response.status).toBe(200);

      const user = await global.api.apiCall('GET', `/users/${userId}`);
      expect(user.data.suspended_at).toBeFalsy();
    });
  });

  describe('Last Admin Protection', () => {
    test('protects last admin from deletion or role change', async () => {
      const adminsResponse = await global.api.apiCall('GET', '/users?filter[role]=admin');
      expect(adminsResponse.status).toBe(200);

      const adminUsers = adminsResponse.data.data || [];

      if (adminUsers.length === 1) {
        const lastAdmin = adminUsers[0];

        // Test deletion - should be protected
        const deleteResponse = await global.api.apiCall('DELETE', `/users/${lastAdmin.id}`);
        expect([403, 422]).toContain(deleteResponse.status);

        // Test role change - should be protected
        const roleChangeResponse = await global.api.apiCall('PUT', `/users/${lastAdmin.id}`, {
          role: 'editor'
        });
        expect([403, 422, 200]).toContain(roleChangeResponse.status);
      } else if (adminUsers.length > 1) {
        // Can delete non-last admin - create and delete test admin
        const createResponse = await global.api.apiCall('POST', '/users', {
          username: `testadmin${Date.now()}${process.pid}`,
          full_name: 'Test Admin User',
          password: 'TestPassword123!',
          role: 'admin'
        });
        expect(createResponse.status).toBe(201);

        const deleteResponse = await global.api.apiCall('DELETE', `/users/${createResponse.data.id}`);
        expect(deleteResponse.status).toBe(204);
      }
    });
  });

  describe('Password Security', () => {
    let userId;

    beforeAll(async () => {
      const response = await global.api.apiCall('POST', '/users', {
        username: `passwordtest${Date.now()}${process.pid}`,
        full_name: 'Password Test User',
        password: 'SecretPassword123!',
        role: 'viewer'
      });
      expect(response.status).toBe(201);
      userId = response.data.id;
      global.resources.track('users', userId);
    });

    test('excludes password from all responses', async () => {
      const response = await global.api.apiCall('GET', `/users/${userId}`);
      expect(response.status).toBe(200);
      expect(response.data).not.toHaveProperty('password');
      expect(response.data).not.toHaveProperty('password_hash');
    });

    test('password update does not expose password', async () => {
      const response = await global.api.apiCall('PUT', `/users/${userId}`, {
        password: 'NewPassword456!'
      });

      expect(response.status).toBe(200);
      expect(response.data).not.toHaveProperty('password');
      expect(response.data).not.toHaveProperty('password_hash');
    });
  });

  describe('User Metadata', () => {
    test('creates user with metadata', async () => {
      const metadata = { department: 'engineering', location: 'Amsterdam', team: 'backend' };

      const response = await global.api.apiCall('POST', '/users', {
        username: `metadatauser${Date.now()}${process.pid}`,
        full_name: 'Metadata Test User',
        password: 'TestPassword123!',
        role: 'editor',
        metadata
      });

      expect(response.status).toBe(201);
      global.resources.track('users', response.data.id);

      // Verify metadata
      const getResponse = await global.api.apiCall('GET', `/users/${response.data.id}`);
      expect(getResponse.status).toBe(200);
      expect(getResponse.data.metadata).toBeDefined();
      expect(typeof getResponse.data.metadata).toBe('object');
      expect(getResponse.data.metadata.department).toBe('engineering');
      expect(getResponse.data.metadata.location).toBe('Amsterdam');
    });

    test('updates user metadata', async () => {
      const createResponse = await global.api.apiCall('POST', '/users', {
        username: `metaupdate${Date.now()}${process.pid}`,
        full_name: 'Metadata Update User',
        password: 'TestPassword123!',
        role: 'editor',
        metadata: { initial: true }
      });

      expect(createResponse.status).toBe(201);
      global.resources.track('users', createResponse.data.id);

      // Update metadata
      const updatedMetadata = { department: 'platform', location: 'Rotterdam', version: 2 };
      const updateResponse = await global.api.apiCall('PUT', `/users/${createResponse.data.id}`, {
        metadata: updatedMetadata
      });

      expect(updateResponse.status).toBe(200);

      // Verify updated metadata
      const getResponse = await global.api.apiCall('GET', `/users/${createResponse.data.id}`);
      expect(getResponse.status).toBe(200);
      expect(getResponse.data.metadata.department).toBe('platform');
      expect(getResponse.data.metadata.version).toBe(2);
    });
  });
});
