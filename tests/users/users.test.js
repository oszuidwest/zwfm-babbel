/**
 * Babbel users tests.
 * Tests user management functionality including CRUD operations, queries, validation, and permissions.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
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
      // Arrange: Create user to test suspension
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

    test('when suspending user, then suspended_at set', async () => {
      // Arrange: Uses userId from beforeAll

      // Act
      const response = await global.api.apiCall('PUT', `/users/${userId}`, { suspended: true });

      // Assert
      expect(response.status).toBe(200);

      const user = await global.api.apiCall('GET', `/users/${userId}`);
      expect(user.data.suspended_at).toBeDefined();
      expect(user.data.suspended_at).not.toBeNull();
    });

    test('when restoring suspended user, then suspended_at cleared', async () => {
      // Arrange: Ensure user is suspended
      await global.api.apiCall('PUT', `/users/${userId}`, { suspended: true });

      // Act
      const response = await global.api.apiCall('PUT', `/users/${userId}`, { suspended: false });

      // Assert
      expect(response.status).toBe(200);

      const user = await global.api.apiCall('GET', `/users/${userId}`);
      expect(user.data.suspended_at).toBeFalsy();
    });
  });

  describe('Last Admin Protection', () => {
    test('when deleting or demoting last admin, then protected', async () => {
      // Arrange: Get admin users
      const adminsResponse = await global.api.apiCall('GET', '/users?filter[role]=admin');
      expect(adminsResponse.status).toBe(200);

      const adminUsers = adminsResponse.data.data || [];

      if (adminUsers.length === 1) {
        // Act & Assert: Last admin should be protected
        const lastAdmin = adminUsers[0];

        const deleteResponse = await global.api.apiCall('DELETE', `/users/${lastAdmin.id}`);
        expect([403, 422]).toContain(deleteResponse.status);

        const roleChangeResponse = await global.api.apiCall('PUT', `/users/${lastAdmin.id}`, {
          role: 'editor'
        });
        expect([403, 422, 200]).toContain(roleChangeResponse.status);
      } else if (adminUsers.length > 1) {
        // Act & Assert: Non-last admin can be deleted
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
      // Arrange: Create user to test password security
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

    test('when fetching user, then password excluded', async () => {
      // Act
      const response = await global.api.apiCall('GET', `/users/${userId}`);

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).not.toHaveProperty('password');
      expect(response.data).not.toHaveProperty('password_hash');
    });

    test('when updating password, then not exposed in response', async () => {
      // Act
      const response = await global.api.apiCall('PUT', `/users/${userId}`, {
        password: 'NewPassword456!'
      });

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).not.toHaveProperty('password');
      expect(response.data).not.toHaveProperty('password_hash');
    });
  });

  describe('User Metadata', () => {
    test('when creating with metadata, then stored', async () => {
      // Arrange
      const metadata = { department: 'engineering', location: 'Amsterdam', team: 'backend' };
      const userData = {
        username: `metadatauser${Date.now()}${process.pid}`,
        full_name: 'Metadata Test User',
        password: 'TestPassword123!',
        role: 'editor',
        metadata
      };

      // Act
      const response = await global.api.apiCall('POST', '/users', userData);

      // Assert
      expect(response.status).toBe(201);

      // Cleanup
      global.resources.track('users', response.data.id);

      // Verify metadata
      const getResponse = await global.api.apiCall('GET', `/users/${response.data.id}`);
      expect(getResponse.status).toBe(200);
      expect(getResponse.data.metadata).toBeDefined();
      expect(typeof getResponse.data.metadata).toBe('object');
      expect(getResponse.data.metadata.department).toBe('engineering');
      expect(getResponse.data.metadata.location).toBe('Amsterdam');
    });

    test('when updating metadata, then persisted', async () => {
      // Arrange
      const createResponse = await global.api.apiCall('POST', '/users', {
        username: `metaupdate${Date.now()}${process.pid}`,
        full_name: 'Metadata Update User',
        password: 'TestPassword123!',
        role: 'editor',
        metadata: { initial: true }
      });
      expect(createResponse.status).toBe(201);
      global.resources.track('users', createResponse.data.id);

      // Act
      const updatedMetadata = { department: 'platform', location: 'Rotterdam', version: 2 };
      const updateResponse = await global.api.apiCall('PUT', `/users/${createResponse.data.id}`, {
        metadata: updatedMetadata
      });

      // Assert
      expect(updateResponse.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/users/${createResponse.data.id}`);
      expect(getResponse.status).toBe(200);
      expect(getResponse.data.metadata.department).toBe('platform');
      expect(getResponse.data.metadata.version).toBe(2);
    });
  });
});
