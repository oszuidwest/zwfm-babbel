const usersSchema = require('../lib/schemas/users.schema');
const { generateCrudTests, generateQueryTests, generateTrashedTests, generateValidationTests } = require('../lib/generators');
const { createMySQLExecutor } = require('../lib/MySQLHelper');

describe('Users', () => {
  // Generate standard CRUD, Query, and Validation tests
  generateCrudTests(usersSchema);
  generateQueryTests(usersSchema);
  generateValidationTests(usersSchema);

  // === BUSINESS LOGIC TESTS ===
  // Tests specific to user behavior that can't be generated

  describe('Query Validation', () => {
    // The users repository once routed query errors through the MySQL error
    // parser, which matched these field names as database failures.
    test.each([
      ['filter[no such table: x]', '1'],
      ['filter[Duplicate entry]', '1'],
      ['sort', 'Duplicate entry'],
      ['sort', '-no such table: x']
    ])('when %s=%s names an unknown field, then returns 422', async (key, value) => {
      const response = await global.api.apiCall('GET', `/users?${new URLSearchParams({ [key]: value })}`);
      expect(response.status).toBe(422);
      expect(response.headers['content-type']).toMatch(/application\/problem\+json/);
    });
  });

  // Strings sort by the column collation, not by code point. The fixtures mix
  // case and accents and include collation ties (full_name is not unique,
  // unlike voice and station names). Only rows with the unique prefix are
  // listed, so other suites' data cannot change the outcome.
  describe('Full Name Sorting Collation', () => {
    const mysql = createMySQLExecutor();
    const prefix = `SortCollation ${Date.now()} ${process.pid}`;
    const fixtures = [];
    const rankFixtures = () => mysql.rankByColumn('users', 'full_name', fixtures.map(user => user.id));
    const isAscending = ranks => ranks.every((rank, index) => index === 0 || rank >= ranks[index - 1]);

    beforeAll(async () => {
      for (const [index, suffix] of ['cherry', 'Banana', '\u00e9cho', 'apple', 'delta', 'Delta', 'echo'].entries()) {
        const fullName = `${prefix} ${suffix}`;
        const response = await global.api.apiCall('POST', '/users', {
          username: `sortcollation${Date.now()}${process.pid}${index}`,
          full_name: fullName,
          password: 'TestPassword123!',
          role: 'viewer'
        });
        expect(response.status).toBe(201);
        global.resources.track('users', response.data.id);
        fixtures.push({ id: response.data.id, fullName });
      }
    });

    test('when fixtures mix case and accents, then code point order disagrees with the collation and ties exist', () => {
      const ranks = rankFixtures();
      const byCodePoint = [...fixtures].sort((a, b) => (a.fullName < b.fullName ? -1 : Number(a.fullName > b.fullName)));
      expect(isAscending(byCodePoint.map(user => ranks.get(user.id)))).toBe(false);
      expect(new Set(ranks.values()).size).toBeLessThan(fixtures.length);
    });

    test.each([['full_name', 1], ['-full_name', -1]])('when sorting the fixtures by %s, then the order follows the collation', async (sort, direction) => {
      const response = await global.api.apiCall(
        'GET',
        `/users?filter[full_name][like]=${encodeURIComponent(prefix)}&sort=${sort}&limit=100`
      );
      expect(response.status).toBe(200);
      const listed = response.data.data;
      expect(listed.map(user => user.id).sort((a, b) => a - b))
        .toEqual(fixtures.map(user => user.id).sort((a, b) => a - b));

      const ranks = rankFixtures();
      expect(isAscending(listed.map(user => direction * ranks.get(user.id)))).toBe(true);
    });
  });

  describe('Soft-Deleted Users', () => {
    let username;

    beforeAll(async () => {
      username = `trashedtest${Date.now()}${process.pid}`;
      const created = await global.api.apiCall('POST', '/users', {
        username,
        full_name: 'Trashed Test User',
        password: 'TestPassword123!',
        role: 'viewer'
      });
      expect(created.status).toBe(201);
      const deleted = await global.api.apiCall('DELETE', `/users/${created.data.id}`);
      expect(deleted.status).toBe(204);
    });

    // The active admin and the deleted fixture user.
    generateTrashedTests('/users', () => `filter[username][in]=admin,${username}`);
  });

  describe('User Suspension', () => {
    let userId;

    beforeAll(async () => {
      // Create user to test suspension
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
      // Uses userId from beforeAll

      const response = await global.api.apiCall('PUT', `/users/${userId}`, { suspended: true });

      expect(response.status).toBe(200);

      const user = await global.api.apiCall('GET', `/users/${userId}`);
      expect(user.data.suspended_at).toBeDefined();
      expect(user.data.suspended_at).not.toBeNull();
    });

    test('when restoring suspended user, then suspended_at cleared', async () => {
      // Ensure user is suspended
      await global.api.apiCall('PUT', `/users/${userId}`, { suspended: true });

      const response = await global.api.apiCall('PUT', `/users/${userId}`, { suspended: false });

      expect(response.status).toBe(200);

      const user = await global.api.apiCall('GET', `/users/${userId}`);
      expect(user.data.suspended_at).toBeFalsy();
    });
  });

  describe('Last Admin Protection', () => {
    test('when deleting or demoting last admin, then protected', async () => {
      // Get admin users
      const adminsResponse = await global.api.apiCall('GET', '/users?filter[role]=admin');
      expect(adminsResponse.status).toBe(200);

      const adminUsers = adminsResponse.data.data || [];

      if (adminUsers.length === 1) {
        // Last admin should be protected
        const lastAdmin = adminUsers[0];

        const deleteResponse = await global.api.apiCall('DELETE', `/users/${lastAdmin.id}`);
        expect([403, 422]).toContain(deleteResponse.status);

        const roleChangeResponse = await global.api.apiCall('PUT', `/users/${lastAdmin.id}`, {
          role: 'editor'
        });
        expect([403, 422]).toContain(roleChangeResponse.status);
      } else if (adminUsers.length > 1) {
        // Non-last admin can be deleted
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
      // Create user to test password security
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
      const response = await global.api.apiCall('GET', `/users/${userId}`);

      expect(response.status).toBe(200);
      expect(response.data).not.toHaveProperty('password');
      expect(response.data).not.toHaveProperty('password_hash');
    });

    test('when updating password, then not exposed in response', async () => {
      const response = await global.api.apiCall('PUT', `/users/${userId}`, {
        password: 'NewPassword456!'
      });

      expect(response.status).toBe(200);
      expect(response.data).not.toHaveProperty('password');
      expect(response.data).not.toHaveProperty('password_hash');
    });
  });

  describe('User Metadata', () => {
    test('when creating with metadata, then stored', async () => {
      const metadata = { department: 'engineering', location: 'Amsterdam', team: 'backend' };
      const userData = {
        username: `metadatauser${Date.now()}${process.pid}`,
        full_name: 'Metadata Test User',
        password: 'TestPassword123!',
        role: 'editor',
        metadata
      };

      const response = await global.api.apiCall('POST', '/users', userData);

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
      const createResponse = await global.api.apiCall('POST', '/users', {
        username: `metaupdate${Date.now()}${process.pid}`,
        full_name: 'Metadata Update User',
        password: 'TestPassword123!',
        role: 'editor',
        metadata: { initial: true }
      });
      expect(createResponse.status).toBe(201);
      global.resources.track('users', createResponse.data.id);

      const updatedMetadata = { department: 'platform', location: 'Rotterdam', version: 2 };
      const updateResponse = await global.api.apiCall('PUT', `/users/${createResponse.data.id}`, {
        metadata: updatedMetadata
      });

      expect(updateResponse.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/users/${createResponse.data.id}`);
      expect(getResponse.status).toBe(200);
      expect(getResponse.data.metadata.department).toBe('platform');
      expect(getResponse.data.metadata.version).toBe(2);
    });
  });
});
