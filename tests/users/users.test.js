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
  // case and accents and include collation ties, which need a non-unique
  // column: voice and station names reject collation-equal duplicates such
  // as delta and Delta. Only rows with the unique prefix are listed, so other
  // suites' data cannot change the outcome.
  describe('Full Name Sorting Collation', () => {
    const stamp = `${Date.now()}${process.pid}`;
    const prefix = `SortCollation ${stamp}`;
    const fixtures = [];
    let ranks;
    const sorted = (values, direction = 1) => [...values].sort((a, b) => direction * (a - b));

    beforeAll(async () => {
      for (const [index, suffix] of ['cherry', 'Banana', '\u00e9cho', 'apple', 'delta', 'Delta', 'echo'].entries()) {
        const fullName = `${prefix} ${suffix}`;
        const response = await global.api.apiCall('POST', '/users', {
          ...usersSchema.createValidData(`sortcollation${stamp}${index}`),
          full_name: fullName
        });
        expect(response.status).toBe(201);
        global.resources.track('users', response.data.id);
        fixtures.push({ id: response.data.id, fullName });
      }
      ranks = createMySQLExecutor().rankByColumn('users', 'full_name', fixtures.map(user => user.id));
    });

    test('when fixtures mix case and accents, then code point order disagrees with the collation and ties exist', () => {
      const byCodePoint = [...fixtures].sort((a, b) => (a.fullName < b.fullName ? -1 : Number(a.fullName > b.fullName)));
      const codePointRanks = byCodePoint.map(user => ranks.get(user.id));
      expect(codePointRanks).not.toEqual(sorted(codePointRanks));
      expect(new Set(ranks.values()).size).toBeLessThan(fixtures.length);
    });

    test.each([['full_name', 1], ['-full_name', -1]])('when sorting the fixtures by %s, then the order follows the collation', async (sort, direction) => {
      const response = await global.api.apiCall(
        'GET',
        `/users?filter[full_name][like]=${encodeURIComponent(prefix)}&sort=${sort}&limit=100`
      );
      expect(response.status).toBe(200);
      const listed = response.data.data;
      expect(sorted(listed.map(user => user.id))).toEqual(sorted(fixtures.map(user => user.id)));

      const listedRanks = listed.map(user => ranks.get(user.id));
      expect(listedRanks).toEqual(sorted(listedRanks, direction));
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
    let adminId;

    beforeAll(async () => {
      const adminsResponse = await global.api.apiCall('GET', '/users?filter[role]=admin');
      expect(adminsResponse.status).toBe(200);
      const adminUsers = adminsResponse.data.data || [];
      expect(adminUsers).toHaveLength(1);
      adminId = adminUsers[0].id;
    });

    test('when deleting the last admin, then returns a conflict', async () => {
      const deleteResponse = await global.api.apiCall('DELETE', `/users/${adminId}`);
      expect(deleteResponse.status).toBe(409);
      expect(deleteResponse.data.code).toBe('user.last_admin');
    });

    test.each([
      ['PUT', { role: 'editor' }],
      ['PUT', { suspended: true }],
      ['PATCH', { action: 'suspend' }]
    ])('when %s %j on the last admin, then returns a conflict and keeps the admin active', async (method, body) => {
      const response = await global.api.apiCall(method, `/users/${adminId}`, body);
      expect(response.status).toBe(409);
      expect(response.data.code).toBe('user.last_admin');

      const admin = await global.api.apiCall('GET', `/users/${adminId}`);
      expect(admin.data.role).toBe('admin');
      expect(admin.data.suspended_at).toBeFalsy();
    });

    test('when another active admin exists, then an admin can be suspended and demoted', async () => {
      const created = await global.api.apiCall('POST', '/users', {
        ...usersSchema.createValidData(`secondadmin${Date.now()}${process.pid}`),
        role: 'admin'
      });
      expect(created.status).toBe(201);
      global.resources.track('users', created.data.id);

      const suspended = await global.api.apiCall('PATCH', `/users/${created.data.id}`, { action: 'suspend' });
      expect(suspended.status).toBe(200);
      // A suspended admin no longer counts, so demoting it leaves the active admin in place.
      const demoted = await global.api.apiCall('PUT', `/users/${created.data.id}`, { role: 'editor' });
      expect(demoted.status).toBe(200);
      expect(demoted.data.role).toBe('editor');
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
