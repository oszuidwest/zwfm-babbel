/**
 * Babbel authentication tests.
 * Tests basic authentication functionality including login, logout, and session management.
 */

describe('Authentication', () => {
  beforeAll(async () => {
    // Start with clean session state
    await global.api.apiLogout();
  });

  afterAll(async () => {
    // Restore admin session for subsequent tests
    await global.api.apiLogin('admin', 'admin');
  });

  describe('Auth Configuration', () => {
    test('auth config endpoint is publicly accessible', async () => {
      const response = await global.api.http({
        method: 'get',
        url: `${global.api.apiUrl}/auth/config`
      });

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('methods');
      expect(Array.isArray(response.data.methods)).toBe(true);
      expect(response.data.methods).toContain('local');
    });
  });

  describe('Login Failures', () => {
    test('rejects invalid username', async () => {
      const response = await global.api.apiCall('POST', '/sessions', {
        username: 'nonexistent',
        password: 'password'
      });

      expect(response.status).toBe(401);
    });

    test('rejects invalid password', async () => {
      const response = await global.api.apiCall('POST', '/sessions', {
        username: 'admin',
        password: 'wrongpassword'
      });

      expect(response.status).toBe(401);
    });

    test('rejects empty credentials', async () => {
      const response = await global.api.apiCall('POST', '/sessions', {});

      expect(response.status).toBeHttpError();
    });
  });

  describe('Successful Login', () => {
    test('admin login succeeds and creates active session', async () => {
      const loginResponse = await global.api.apiLogin('admin', 'admin');

      expect(loginResponse.status).toBe(201);
      expect(await global.api.isSessionActive()).toBe(true);
    });

    test('session contains correct user information', async () => {
      const sessionInfo = await global.api.getCurrentSession();

      expect(sessionInfo).not.toBeNull();
      expect(sessionInfo.username).toBe('admin');
      expect(sessionInfo.role).toBe('admin');
    });
  });

  describe('Session Management', () => {
    beforeEach(async () => {
      await global.api.apiLogin('admin', 'admin');
    });

    test('can retrieve current session', async () => {
      const sessionInfo = await global.api.getCurrentSession();

      expect(sessionInfo).not.toBeNull();
      expect(sessionInfo).toHaveProperty('username');
    });

    test('logout destroys session', async () => {
      const logoutResponse = await global.api.apiLogout();

      expect(logoutResponse.status).toBe(204);
      expect(await global.api.isSessionActive()).toBe(false);
    });

    test('protected endpoint rejects after logout', async () => {
      await global.api.apiLogout();

      const response = await global.api.apiCall('GET', '/sessions/current');

      expect(response.status).toBeHttpError();
    });
  });

  describe('Unauthorized Access', () => {
    beforeAll(async () => {
      await global.api.apiLogout();
    });

    const protectedEndpoints = [
      { method: 'GET', endpoint: '/stations' },
      { method: 'GET', endpoint: '/voices' },
      { method: 'GET', endpoint: '/stories' },
      { method: 'GET', endpoint: '/users' },
      { method: 'GET', endpoint: '/sessions/current' }
    ];

    test.each(protectedEndpoints)(
      'rejects unauthorized access to $method $endpoint',
      async ({ method, endpoint }) => {
        const response = await global.api.apiCall(method, endpoint);

        expect(response.status).toBeHttpError();
      }
    );
  });

  describe('Invalid Session Token', () => {
    beforeAll(async () => {
      await global.api.clearCookies();
    });

    test('rejects invalid session token', async () => {
      const response = await global.api.http({
        method: 'get',
        url: `${global.api.apiUrl}/sessions/current`,
        headers: {
          'Cookie': 'babbel_session=invalid_session_token_12345'
        }
      });

      expect(response.status).toBeHttpError();
    });

    test('rejects malformed session token', async () => {
      const response = await global.api.http({
        method: 'get',
        url: `${global.api.apiUrl}/sessions/current`,
        headers: {
          'Cookie': 'babbel_session=malformed'
        }
      });

      expect(response.status).toBeHttpError();
    });
  });
});
