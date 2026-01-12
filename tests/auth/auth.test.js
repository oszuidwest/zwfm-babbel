/**
 * Babbel authentication tests.
 * Tests basic authentication functionality including login, logout, and session management.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
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
    test('when fetching auth config, then publicly accessible', async () => {
      // Act
      const response = await global.api.http({
        method: 'get',
        url: `${global.api.apiUrl}/auth/config`
      });

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('methods');
      expect(Array.isArray(response.data.methods)).toBe(true);
      expect(response.data.methods).toContain('local');
    });
  });

  describe('Login Failures', () => {
    test('when username invalid, then returns 401', async () => {
      // Act
      const response = await global.api.apiCall('POST', '/sessions', {
        username: 'nonexistent',
        password: 'password'
      });

      // Assert
      expect(response.status).toBe(401);
    });

    test('when password invalid, then returns 401', async () => {
      // Act
      const response = await global.api.apiCall('POST', '/sessions', {
        username: 'admin',
        password: 'wrongpassword'
      });

      // Assert
      expect(response.status).toBe(401);
    });

    test('when credentials empty, then returns error', async () => {
      // Act
      const response = await global.api.apiCall('POST', '/sessions', {});

      // Assert
      expect(response.status).toBeHttpError();
    });
  });

  describe('Successful Login', () => {
    test('when admin logs in, then session created', async () => {
      // Act
      const loginResponse = await global.api.apiLogin('admin', 'admin');

      // Assert
      expect(loginResponse.status).toBe(201);
      expect(await global.api.isSessionActive()).toBe(true);
    });

    test('when session active, then contains user info', async () => {
      // Act
      const sessionInfo = await global.api.getCurrentSession();

      // Assert
      expect(sessionInfo).not.toBeNull();
      expect(sessionInfo.username).toBe('admin');
      expect(sessionInfo.role).toBe('admin');
    });
  });

  describe('Session Management', () => {
    beforeEach(async () => {
      await global.api.apiLogin('admin', 'admin');
    });

    test('when fetching session, then returns current user', async () => {
      // Act
      const sessionInfo = await global.api.getCurrentSession();

      // Assert
      expect(sessionInfo).not.toBeNull();
      expect(sessionInfo).toHaveProperty('username');
    });

    test('when logging out, then session destroyed', async () => {
      // Act
      const logoutResponse = await global.api.apiLogout();

      // Assert
      expect(logoutResponse.status).toBe(204);
      expect(await global.api.isSessionActive()).toBe(false);
    });

    test('when accessing protected endpoint after logout, then rejected', async () => {
      // Arrange
      await global.api.apiLogout();

      // Act
      const response = await global.api.apiCall('GET', '/sessions/current');

      // Assert
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
      'when unauthorized accessing $method $endpoint, then rejected',
      async ({ method, endpoint }) => {
        // Act
        const response = await global.api.apiCall(method, endpoint);

        // Assert
        expect(response.status).toBeHttpError();
      }
    );
  });

  describe('Invalid Session Token', () => {
    beforeAll(async () => {
      await global.api.clearCookies();
    });

    test('when session token invalid, then rejected', async () => {
      // Act
      const response = await global.api.http({
        method: 'get',
        url: `${global.api.apiUrl}/sessions/current`,
        headers: {
          'Cookie': 'babbel_session=invalid_session_token_12345'
        }
      });

      // Assert
      expect(response.status).toBeHttpError();
    });

    test('when session token malformed, then rejected', async () => {
      // Act
      const response = await global.api.http({
        method: 'get',
        url: `${global.api.apiUrl}/sessions/current`,
        headers: {
          'Cookie': 'babbel_session=malformed'
        }
      });

      // Assert
      expect(response.status).toBeHttpError();
    });
  });
});
