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
    test('when username invalid, then returns 401', async () => {
      const response = await global.api.apiCall('POST', '/sessions', {
        username: 'nonexistent',
        password: 'password'
      });

      expect(response.status).toBe(401);
    });

    test('when password invalid, then returns 401', async () => {
      const response = await global.api.apiCall('POST', '/sessions', {
        username: 'admin',
        password: 'wrongpassword'
      });

      expect(response.status).toBe(401);
    });

    test('when credentials empty, then returns 422 naming both fields', async () => {
      // Required-field validation runs before the credential check.
      const response = await global.api.apiCall('POST', '/sessions', {});

      expect(response.status).toBe(422);
      expect(response.data.errors).toEqual(expect.arrayContaining([
        expect.objectContaining({ field: 'username', code: 'required' }),
        expect.objectContaining({ field: 'password', code: 'required' })
      ]));
    });

    test('when login body has an unknown field, then returns 400', async () => {
      const response = await global.api.apiCall('POST', '/sessions', {
        username: 'admin',
        password: 'admin',
        remember: true
      });

      expect(response.status).toBe(400);
      expect(response.data.errors).toEqual([
        expect.objectContaining({ field: 'remember', code: 'unknown_field' })
      ]);
    });
  });

  describe('Successful Login', () => {
    test('when admin logs in, then the session contains the user', async () => {
      const loginResponse = await global.api.apiLogin('admin', 'admin');

      expect(loginResponse.status).toBe(201);
      expect(await global.api.isSessionActive()).toBe(true);
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

    test('when fetching session, then returns current user', async () => {
      const sessionInfo = await global.api.getCurrentSession();

      expect(sessionInfo).not.toBeNull();
      expect(sessionInfo).toHaveProperty('username');
      expect(sessionInfo).toHaveProperty('permissions');
      expect(sessionInfo.permissions.stations).toContain('read');
    });

    test('when logging out, then session destroyed', async () => {
      const logoutResponse = await global.api.apiLogout();

      expect(logoutResponse.status).toBe(204);
      expect(await global.api.isSessionActive()).toBe(false);
    });

    test('when accessing protected endpoint after logout, then rejected', async () => {
      await global.api.apiLogout();

      const response = await global.api.apiCall('GET', '/sessions/current');

      expect(response.status).toBe(401);
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
        const response = await global.api.apiCall(method, endpoint);

        expect(response.status).toBe(401);
      }
    );
  });

  describe('Invalid Session Token', () => {
    beforeAll(async () => {
      global.api.clearCookies();
    });

    test('when session token invalid, then rejected', async () => {
      const response = await global.api.http({
        method: 'get',
        url: `${global.api.apiUrl}/sessions/current`,
        headers: {
          'Cookie': 'babbel_session=invalid_session_token_12345'
        }
      });

      expect(response.status).toBe(401);
    });

    test('when session token malformed, then rejected', async () => {
      const response = await global.api.http({
        method: 'get',
        url: `${global.api.apiUrl}/sessions/current`,
        headers: {
          'Cookie': 'babbel_session=malformed'
        }
      });

      expect(response.status).toBe(401);
    });
  });
});
