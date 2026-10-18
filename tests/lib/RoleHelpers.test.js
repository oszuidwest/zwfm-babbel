const { createUser } = require('./RoleHelpers');

describe('Role fixture diagnostics', () => {
  const originalAPI = global.api;
  const originalResources = global.resources;
  afterEach(() => { global.api = originalAPI; global.resources = originalResources; });

  test('failed user creation reports the response', async () => {
    global.api = { apiCall: jest.fn().mockResolvedValue({ status: 500, data: { detail: 'database offline' } }) };
    await expect(createUser('user', 'User', 'Password123!', 'viewer')).rejects.toThrow('POST /users failed: HTTP 500; body {"detail":"database offline"}');
  });

  test('failed conflict lookup reports its own response', async () => {
    global.api = { apiCall: jest.fn().mockResolvedValueOnce({ status: 409, data: {} }).mockResolvedValueOnce({ status: 503, data: { detail: 'query failed' } }) };
    await expect(createUser('user', 'User', 'Password123!', 'viewer')).rejects.toThrow('GET /users failed: HTTP 503; body {"detail":"query failed"}');
  });

  test('existing users are reused without tracking them for deletion', async () => {
    global.api = { apiCall: jest.fn().mockResolvedValueOnce({ status: 409 }).mockResolvedValueOnce({ status: 200, data: { data: [{ id: 7, username: 'user' }] } }) };
    global.resources = { track: jest.fn() };
    await expect(createUser('user', 'User', 'Password123!', 'viewer')).resolves.toBe(7);
    expect(global.resources.track).not.toHaveBeenCalled();
  });
});
