/**
 * Babbel account lockout tests.
 * Verifies that local login enforces the configured failed-attempt threshold
 * and that the WHERE-clause guard in updateLoginFailure prevents stale
 * pre-lock requests from extending an active lockout.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

const { execSync } = require('child_process');

// Matches BABBEL_AUTH_MAX_LOGIN_ATTEMPTS default in internal/config/config.go.
const MAX_LOGIN_ATTEMPTS = 5;

// Reads locked_until as UNIX seconds for the given user, or 0 when NULL.
// The users.locked_until column is TIMESTAMP (1-second precision), so callers
// that compare two reads must allow enough wall-clock time between them for a
// missing guard to shift the value into the next second.
const readLockedUntilUnix = (uname) => {
  if (!/^[a-z0-9_]+$/i.test(uname)) {
    throw new Error(`refusing to query MySQL with unsafe username: ${uname}`);
  }
  const sql = `SELECT IFNULL(UNIX_TIMESTAMP(locked_until), 0) FROM users WHERE username = '${uname}';`;
  const out = execSync(
    `docker exec -i babbel-mysql mysql -ubabbel -pbabbel -N -s -e "${sql}" babbel`,
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
  ).trim();
  return Number.parseInt(out, 10);
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

describe('Account Lockout', () => {
  let username;
  const password = 'LockoutTest123!';

  beforeAll(async () => {
    await global.api.apiLogin('admin', 'admin');

    username = `lockouttest${Date.now()}`;
    const response = await global.api.apiCall('POST', '/users', {
      username,
      full_name: 'Lockout Test',
      password,
      role: 'viewer'
    });

    expect(response.status).toBe(201);
    expect(response.data?.id).toBeDefined();
    global.resources.track('users', response.data.id);
  });

  afterAll(async () => {
    // Restore admin session so ResourceManager cleanup and subsequent
    // suites run with admin credentials.
    await global.api.apiLogin('admin', 'admin');
  });

  test('when wrong password attempts stay below threshold, then each returns 401 and account remains usable', async () => {
    // Arrange
    const attempts = MAX_LOGIN_ATTEMPTS - 1;

    // Act
    for (let i = 0; i < attempts; i++) {
      const response = await global.api.apiCall('POST', '/sessions', {
        username,
        password: 'wrong-password'
      });
      expect(response.status).toBe(401);
    }

    // Assert: correct credentials still work because threshold was not reached.
    const loginResponse = await global.api.apiLogin(username, password);
    expect(loginResponse.status).toBe(201);

    // Cleanup: successful login resets the counter, so the next test starts fresh.
    await global.api.apiLogin('admin', 'admin');
  });

  test('when wrong password attempts reach threshold, then account is locked and correct password is also rejected', async () => {
    // Arrange: exhaust the threshold.
    for (let i = 0; i < MAX_LOGIN_ATTEMPTS; i++) {
      const response = await global.api.apiCall('POST', '/sessions', {
        username,
        password: 'wrong-password'
      });
      expect(response.status).toBe(401);
    }

    // Act: try the correct password against the now-locked account.
    const response = await global.api.apiCall('POST', '/sessions', {
      username,
      password
    });

    // Assert
    expect(response.status).toBe(401);
  });

  test('when locked account is spammed with parallel wrong-password attempts, then locked_until is not extended', async () => {
    // Arrange: account is already locked from the previous test. Capture the
    // initial lockout timestamp, then wait long enough that a missing guard
    // would push locked_until into the next TIMESTAMP second.
    const lockedUntilBefore = readLockedUntilUnix(username);
    expect(lockedUntilBefore).toBeGreaterThan(0);

    await sleep(2000);

    // Act: fire concurrent wrong-password attempts. Without the WHERE-clause
    // guard each would recompute locked_until = now + lockout_duration.
    const spamCount = 10;
    const responses = await Promise.all(
      Array.from({ length: spamCount }, () =>
        global.api.apiCall('POST', '/sessions', {
          username,
          password: 'wrong-password'
        })
      )
    );

    // Assert: every attempt rejected with 401, and locked_until is unchanged.
    for (const response of responses) {
      expect(response.status).toBe(401);
    }
    const lockedUntilAfter = readLockedUntilUnix(username);
    expect(lockedUntilAfter).toBe(lockedUntilBefore);
  });
});
