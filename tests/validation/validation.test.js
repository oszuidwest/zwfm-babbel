/**
 * Babbel security and cross-cutting validation tests.
 * Tests security-related validation that applies across all endpoints.
 *
 * Note: Resource-specific validation (field types, boundaries, required fields)
 * is now tested via generateValidationTests() in each resource's test file.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

describe('Security Validation', () => {
  // Track created resources for cleanup
  const createdStationIds = [];

  afterAll(async () => {
    for (const id of createdStationIds) {
      try { await global.api.apiCall('DELETE', `/stations/${id}`); } catch {}
    }
  });

  describe('SQL Injection Prevention', () => {
    const sqlPayloads = [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "'; SELECT * FROM users; --",
      "' UNION SELECT password FROM users --",
      "admin'--",
      "admin' OR '1'='1' --"
    ];

    test.each(sqlPayloads)('when SQL payload submitted: %s, then handled safely', async (payload) => {
      // Arrange
      const data = {
        name: payload,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      };

      // Act
      const response = await global.api.apiCall('POST', '/stations', data);

      // Assert: Should be rejected (422) or safely handled (201/409)
      expect([201, 409, 422]).toContain(response.status);

      // Cleanup
      if (response.status === 201) {
        const stationId = global.api.parseJsonField(response.data, 'id');
        if (stationId) createdStationIds.push(stationId);
      }
    });
  });

  describe('XSS Prevention', () => {
    const xssPayloads = [
      "<script>alert('xss')</script>",
      "<img src=x onerror=alert('xss')>",
      "javascript:alert('xss')",
      "<svg/onload=alert('xss')>",
      "'><script>alert('xss')</script>"
    ];

    test.each(xssPayloads)('when XSS payload submitted: %s, then handled safely', async (payload) => {
      // Arrange
      const data = {
        name: payload,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      };

      // Act
      const response = await global.api.apiCall('POST', '/stations', data);

      // Assert
      expect([201, 409, 422]).toContain(response.status);

      // Cleanup
      if (response.status === 201) {
        const stationId = global.api.parseJsonField(response.data, 'id');
        if (stationId) createdStationIds.push(stationId);
      }
    });
  });

  describe('Path Traversal Prevention', () => {
    const pathPayloads = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '....//....//....//etc/passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
    ];

    test.each(pathPayloads)('when path traversal payload submitted: %s, then handled safely', async (payload) => {
      // Arrange
      const data = {
        name: payload,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      };

      // Act
      const response = await global.api.apiCall('POST', '/stations', data);

      // Assert
      expect([201, 409, 422]).toContain(response.status);

      // Cleanup
      if (response.status === 201) {
        const stationId = global.api.parseJsonField(response.data, 'id');
        if (stationId) createdStationIds.push(stationId);
      }
    });
  });
});

describe('Story Date Validation', () => {
  let stationId, voiceId;

  beforeAll(async () => {
    // Arrange: Create dependencies for date validation tests
    const station = await global.helpers.createStation(global.resources, 'DateValidationStation');
    const voice = await global.helpers.createVoice(global.resources, 'DateValidationVoice');
    stationId = station.id;
    voiceId = voice.id;
  });

  test('when start_date invalid format, then returns 422', async () => {
    // Arrange
    const storyData = {
      title: `DateTest ${Date.now()}`,
      text: 'Test content',
      voice_id: parseInt(voiceId, 10),
      target_stations: [parseInt(stationId, 10)],
      start_date: 'invalid-date',
      status: 'active',
      weekdays: 127
    };

    // Act
    const response = await global.api.apiCall('POST', '/stories', storyData);

    // Assert
    expect(response.status).toBe(422);
  });

  test('when end_date invalid format, then returns 422', async () => {
    // Arrange
    const storyData = {
      title: `DateTest ${Date.now()}`,
      text: 'Test content',
      voice_id: parseInt(voiceId, 10),
      target_stations: [parseInt(stationId, 10)],
      end_date: 'invalid-date',
      status: 'active',
      weekdays: 127
    };

    // Act
    const response = await global.api.apiCall('POST', '/stories', storyData);

    // Assert
    expect(response.status).toBe(422);
  });

  test('when end_date before start_date, then returns 422', async () => {
    // Arrange
    const storyData = {
      title: `DateTest ${Date.now()}`,
      text: 'Test content',
      voice_id: parseInt(voiceId, 10),
      target_stations: [parseInt(stationId, 10)],
      start_date: '2024-12-31',
      end_date: '2024-01-01',
      status: 'active',
      weekdays: 127
    };

    // Act
    const response = await global.api.apiCall('POST', '/stories', storyData);

    // Assert
    expect(response.status).toBe(422);
  });
});
