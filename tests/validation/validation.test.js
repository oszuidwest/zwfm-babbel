/**
 * Babbel security and cross-cutting validation tests.
 * Tests security-related validation that applies across all endpoints.
 *
 * Note: Resource-specific validation (field types, boundaries, required fields)
 * is now tested via generateValidationTests() in each resource's test file.
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

    test.each(sqlPayloads)('safely handles SQL payload: %s', async (payload) => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: payload,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });

      // Should be rejected (422) or safely handled (201/409)
      expect([201, 409, 422]).toContain(response.status);

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

    test.each(xssPayloads)('safely handles XSS payload: %s', async (payload) => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: payload,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });

      expect([201, 409, 422]).toContain(response.status);

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

    test.each(pathPayloads)('safely handles path traversal payload: %s', async (payload) => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: payload,
        max_stories_per_block: 5,
        pause_seconds: 2.0
      });

      expect([201, 409, 422]).toContain(response.status);

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
    const station = await global.helpers.createStation(global.resources, 'DateValidationStation');
    const voice = await global.helpers.createVoice(global.resources, 'DateValidationVoice');
    stationId = station.id;
    voiceId = voice.id;
  });

  test('rejects invalid start date format', async () => {
    const response = await global.api.apiCall('POST', '/stories', {
      title: `DateTest ${Date.now()}`,
      text: 'Test content',
      voice_id: parseInt(voiceId, 10),
      target_stations: [parseInt(stationId, 10)],
      start_date: 'invalid-date',
      status: 'active',
      weekdays: 127
    });
    expect(response.status).toBe(422);
  });

  test('rejects invalid end date format', async () => {
    const response = await global.api.apiCall('POST', '/stories', {
      title: `DateTest ${Date.now()}`,
      text: 'Test content',
      voice_id: parseInt(voiceId, 10),
      target_stations: [parseInt(stationId, 10)],
      end_date: 'invalid-date',
      status: 'active',
      weekdays: 127
    });
    expect(response.status).toBe(422);
  });

  test('rejects end date before start date', async () => {
    const response = await global.api.apiCall('POST', '/stories', {
      title: `DateTest ${Date.now()}`,
      text: 'Test content',
      voice_id: parseInt(voiceId, 10),
      target_stations: [parseInt(stationId, 10)],
      start_date: '2024-12-31',
      end_date: '2024-01-01',
      status: 'active',
      weekdays: 127
    });
    expect(response.status).toBe(422);
  });
});
