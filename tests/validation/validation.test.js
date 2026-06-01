describe('Security Validation', () => {
  const expectStationPayloadHandledSafely = async (payload) => {
    const response = await global.api.apiCall('POST', '/stations', {
      name: payload,
      max_stories_per_block: 5,
      pause_seconds: 2.0
    });

    expect([201, 409, 422]).toContain(response.status);
    if (response.status === 201 && response.data?.id) {
      global.resources.track('stations', response.data.id);
    }
  };

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
      await expectStationPayloadHandledSafely(payload);
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
      await expectStationPayloadHandledSafely(payload);
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
      await expectStationPayloadHandledSafely(payload);
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

  test.each([
    ['when start_date invalid format, then returns 422', { start_date: 'invalid-date' }],
    ['when end_date invalid format, then returns 422', { end_date: 'invalid-date' }],
    ['when end_date before start_date, then returns 422', { start_date: '2024-12-31', end_date: '2024-01-01' }]
  ])('%s', async (_name, overrides) => {
    const response = await global.api.apiCall('POST', '/stories', {
      title: `DateTest ${Date.now()}`,
      text: 'Test content',
      voice_id: voiceId,
      target_stations: [stationId],
      status: 'active',
      weekdays: 127,
      ...overrides
    });
    expect(response.status).toBe(422);
  });
});
