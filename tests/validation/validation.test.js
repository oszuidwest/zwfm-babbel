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
    // Create dependencies for date validation tests
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
      status: 'active',
      weekdays: 127,
      ...overrides
    });
    expect(response.status).toBe(422);
  });
});

describe('Empty Update Validation', () => {
  const paths = {};

  beforeAll(async () => {
    const station = await global.helpers.createStation(global.resources, 'EmptyUpdateStation');
    const voice = await global.helpers.createVoice(global.resources, 'EmptyUpdateVoice');
    const story = await global.helpers.createStory(global.resources, {
      title: 'Empty update', text: 'Test content', voice_id: voice.id
    });
    const stationVoice = await global.helpers.createStationVoice(global.resources, station.id, voice.id);
    paths.voice = `/voices/${voice.id}`;
    paths.story = `/stories/${story.id}`;
    paths.stationVoice = `/station-voices/${stationVoice.id}`;
    paths.ttsSettings = '/settings/tts';
    const users = await global.api.apiCall('GET', '/users?filter[username]=admin');
    paths.user = `/users/${users.data.data[0].id}`;
  });

  test.each([
    ['PUT', 'voice'],
    ['PUT', 'story'],
    ['PUT', 'stationVoice'],
    ['PUT', 'user'],
    ['PATCH', 'ttsSettings']
  ])('when %s %s with an empty object, then 422 names request', async (method, resource) => {
    const response = await global.api.apiCall(method, paths[resource], {});

    expect(response.status).toBe(422);
    expect(response.data.errors).toEqual([
      { field: 'request', code: 'empty_update', message: 'At least one field must be provided' }
    ]);
  });
});

describe('Validation Error Contract', () => {
  let storyPath, voicePath;

  beforeAll(async () => {
    const voice = await global.helpers.createVoice(global.resources, 'ContractVoice');
    const story = await global.helpers.createStory(global.resources, {
      title: 'Contract story', text: 'Test content', voice_id: voice.id
    });
    storyPath = `/stories/${story.id}`;
    voicePath = `/voices/${voice.id}`;
  });

  const expectFieldError = (response, status, field, code) => {
    expect(response.status).toBe(status);
    expect(response.data.errors).toEqual([expect.objectContaining({ field, code })]);
  };

  test('when PATCH story combines status and deleted_at, then 422 names request', async () => {
    const response = await global.api.apiCall('PATCH', storyPath, { status: 'draft', deleted_at: '' });
    expectFieldError(response, 422, 'request', 'unsupported');
  });

  test('when PATCH story sends an invalid status, then 422 names status', async () => {
    const response = await global.api.apiCall('PATCH', storyPath, { status: 'bogus' });
    expectFieldError(response, 422, 'status', 'invalid_choice');
  });

  test('when creating a story with a missing voice, then 422 names voice_id', async () => {
    const response = await global.api.apiCall('POST', '/stories', {
      title: 'Missing voice', text: 'Test content', voice_id: 999999,
      start_date: '2026-01-01', end_date: '2026-12-31'
    });
    expectFieldError(response, 422, 'voice_id', 'not_found');
  });

  test('when updating a voice with an empty ElevenLabs id, then 422 names the field', async () => {
    const response = await global.api.apiCall('PUT', voicePath, { elevenlabs_voice_id: '' });
    expectFieldError(response, 422, 'elevenlabs_voice_id', 'invalid_format');
  });

  test('when creating a user with a password over 72 bytes, then 422 names password', async () => {
    const response = await global.api.apiCall('POST', '/users', {
      username: `longpw${Date.now()}`,
      full_name: 'Long Password',
      password: `Valid1!${'é'.repeat(33)}`,
      role: 'viewer'
    });
    expectFieldError(response, 422, 'password', 'too_long');
  });

  test('when generating TTS with a non-boolean force, then 422 names force', async () => {
    const response = await global.api.apiCall('POST', `${storyPath}/tts?force=yes`);
    if (response.status === 501) {
      return; // TTS is not configured in this environment
    }
    expectFieldError(response, 422, 'force', 'invalid_format');
  });

  test('when a request uses an invalid path id, then 422 names id', async () => {
    const response = await global.api.apiCall('GET', '/stories/abc');
    expectFieldError(response, 422, 'id', 'invalid_format');
  });
});
