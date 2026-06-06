describe('TTS Settings', () => {
  let originalSettings;

  beforeAll(async () => {
    const response = await global.api.apiCall('GET', '/settings/tts');
    expect(response.status).toBe(200);
    originalSettings = response.data;
  });

  afterEach(async () => {
    await global.api.apiLogin('admin', 'admin');
  });

  afterAll(async () => {
    if (!originalSettings) return;

    await global.api.apiLogin('admin', 'admin');
    const response = await global.api.apiCall('PATCH', '/settings/tts', restoreBody(originalSettings));
    expect(response.status).toBe(200);
  });

  test('when reading settings, then returns the singleton without secrets', async () => {
    const response = await global.api.apiCall('GET', '/settings/tts');

    expect(response.status).toBe(200);
    expect(response.data).toEqual(expect.objectContaining({
      model: expect.any(String),
      stability: expect.any(Number),
      similarity_boost: expect.any(Number),
      style: expect.any(Number),
      use_speaker_boost: expect.any(Boolean),
      speed: expect.any(Number),
      apply_text_normalization: expect.any(String),
      tts_style_prefix: expect.any(String),
      updated_at: expect.any(String),
      api_key_configured: expect.any(Boolean)
    }));
    expect(response.data).not.toHaveProperty('api_key');
  });

  test('when patching zero values, false, and empty prefix, then values are persisted', async () => {
    const response = await global.api.apiCall('PATCH', '/settings/tts', {
      stability: 0,
      style: 0,
      use_speaker_boost: false,
      tts_style_prefix: ''
    });

    expect(response.status).toBe(200);
    expect(response.data.stability).toBe(0);
    expect(response.data.style).toBe(0);
    expect(response.data.use_speaker_boost).toBe(false);
    expect(response.data.tts_style_prefix).toBe('');
  });

  test('when patching seed to null, then seed is cleared', async () => {
    const setResponse = await global.api.apiCall('PATCH', '/settings/tts', { seed: 123 });
    expect(setResponse.status).toBe(200);
    expect(setResponse.data.seed).toBe(123);

    const clearResponse = await global.api.apiCall('PATCH', '/settings/tts', { seed: null });
    expect(clearResponse.status).toBe(200);
    expect(clearResponse.data.seed).toBeNull();
  });

  test('when patching empty object, then returns request validation error', async () => {
    const response = await global.api.apiCall('PATCH', '/settings/tts', {});

    expect(response.status).toBe(422);
    expect(response.data.errors).toEqual([
      { field: 'request', message: 'At least one field must be provided' }
    ]);
  });

  test('when patching zero-byte body, then returns invalid format validation error', async () => {
    const response = await global.api.apiCall('PATCH', '/settings/tts', undefined, {
      data: '',
      headers: { 'Content-Type': 'application/json' }
    });

    expect(response.status).toBe(422);
    expect(response.data.errors).toEqual([
      { field: 'request', message: 'Invalid request format' }
    ]);
  });

  test('when patching the same value, then idempotent update succeeds', async () => {
    const current = await global.api.apiCall('GET', '/settings/tts');
    expect(current.status).toBe(200);

    const response = await global.api.apiCall('PATCH', '/settings/tts', {
      stability: current.data.stability
    });

    expect(response.status).toBe(200);
    expect(response.data.stability).toBe(current.data.stability);
  });

  test('when patching invalid ranges, then returns field validation errors only', async () => {
    const response = await global.api.apiCall('PATCH', '/settings/tts', {
      stability: 1.5,
      speed: 0.69
    });

    expect(response.status).toBe(422);
    expect(response.data.type).toBe('https://babbel.api/problems/validation-error');
    expect(response.data.errors).toEqual(expect.arrayContaining([
      { field: 'stability', message: 'must be between 0 and 1' },
      { field: 'speed', message: 'must be between 0.7 and 1.2' }
    ]));
    expect(response.data.errors[0]).not.toHaveProperty('code');
  });

  test('when patching prefix over 500 runes, then returns validation error', async () => {
    const response = await global.api.apiCall('PATCH', '/settings/tts', {
      tts_style_prefix: 'é'.repeat(501)
    });

    expect(response.status).toBe(422);
    expect(response.data.errors).toEqual(expect.arrayContaining([
      { field: 'tts_style_prefix', message: 'must be at most 500 characters' }
    ]));
  });

  test('when checking settings permissions, then read is shared and write is admin-only', async () => {
    const editor = await createUser('editor');
    const viewer = await createUser('viewer');

    await expectRoleAccess('admin', 'admin', {
      canRead: true,
      canWrite: true
    });
    await expectRoleAccess(editor.username, editor.password, {
      canRead: true,
      canWrite: false
    });
    await expectRoleAccess(viewer.username, viewer.password, {
      canRead: true,
      canWrite: false
    });

    await global.api.apiLogout();
    const unauthenticated = await global.api.apiCall('GET', '/settings/tts');
    expect(unauthenticated.status).toBe(401);
  });

  async function createUser(role) {
    await global.api.apiLogin('admin', 'admin');
    const user = {
      username: `ttssettings${role}${Date.now()}${Math.random().toString(36).slice(2, 8)}`,
      full_name: `TTS Settings ${role}`,
      password: 'SettingsPass123!',
      role
    };

    const response = await global.api.apiCall('POST', '/users', user);
    expect(response.status).toBe(201);
    global.resources.track('users', response.data.id);
    return user;
  }

  async function expectRoleAccess(username, password, expected) {
    const login = await global.api.apiLogin(username, password);
    expect(login.status).toBe(201);

    const read = await global.api.apiCall('GET', '/settings/tts');
    expect(read.status).toBe(expected.canRead ? 200 : 403);

    const write = await global.api.apiCall('PATCH', '/settings/tts', {
      stability: originalSettings.stability
    });
    expect(write.status).toBe(expected.canWrite ? 200 : 403);
  }

  function restoreBody(settings) {
    return {
      model: settings.model,
      stability: settings.stability,
      similarity_boost: settings.similarity_boost,
      style: settings.style,
      use_speaker_boost: settings.use_speaker_boost,
      speed: settings.speed,
      apply_text_normalization: settings.apply_text_normalization,
      seed: settings.seed,
      tts_style_prefix: settings.tts_style_prefix
    };
  }
});
