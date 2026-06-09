describe('TTS Settings', () => {
  let originalSettings;
  let originalPronunciations;

  beforeAll(async () => {
    const response = await global.api.apiCall('GET', '/settings/tts');
    expect(response.status).toBe(200);
    originalSettings = response.data;

    const pronunciations = await global.api.apiCall('GET', '/settings/tts/pronunciations');
    expect(pronunciations.status).toBe(200);
    originalPronunciations = pronunciations.data;
  });

  afterEach(async () => {
    await global.api.apiLogin('admin', 'admin');
  });

  afterAll(async () => {
    if (!originalSettings) return;

    await global.api.apiLogin('admin', 'admin');
    const response = await global.api.apiCall('PATCH', '/settings/tts', restoreBody(originalSettings));
    expect(response.status).toBe(200);

    if (originalPronunciations) {
      const pronunciationResponse = await global.api.apiCall(
        'PUT',
        '/settings/tts/pronunciations',
        { rules: originalPronunciations.rules || [] }
      );
      expect(pronunciationResponse.status).toBe(200);
    }
  });

  test('when reading settings, then returns the singleton without secrets', async () => {
    const response = await global.api.apiCall('GET', '/settings/tts');

    expect(response.status).toBe(200);
    expect(response.data).toEqual(expect.objectContaining({
      stability: expect.any(Number),
      similarity_boost: expect.any(Number),
      style: expect.any(Number),
      speed: expect.any(Number),
      apply_text_normalization: expect.any(String),
      tts_style_prefix: expect.any(String),
      updated_at: expect.any(String),
      api_key_configured: expect.any(Boolean)
    }));
    expect(response.data).not.toHaveProperty('api_key');
    expect(response.data).not.toHaveProperty('model');
    expect(response.data).not.toHaveProperty('use_speaker_boost');
  });

  test('when patching zero values and empty prefix, then values are persisted', async () => {
    const response = await global.api.apiCall('PATCH', '/settings/tts', {
      stability: 0,
      style: 0,
      tts_style_prefix: ''
    });

    expect(response.status).toBe(200);
    expect(response.data.stability).toBe(0);
    expect(response.data.style).toBe(0);
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

  test('when patching zero-byte body, then returns strict bad request error', async () => {
    const response = await global.api.apiCall('PATCH', '/settings/tts', undefined, {
      data: Buffer.alloc(0),
      headers: { 'Content-Type': 'application/json' },
      transformRequest: [(body) => body]
    });

    expect(response.status).toBe(400);
    expect(response.data.errors).toEqual([
      { field: 'request', message: 'request body is empty' }
    ]);
  });

  test('when patching removed or unknown fields, then returns strict bad request errors', async () => {
    const cases = [
      ['model', { model: 'eleven_multilingual_v2' }, 'field has been removed in v3-only release'],
      ['use_speaker_boost', { use_speaker_boost: true }, 'field has been removed in v3-only release'],
      ['stabilty', { stabilty: 0.5 }, 'unknown field']
    ];

    for (const [field, body, message] of cases) {
      const response = await global.api.apiCall('PATCH', '/settings/tts', body);
      expect(response.status).toBe(400);
      expect(response.data.errors).toEqual([{ field, message }]);
    }
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

  test('when replacing pronunciation rules with IPA, then GET returns the sorted local set', async () => {
    const rules = [
      { string_to_replace: 'Streekomroep', ipa: 'ˈstreːkɔmˌrupə', case_sensitive: false, word_boundaries: true },
      { string_to_replace: 'PSV', ipa: 'piː ɛs veː' },
      { string_to_replace: 'Albert Heijn', ipa: 'ˈɑlbərt ˈɦɛin', case_sensitive: true, word_boundaries: true },
      { string_to_replace: 'AZ', ipa: 'ˈɑlkmaːr ˈzɑːnstreːk', case_sensitive: true, word_boundaries: true },
      { string_to_replace: 'biochemie', ipa: 'ˌbaɪoʊˈkemɪstri', case_sensitive: false, word_boundaries: true }
    ];

    const putResponse = await global.api.apiCall('PUT', '/settings/tts/pronunciations', { rules });
    expect(putResponse.status).toBe(200);
    expect(putResponse.data.updated_at).toEqual(expect.any(String));

    const getResponse = await global.api.apiCall('GET', '/settings/tts/pronunciations');
    expect(getResponse.status).toBe(200);
    expect(getResponse.data.rules.map(rule => rule.string_to_replace)).toEqual([
      'AZ',
      'Albert Heijn',
      'PSV',
      'Streekomroep',
      'biochemie'
    ]);
    expect(getResponse.data.rules).toEqual(putResponse.data.rules);
    expect(getResponse.data.rules[0]).not.toHaveProperty('id');
    expect(getResponse.data.rules[0]).not.toHaveProperty('created_at');
  });

  test('when clearing pronunciation rules, then updated_at is null', async () => {
    const response = await global.api.apiCall('PUT', '/settings/tts/pronunciations', { rules: [] });

    expect(response.status).toBe(200);
    expect(response.data).toEqual({ rules: [], updated_at: null });
  });

  test('when pronunciation rules exceed max count, then returns validation error', async () => {
    const rules = Array.from({ length: 1001 }, (_, index) => ({
      string_to_replace: `term-${index}`,
      ipa: 'a'
    }));

    const response = await global.api.apiCall('PUT', '/settings/tts/pronunciations', { rules });

    expect(response.status).toBe(422);
    expect(response.data.errors).toEqual(expect.arrayContaining([
      { field: 'rules', message: 'must contain at most 1000 rules' }
    ]));
  });

  test.each([
    ['empty ipa', { string_to_replace: 'PSV', ipa: ' ' }, 'rules[0].ipa'],
    ['slash in ipa', { string_to_replace: 'PSV', ipa: 'piː/ɛs' }, 'rules[0].ipa'],
    ['control char in ipa', { string_to_replace: 'PSV', ipa: 'piː\nɛs' }, 'rules[0].ipa'],
    ['missing ipa', { string_to_replace: 'PSV' }, 'rules[0].ipa']
  ])('when PUT pronunciations has invalid IPA (%s), then returns 422', async (_name, rule, field) => {
    const response = await global.api.apiCall('PUT', '/settings/tts/pronunciations', { rules: [rule] });

    expect(response.status).toBe(422);
    expect(response.data.errors.some(error => error.field === field)).toBe(true);
  });

  test('when PUT pronunciations has duplicate term, then returns validation error before DB write', async () => {
    const response = await global.api.apiCall('PUT', '/settings/tts/pronunciations', {
      rules: [
        { string_to_replace: 'PSV', ipa: 'one' },
        { string_to_replace: 'PSV', ipa: 'two' }
      ]
    });

    expect(response.status).toBe(422);
    expect(response.data.errors).toEqual(expect.arrayContaining([
      { field: 'rules[1].string_to_replace', message: 'duplicates rules[0]' }
    ]));
  });

  test('when PUT pronunciations has case-insensitive shadowing, then returns validation error', async () => {
    const response = await global.api.apiCall('PUT', '/settings/tts/pronunciations', {
      rules: [
        { string_to_replace: 'PSV', ipa: 'one', case_sensitive: false },
        { string_to_replace: 'psv', ipa: 'two' }
      ]
    });

    expect(response.status).toBe(422);
    expect(response.data.errors).toEqual(expect.arrayContaining([
      {
        field: 'rules[0].string_to_replace',
        message: 'conflicts with rules[1] under case-insensitive matching'
      }
    ]));
  });

  test('when PUT pronunciations sends alias, then strict binding returns 400', async () => {
    const response = await global.api.apiCall('PUT', '/settings/tts/pronunciations', {
      rules: [{ string_to_replace: 'Albert Heijn', alias: 'albert hijn' }]
    });

    expect(response.status).toBe(400);
    expect(response.data.errors).toEqual([
      { field: 'alias', message: "field has been replaced by 'ipa'" }
    ]);
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
      stability: settings.stability,
      similarity_boost: settings.similarity_boost,
      style: settings.style,
      speed: settings.speed,
      apply_text_normalization: settings.apply_text_normalization,
      seed: settings.seed,
      tts_style_prefix: settings.tts_style_prefix
    };
  }
});
