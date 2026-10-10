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
    const users = await global.api.apiCall('GET', '/users?filter[username]=admin');
    paths.user = `/users/${users.data.data[0].id}`;
  });

  test.each([
    ['PUT', 'voice'],
    ['PUT', 'story'],
    ['PUT', 'stationVoice'],
    ['PUT', 'user']
  ])('when %s %s with an empty object, then 422 names request', async (method, resource) => {
    const response = await global.api.apiCall(method, paths[resource], {});

    expect(response.status).toBe(422);
    expect(response.data.errors).toEqual([
      expect.objectContaining({ field: 'request', code: 'empty_update' })
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

});
