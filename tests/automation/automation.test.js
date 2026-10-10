const TestHelpers = require('../lib/TestHelpers');

describe('Automation', () => {
  const automationKey = TestHelpers.AUTOMATION_KEY;

  describe('API Key Validation', () => {
    test.each([
      ['when API key missing, then returns 401', { max_age: '3600' }],
      ['when API key invalid, then returns 401', { key: 'wrong-key', max_age: '3600' }]
    ])('%s', async (_name, params) => {
      const response = await global.helpers.publicBulletinRequest(1, params);
      expect(response.status).toBe(401);
    });
  });

  describe('Parameter Validation', () => {
    test.each([
      ['when max_age missing, then returns 422', { key: automationKey }, 'required'],
      ['when max_age invalid, then returns 422', { key: automationKey, max_age: 'invalid' }, 'invalid_format'],
      ['when max_age negative, then returns 422', { key: automationKey, max_age: '-100' }, 'out_of_range'],
      ['when max_age overflows a duration, then returns 422', { key: automationKey, max_age: '9223372036854775807' }, 'out_of_range']
    ])('%s', async (_name, params, code) => {
      const response = await global.helpers.publicBulletinRequest(1, params);
      expect(response.status).toBe(422);
      expect(response.data.errors).toEqual([expect.objectContaining({ field: 'max_age', code })]);
    });

    test('when station ID invalid, then returns 422', async () => {
      const url = `${global.api.apiBase}/public/stations/invalid/bulletin.wav?key=${automationKey}&max_age=3600`;

      const response = await global.api.http({
        method: 'get',
        url: url,
        validateStatus: () => true
      });

      expect(response.status).toBe(422);
      expect(response.data.errors).toEqual([expect.objectContaining({ field: 'id', code: 'invalid_format' })]);
    });
  });

  describe('Station Validation', () => {
    test('when station non-existent, then returns 404', async () => {
      const response = await global.helpers.publicBulletinRequest(999999, {
        key: automationKey,
        max_age: '3600'
      });

      expect(response.status).toBe(404);
    });

    test('when station has no stories, then returns 409', async () => {
      const station = await global.helpers.createStation(global.resources, 'Empty Automation Station');
      expect(station).not.toBeNull();

      const response = await global.helpers.publicBulletinRequest(station.id, {
        key: automationKey,
        max_age: '0'
      });

      expect(response.status).toBe(409);
      expect(response.data.code).toBe('bulletin.no_stories');
    });
  });

  describe('Successful Bulletin Generation', () => {
    let stationId;

    beforeAll(async () => {
      const { station } = await global.helpers.createBroadcastFixture(global.resources, {
        stationName: 'Automation Test Station',
        voiceName: 'Automation Test Voice',
        storyTitle: 'Automation Test Story',
        storyText: 'This is a test story for automation endpoint testing.'
      });
      stationId = station.id;
    });

    test('when requesting bulletin, then returns audio', async () => {
      // Uses station setup from beforeAll

      const response = await global.helpers.publicBulletinRequest(stationId, {
        key: automationKey,
        max_age: '0'
      });

      expect(response.status).toBe(200);
      expect(response.contentType).toContain('audio/wav');
      expect(response.data.length).toBeGreaterThan(1000);
    });
  });

  describe('Bulletin Caching', () => {
    let stationId;

    beforeAll(async () => {
      const { station } = await global.helpers.createBroadcastFixture(global.resources, {
        stationName: 'Caching Test Station',
        voiceName: 'Caching Test Voice',
        storyTitle: 'Caching Test Story',
        storyText: 'Story for testing caching behavior.'
      });
      stationId = station.id;
    });

    test('when requesting twice within max age, then reuses the generated bulletin', async () => {
      const generated = await global.helpers.publicBulletinRequest(stationId, {
        key: automationKey,
        max_age: '0'
      });

      expect(generated.status).toBe(200);
      expect(generated.headers['x-bulletin-cached']).toBe('false');
      expect(generated.headers['x-bulletin-id']).toBeDefined();

      const cached = await global.helpers.publicBulletinRequest(stationId, {
        key: automationKey,
        max_age: '3600'
      });

      expect(cached.status).toBe(200);
      expect(cached.headers['x-bulletin-cached']).toBe('true');
      expect(cached.headers['x-bulletin-id']).toBe(generated.headers['x-bulletin-id']);
    });
  });

  describe('Timezone Regression Test', () => {
    let stationId, voiceId;

    beforeAll(async () => {
      // Create station and voice
      const station = await global.helpers.createStation(global.resources, 'Timezone Test Station');
      const voice = await global.helpers.createVoice(global.resources, 'Timezone Test Voice');
      stationId = station.id;
      voiceId = voice.id;

      const sv = await global.helpers.createStationVoiceWithJingle(global.resources, stationId, voiceId);
      expect(sv).not.toBeNull();
    });

    test('when single-day story, then scheduling works correctly', async () => {
      // Use today only
      const today = new Date();
      const year = today.getFullYear();
      const month = String(today.getMonth() + 1).padStart(2, '0');
      const day = String(today.getDate()).padStart(2, '0');
      const todayStr = `${year}-${month}-${day}`;

      await global.helpers.requireStoriesWithReadyAudio(global.resources, voiceId, [{
        title: `Timezone_Test_Story_${Date.now()}`,
        text: 'Story for testing single-day DATE comparison fix.',
        start_date: todayStr,
        end_date: todayStr
      }]);

      const response = await global.helpers.publicBulletinRequest(stationId, {
        key: automationKey,
        max_age: '0'
      });

      // Story should not be incorrectly marked as expired
      expect(response.status).toBe(200);
    });
  });
});
