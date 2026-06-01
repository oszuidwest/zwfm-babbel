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
      ['when max_age missing, then returns 422', { key: automationKey }],
      ['when max_age invalid, then returns 422', { key: automationKey, max_age: 'invalid' }],
      ['when max_age negative, then returns 422', { key: automationKey, max_age: '-100' }]
    ])('%s', async (_name, params) => {
      const response = await global.helpers.publicBulletinRequest(1, params);
      expect(response.status).toBe(422);
    });

    test('when station ID invalid, then returns 422', async () => {
      // Arrange
      const url = `${global.api.apiBase}/public/stations/invalid/bulletin.wav?key=${automationKey}&max_age=3600`;

      // Act
      const response = await global.api.http({
        method: 'get',
        url: url,
        validateStatus: () => true
      });

      // Assert
      expect(response.status).toBe(422);
    });
  });

  describe('Station Validation', () => {
    test('when station non-existent, then returns 404', async () => {
      // Act
      const response = await global.helpers.publicBulletinRequest(999999, {
        key: automationKey,
        max_age: '3600'
      });

      // Assert
      expect(response.status).toBe(404);
    });

    test('when station has no stories, then returns 422', async () => {
      // Arrange
      const station = await global.helpers.createStation(global.resources, 'Empty Automation Station');
      expect(station).not.toBeNull();

      // Act
      const response = await global.helpers.publicBulletinRequest(station.id, {
        key: automationKey,
        max_age: '0'
      });

      // Assert
      expect(response.status).toBe(422);
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
      // Arrange: Uses station setup from beforeAll

      // Act
      const response = await global.helpers.publicBulletinRequest(stationId, {
        key: automationKey,
        max_age: '0'
      });

      // Assert
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

    test('when first request, then generates new bulletin', async () => {
      // Arrange: Uses station setup from beforeAll

      // Act
      const response = await global.helpers.publicBulletinRequest(stationId, {
        key: automationKey,
        max_age: '0'
      });

      // Assert
      expect(response.status).toBe(200);
      expect(response.headers['x-bulletin-cached']).toBe('false');
      expect(response.headers['x-bulletin-id']).toBeDefined();
    });

    test('when subsequent request, then returns cached', async () => {
      // Arrange: First request generates new bulletin
      const response1 = await global.helpers.publicBulletinRequest(stationId, {
        key: automationKey,
        max_age: '0'
      });
      expect(response1.status).toBe(200);
      expect(response1.headers['x-bulletin-id']).toBeDefined();

      // Act: Second request with high max_age should use cache
      const response2 = await global.helpers.publicBulletinRequest(stationId, {
        key: automationKey,
        max_age: '3600'
      });

      // Assert
      expect(response2.status).toBe(200);
      expect(response2.headers['x-bulletin-cached']).toBe('true');
      expect(response2.headers['x-bulletin-id']).toBeDefined();
    });
  });

  describe('Timezone Regression Test', () => {
    let stationId, voiceId;

    beforeAll(async () => {
      // Arrange: Create station and voice
      const station = await global.helpers.createStation(global.resources, 'Timezone Test Station');
      const voice = await global.helpers.createVoice(global.resources, 'Timezone Test Voice');
      stationId = station.id;
      voiceId = voice.id;

      const sv = await global.helpers.createStationVoiceWithJingle(global.resources, stationId, voiceId);
      expect(sv).not.toBeNull();
    });

    test('when single-day story, then scheduling works correctly', async () => {
      if (!global.helpers.isFFmpegAvailable()) return;

      // Use today only
      const today = new Date();
      const year = today.getFullYear();
      const month = String(today.getMonth() + 1).padStart(2, '0');
      const day = String(today.getDate()).padStart(2, '0');
      const todayStr = `${year}-${month}-${day}`;

      await global.helpers.createStationStoriesWithReadyAudio(global.resources, stationId, voiceId, [{
        title: `Timezone_Test_Story_${Date.now()}`,
        text: 'Story for testing single-day DATE comparison fix.',
        start_date: todayStr,
        end_date: todayStr
      }]);

      // Act
      const response = await global.helpers.publicBulletinRequest(stationId, {
        key: automationKey,
        max_age: '0'
      });

      // Assert: Story should not be incorrectly marked as expired
      expect(response.status).toBe(200);
    });
  });
});
