/**
 * Babbel automation endpoint tests.
 * Tests the public automation endpoint for radio automation systems.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

const TestHelpers = require('../lib/TestHelpers');

describe('Automation', () => {
  const automationKey = TestHelpers.AUTOMATION_KEY;

  describe('API Key Validation', () => {
    test('when API key missing, then returns 401', async () => {
      // Act
      const response = await global.helpers.publicBulletinRequest(1, { max_age: '3600' });

      // Assert
      expect(response.status).toBe(401);
    });

    test('when API key invalid, then returns 401', async () => {
      // Act
      const response = await global.helpers.publicBulletinRequest(1, {
        key: 'wrong-key',
        max_age: '3600'
      });

      // Assert
      expect(response.status).toBe(401);
    });
  });

  describe('Parameter Validation', () => {
    test('when max_age missing, then returns 422', async () => {
      // Act
      const response = await global.helpers.publicBulletinRequest(1, {
        key: automationKey
      });

      // Assert
      expect(response.status).toBe(422);
    });

    test('when max_age invalid, then returns 422', async () => {
      // Act
      const response = await global.helpers.publicBulletinRequest(1, {
        key: automationKey,
        max_age: 'invalid'
      });

      // Assert
      expect(response.status).toBe(422);
    });

    test('when max_age negative, then returns 422', async () => {
      // Act
      const response = await global.helpers.publicBulletinRequest(1, {
        key: automationKey,
        max_age: '-100'
      });

      // Assert
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
    let stationId, voiceId;

    beforeAll(async () => {
      // Arrange: Create full station setup
      const station = await global.helpers.createStation(global.resources, 'Automation Test Station');
      const voice = await global.helpers.createVoice(global.resources, 'Automation Test Voice');
      stationId = station.id;
      voiceId = voice.id;

      const sv = await global.helpers.createStationVoiceWithJingle(global.resources, stationId, voiceId);
      expect(sv).not.toBeNull();

      const story = await global.helpers.createStoryWithAudio(global.resources, {
        title: `Automation Test Story_${Date.now()}`,
        text: 'This is a test story for automation endpoint testing.',
        voice_id: voiceId,
        weekdays: 127,
        status: 'active'
      }, [stationId]);
      expect(story).not.toBeNull();

      await global.helpers.waitForStoryAudio(story.id);
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
      // Arrange: Create station with story
      const station = await global.helpers.createStation(global.resources, 'Caching Test Station');
      const voice = await global.helpers.createVoice(global.resources, 'Caching Test Voice');
      stationId = station.id;

      const sv = await global.helpers.createStationVoiceWithJingle(global.resources, station.id, voice.id);
      expect(sv).not.toBeNull();

      const story = await global.helpers.createStoryWithAudio(global.resources, {
        title: `Caching Test Story_${Date.now()}`,
        text: 'Story for testing caching behavior.',
        voice_id: voice.id,
        weekdays: 127,
        status: 'active'
      }, [stationId]);
      expect(story).not.toBeNull();

      await global.helpers.waitForStoryAudio(story.id);
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
      if (!global.helpers.isFFmpegAvailable()) {
        throw new Error('Test requires ffmpeg to create audio files');
      }

      // Arrange: Create test audio
      const audioFile = `/tmp/test_story_timezone_${Date.now()}.wav`;
      const audioCreated = global.helpers.createTestAudioFile(audioFile, 3, 330);

      if (!audioCreated) {
        throw new Error('Failed to create test audio file');
      }

      // Use today only
      const today = new Date();
      const year = today.getFullYear();
      const month = String(today.getMonth() + 1).padStart(2, '0');
      const day = String(today.getDate()).padStart(2, '0');
      const todayStr = `${year}-${month}-${day}`;

      // Create story valid only today
      const storyResponse = await global.api.apiCall('POST', '/stories', {
        title: `Timezone_Test_Story_${Date.now()}`,
        text: 'Story for testing single-day DATE comparison fix.',
        voice_id: voiceId,
        status: 'active',
        start_date: todayStr,
        end_date: todayStr,
        weekdays: 127,
        target_stations: [stationId]
      });

      expect(storyResponse.status).toBe(201);
      global.resources.track('stories', storyResponse.data.id);

      // Upload audio
      const uploadResponse = await global.api.uploadFile(
        `/stories/${storyResponse.data.id}/audio`,
        {},
        audioFile,
        'audio'
      );
      expect(uploadResponse.status).toBe(201);

      // Cleanup
      global.helpers.cleanupTempFile(audioFile);

      await global.helpers.waitForStoryAudio(storyResponse.data.id);

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
