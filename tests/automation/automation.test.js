/**
 * Babbel automation endpoint tests.
 * Tests the public automation endpoint for radio automation systems.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

describe('Automation', () => {
  const automationKey = 'test-automation-key-for-integration-tests';
  const publicBase = process.env.API_BASE || 'http://localhost:8080';

  // Helper to make public bulletin request
  const publicBulletinRequest = async (stationId, queryParams = {}) => {
    const params = new URLSearchParams(queryParams);
    const url = `${publicBase}/public/stations/${stationId}/bulletin.wav?${params.toString()}`;

    const response = await global.api.http({
      method: 'get',
      url: url,
      responseType: 'arraybuffer',
      validateStatus: () => true
    });

    return {
      status: response.status,
      data: response.data,
      headers: response.headers,
      contentType: response.headers['content-type']
    };
  };

  // Helper to create station
  const createStation = async (name) => {
    const result = await global.helpers.createStation(global.resources, name);
    return result ? result.id : null;
  };

  // Helper to create voice
  const createVoice = async (name) => {
    const result = await global.helpers.createVoice(global.resources, name);
    return result ? result.id : null;
  };

  // Helper to create station-voice with jingle
  const createStationVoiceWithJingle = async (stationId, voiceId) => {
    const result = await global.helpers.createStationVoiceWithJingle(global.resources, stationId, voiceId);
    return result ? result.id : null;
  };

  // Helper to create story with audio
  const createStoryWithAudio = async (title, text, voiceId, targetStations) => {
    const result = await global.helpers.createStoryWithAudio(global.resources, {
      title: `${title}_${Date.now()}`,
      text,
      voice_id: voiceId,
      weekdays: 127,
      status: 'active'
    }, targetStations);
    return result ? result.id : null;
  };

  describe('API Key Validation', () => {
    test('when API key missing, then returns 401', async () => {
      // Act
      const response = await publicBulletinRequest(1, { max_age: '3600' });

      // Assert
      expect(response.status).toBe(401);
    });

    test('when API key invalid, then returns 401', async () => {
      // Act
      const response = await publicBulletinRequest(1, {
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
      const response = await publicBulletinRequest(1, {
        key: automationKey
      });

      // Assert
      expect(response.status).toBe(422);
    });

    test('when max_age invalid, then returns 422', async () => {
      // Act
      const response = await publicBulletinRequest(1, {
        key: automationKey,
        max_age: 'invalid'
      });

      // Assert
      expect(response.status).toBe(422);
    });

    test('when max_age negative, then returns 422', async () => {
      // Act
      const response = await publicBulletinRequest(1, {
        key: automationKey,
        max_age: '-100'
      });

      // Assert
      expect(response.status).toBe(422);
    });

    test('when station ID invalid, then returns 422', async () => {
      // Arrange
      const url = `${publicBase}/public/stations/invalid/bulletin.wav?key=${automationKey}&max_age=3600`;

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
      const response = await publicBulletinRequest(999999, {
        key: automationKey,
        max_age: '3600'
      });

      // Assert
      expect(response.status).toBe(404);
    });

    test('when station has no stories, then returns 422', async () => {
      // Arrange
      const stationId = await createStation('Empty Automation Station');
      expect(stationId).not.toBeNull();

      // Act
      const response = await publicBulletinRequest(stationId, {
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
      stationId = await createStation('Automation Test Station');
      voiceId = await createVoice('Automation Test Voice');

      const svId = await createStationVoiceWithJingle(stationId, voiceId);
      expect(svId).not.toBeNull();

      const storyId = await createStoryWithAudio(
        'Automation Test Story',
        'This is a test story for automation endpoint testing.',
        voiceId,
        [stationId]
      );
      expect(storyId).not.toBeNull();

      // Wait for processing
      await new Promise(resolve => setTimeout(resolve, 2000));
    });

    test('when requesting bulletin, then returns audio', async () => {
      // Arrange: Uses station setup from beforeAll

      // Act
      const response = await publicBulletinRequest(stationId, {
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
      stationId = await createStation('Caching Test Station');
      const voiceId = await createVoice('Caching Test Voice');

      const svId = await createStationVoiceWithJingle(stationId, voiceId);
      expect(svId).not.toBeNull();

      const storyId = await createStoryWithAudio(
        'Caching Test Story',
        'Story for testing caching behavior.',
        voiceId,
        [stationId]
      );
      expect(storyId).not.toBeNull();

      await new Promise(resolve => setTimeout(resolve, 2000));
    });

    test('when first request, then generates new bulletin', async () => {
      // Arrange: Uses station setup from beforeAll

      // Act
      const response = await publicBulletinRequest(stationId, {
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
      const response1 = await publicBulletinRequest(stationId, {
        key: automationKey,
        max_age: '0'
      });
      expect(response1.status).toBe(200);
      expect(response1.headers['x-bulletin-id']).toBeDefined();

      // Act: Second request with high max_age should use cache
      const response2 = await publicBulletinRequest(stationId, {
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
      stationId = await createStation('Timezone Test Station');
      voiceId = await createVoice('Timezone Test Voice');

      const svId = await createStationVoiceWithJingle(stationId, voiceId);
      expect(svId).not.toBeNull();
    });

    test('when single-day story, then scheduling works correctly', async () => {
      // Skip if ffmpeg not available
      if (!global.helpers.isFFmpegAvailable()) {
        console.log('Skipping timezone test - ffmpeg not available');
        return;
      }

      // Arrange: Create test audio
      const audioFile = `/tmp/test_story_timezone_${Date.now()}.wav`;
      const audioCreated = global.helpers.createTestAudioFile(audioFile, 3, 330);

      if (!audioCreated) {
        console.log('Skipping timezone test - could not create audio');
        return;
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
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: todayStr,
        end_date: todayStr,
        weekdays: 127,
        target_stations: [parseInt(stationId, 10)]
      });

      expect(storyResponse.status).toBe(201);
      const storyId = global.api.parseJsonField(storyResponse.data, 'id');
      global.resources.track('stories', storyId);

      // Upload audio
      const uploadResponse = await global.api.uploadFile(
        `/stories/${storyId}/audio`,
        {},
        audioFile,
        'audio'
      );
      expect(uploadResponse.status).toBe(201);

      // Cleanup
      global.helpers.cleanupTempFile(audioFile);

      await new Promise(resolve => setTimeout(resolve, 2000));

      // Act
      const response = await publicBulletinRequest(stationId, {
        key: automationKey,
        max_age: '0'
      });

      // Assert: Story should not be incorrectly marked as expired
      expect(response.status).toBe(200);
    });
  });
});
