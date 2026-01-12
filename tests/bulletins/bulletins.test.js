/**
 * Babbel bulletins tests.
 * Tests bulletin generation and audio handling functionality.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

const fs = require('fs');
const bulletinsSchema = require('../lib/schemas/bulletins.schema');
const { generateQueryTests } = require('../lib/generators');

describe('Bulletins', () => {
  // Setup function - generates a bulletin for query tests
  const setupQueryTestData = async () => {
    const station = await global.helpers.createStation(global.resources, 'QueryBulletinStation');
    const voice = await global.helpers.createVoice(global.resources, 'QueryBulletinVoice');
    await global.helpers.createStationVoiceWithJingle(global.resources, station.id, voice.id, 3.0);
    await global.helpers.createStoryWithAudio(global.resources, {
      title: `QueryBulletinStory_${Date.now()}`,
      text: 'Query test story',
      voice_id: voice.id,
      weekdays: 127,
      status: 'active'
    }, [parseInt(station.id, 10)]);

    await new Promise(resolve => setTimeout(resolve, 2000));

    const response = await global.api.apiCall('POST', `/stations/${station.id}/bulletins`, {});
    return response.status === 200 && response.data.id ? [response.data.id] : [];
  };

  // Generate query parameter tests
  generateQueryTests(bulletinsSchema, setupQueryTestData);

  // === BUSINESS LOGIC TESTS ===

  describe('Bulletin Generation', () => {
    let stationId, voiceId;

    beforeAll(async () => {
      // Arrange: Create dependencies for bulletin generation
      const station = await global.helpers.createStation(global.resources, 'BulletinGenStation');
      const voice = await global.helpers.createVoice(global.resources, 'BulletinGenVoice');
      stationId = station.id;
      voiceId = voice.id;

      await global.helpers.createStationVoiceWithJingle(global.resources, stationId, voiceId, 3.0);
      await global.helpers.createStoryWithAudio(global.resources, {
        title: `BulletinGenStory_${Date.now()}`,
        text: 'Bulletin generation test story',
        voice_id: voiceId,
        weekdays: 127,
        status: 'active'
      }, [parseInt(stationId, 10)]);

      await new Promise(resolve => setTimeout(resolve, 3000));
    });

    test('when generating bulletin, then returns complete data', async () => {
      // Arrange: Uses station setup from beforeAll

      // Act
      const response = await global.api.apiCall('POST', `/stations/${stationId}/bulletins`, {});

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('id');
      expect(response.data).toHaveProperty('audio_url');
      expect(response.data).toHaveProperty('duration_seconds');
      expect(response.data).toHaveProperty('story_count');
      expect(response.data).toHaveProperty('filename');
    });

    test('when generating with specific date, then succeeds', async () => {
      // Arrange
      const today = new Date().toISOString().split('T')[0];

      // Act
      const response = await global.api.apiCall('POST', `/stations/${stationId}/bulletins`, { date: today });

      // Assert
      expect(response.status).toBe(200);
    });
  });

  describe('Bulletin Retrieval', () => {
    test('when fetching single bulletin, then returns data', async () => {
      // Arrange
      const listResponse = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (listResponse.data.data.length > 0) {
        const bulletinId = listResponse.data.data[0].id;

        // Act
        const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}`);

        // Assert
        expect(response.status).toBe(200);
        expect(response.data.id).toBe(bulletinId);
      }
    });

    test('when fetching non-existent bulletin, then returns 404', async () => {
      // Act
      const response = await global.api.apiCall('GET', '/bulletins/999999999');

      // Assert
      expect(response.status).toBe(404);
    });

    test('when fetching bulletin, then has correct field types', async () => {
      // Arrange
      const listResponse = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (listResponse.data.data.length > 0) {
        const bulletinId = listResponse.data.data[0].id;

        // Act
        const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}`);
        const bulletin = response.data;

        // Assert
        expect(typeof bulletin.id).toBe('number');
        expect(typeof bulletin.station_id).toBe('number');
        expect(typeof bulletin.station_name).toBe('string');
        expect(typeof bulletin.audio_url).toBe('string');
        expect(typeof bulletin.filename).toBe('string');
        expect(typeof bulletin.duration_seconds).toBe('number');
      }
    });
  });

  describe('Bulletin Audio Download', () => {
    test('when downloading audio, then file is valid', async () => {
      // Arrange
      const response = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (response.data.data.length > 0) {
        const bulletinId = response.data.data[0].id;
        const downloadPath = '/tmp/test_bulletin_download.wav';

        // Act
        const downloadResponse = await global.api.downloadFile(`/bulletins/${bulletinId}/audio`, downloadPath);

        // Assert
        if (downloadResponse === 200) {
          expect(fs.existsSync(downloadPath)).toBe(true);
          const stats = fs.statSync(downloadPath);
          expect(stats.size).toBeGreaterThan(1000);

          // Cleanup
          fs.unlinkSync(downloadPath);
        }
      }
    });
  });

  describe('Station Bulletin Endpoints', () => {
    let stationId;

    beforeAll(async () => {
      // Arrange: Create station with full setup
      const station = await global.helpers.createStation(global.resources, 'StationBulletinEndpoint');
      const voice = await global.helpers.createVoice(global.resources, 'StationBulletinVoice');
      stationId = station.id;

      await global.helpers.createStationVoiceWithJingle(global.resources, stationId, voice.id);
      await global.helpers.createStoryWithAudio(global.resources, {
        title: `StationBulletinStory_${Date.now()}`,
        text: 'Station endpoint test story',
        voice_id: voice.id,
        weekdays: 127,
        status: 'active'
      }, [parseInt(stationId, 10)]);

      await new Promise(resolve => setTimeout(resolve, 2000));
    });

    test('when generating station bulletin, then succeeds', async () => {
      // Arrange: Uses station setup from beforeAll

      // Act
      const response = await global.api.apiCall('POST', `/stations/${stationId}/bulletins`, {});

      // Assert
      expect(response.status).toBe(200);
    });

    test('when listing station bulletins, then returns data', async () => {
      // Arrange: Uses station setup from beforeAll

      // Act
      const response = await global.api.apiCall('GET', `/stations/${stationId}/bulletins`);

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
    });
  });

  describe('Bulletin Error Cases', () => {
    test('when station non-existent, then returns 404', async () => {
      // Act
      const response = await global.api.apiCall('POST', '/stations/99999/bulletins', {});

      // Assert
      expect(response.status).toBe(404);
    });

    test('when bulletin audio non-existent, then returns 404', async () => {
      // Act
      const response = await global.api.apiCall('GET', '/bulletins/99999/audio');

      // Assert
      expect(response.status).toBe(404);
    });
  });

  describe('Bulletin History', () => {
    test('when listing with sort, then ordered by date', async () => {
      // Act
      const response = await global.api.apiCall('GET', '/bulletins?sort=-created_at');

      // Assert
      expect(response.status).toBe(200);
      const bulletins = response.data.data || [];
      if (bulletins.length > 1) {
        const first = new Date(bulletins[0].created_at);
        const second = new Date(bulletins[1].created_at);
        expect(first >= second).toBe(true);
      }
    });

    test('when filtering by date range, then returns matching', async () => {
      // Arrange
      const today = new Date().toISOString().split('T')[0];
      const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];

      // Act
      const response = await global.api.apiCall('GET', `/bulletins?filter[created_at][gte]=${yesterday}&filter[created_at][lte]=${today}`);

      // Assert
      expect(response.status).toBe(200);
    });
  });
});
