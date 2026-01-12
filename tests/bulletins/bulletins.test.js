/**
 * Babbel bulletins tests.
 * Tests bulletin generation and audio handling functionality.
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

    test('generates bulletin successfully', async () => {
      const response = await global.api.apiCall('POST', `/stations/${stationId}/bulletins`, {});

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('id');
      expect(response.data).toHaveProperty('audio_url');
      expect(response.data).toHaveProperty('duration_seconds');
      expect(response.data).toHaveProperty('story_count');
      expect(response.data).toHaveProperty('filename');
    });

    test('generates bulletin with specific date', async () => {
      const today = new Date().toISOString().split('T')[0];
      const response = await global.api.apiCall('POST', `/stations/${stationId}/bulletins`, { date: today });

      expect(response.status).toBe(200);
    });
  });

  describe('Bulletin Retrieval', () => {
    test('retrieves single bulletin', async () => {
      const listResponse = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (listResponse.data.data.length > 0) {
        const bulletinId = listResponse.data.data[0].id;
        const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}`);

        expect(response.status).toBe(200);
        expect(response.data.id).toBe(bulletinId);
      }
    });

    test('returns 404 for non-existent bulletin', async () => {
      const response = await global.api.apiCall('GET', '/bulletins/999999999');
      expect(response.status).toBe(404);
    });

    test('bulletin has correct field types', async () => {
      const listResponse = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (listResponse.data.data.length > 0) {
        const bulletinId = listResponse.data.data[0].id;
        const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}`);
        const bulletin = response.data;

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
    test('downloads audio file', async () => {
      const response = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (response.data.data.length > 0) {
        const bulletinId = response.data.data[0].id;
        const downloadPath = '/tmp/test_bulletin_download.wav';

        const downloadResponse = await global.api.downloadFile(`/bulletins/${bulletinId}/audio`, downloadPath);

        if (downloadResponse === 200) {
          expect(fs.existsSync(downloadPath)).toBe(true);
          const stats = fs.statSync(downloadPath);
          expect(stats.size).toBeGreaterThan(1000);
          fs.unlinkSync(downloadPath);
        }
      }
    });
  });

  describe('Station Bulletin Endpoints', () => {
    let stationId;

    beforeAll(async () => {
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

    test('generates station-specific bulletin', async () => {
      const response = await global.api.apiCall('POST', `/stations/${stationId}/bulletins`, {});
      expect(response.status).toBe(200);
    });

    test('lists station bulletins', async () => {
      const response = await global.api.apiCall('GET', `/stations/${stationId}/bulletins`);
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
    });
  });

  describe('Bulletin Error Cases', () => {
    test('non-existent station returns 404', async () => {
      const response = await global.api.apiCall('POST', '/stations/99999/bulletins', {});
      expect(response.status).toBe(404);
    });

    test('non-existent bulletin audio returns 404', async () => {
      const response = await global.api.apiCall('GET', '/bulletins/99999/audio');
      expect(response.status).toBe(404);
    });
  });

  describe('Bulletin History', () => {
    test('lists history sorted by date', async () => {
      const response = await global.api.apiCall('GET', '/bulletins?sort=-created_at');

      expect(response.status).toBe(200);
      const bulletins = response.data.data || [];
      if (bulletins.length > 1) {
        const first = new Date(bulletins[0].created_at);
        const second = new Date(bulletins[1].created_at);
        expect(first >= second).toBe(true);
      }
    });

    test('date range filtering', async () => {
      const today = new Date().toISOString().split('T')[0];
      const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];

      const response = await global.api.apiCall('GET', `/bulletins?filter[created_at][gte]=${yesterday}&filter[created_at][lte]=${today}`);
      expect(response.status).toBe(200);
    });
  });
});
