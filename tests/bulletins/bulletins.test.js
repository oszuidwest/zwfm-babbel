/**
 * Babbel bulletins tests.
 * Tests bulletin generation and audio handling functionality.
 */

const fs = require('fs');

describe('Bulletins', () => {
  // Helpers
  const createStation = async (name) => {
    const result = await global.helpers.createStation(global.resources, name);
    return result ? result.id : null;
  };

  const createVoice = async (name) => {
    const result = await global.helpers.createVoice(global.resources, name);
    return result ? result.id : null;
  };

  const createStationVoiceWithJingle = async (stationId, voiceId, mixPoint = 3.0) => {
    const result = await global.helpers.createStationVoiceWithJingle(global.resources, stationId, voiceId, mixPoint);
    return result ? result.id : null;
  };

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

  describe('Bulletin Generation', () => {
    let stationId, voice1Id, voice2Id;

    beforeAll(async () => {
      stationId = await createStation('Bulletin Test Station');
      voice1Id = await createVoice('Bulletin Voice 1');
      voice2Id = await createVoice('Bulletin Voice 2');

      await createStationVoiceWithJingle(stationId, voice1Id, 3.0);
      await createStationVoiceWithJingle(stationId, voice2Id, 2.5);

      await createStoryWithAudio('Breaking News', 'Breaking news content', voice1Id, [stationId]);
      await createStoryWithAudio('Weather Update', 'Weather forecast', voice2Id, [stationId]);

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
    test('lists all bulletins', async () => {
      const response = await global.api.apiCall('GET', '/bulletins');

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
      expect(Array.isArray(response.data.data)).toBe(true);
    });

    test('pagination works', async () => {
      const response = await global.api.apiCall('GET', '/bulletins?limit=2&offset=0');

      expect(response.status).toBe(200);
      expect(response.data.data.length).toBeLessThanOrEqual(2);
    });
  });

  describe('Get Bulletin By ID', () => {
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
  });

  describe('Bulletin Field Types', () => {
    test('has correct field types', async () => {
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
        expect(typeof bulletin.file_size).toBe('number');
        expect(typeof bulletin.story_count).toBe('number');
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
      stationId = await createStation('Station Bulletin Test');
      const voiceId = await createVoice('Station Bulletin Voice');
      await createStationVoiceWithJingle(stationId, voiceId);
      await createStoryWithAudio('Station Story', 'Content', voiceId, [stationId]);
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

  describe('Modern Query Parameters', () => {
    test('search by filename', async () => {
      const response = await global.api.apiCall('GET', '/bulletins?search=bulletin');

      expect(response.status).toBe(200);
    });

    test('field selection', async () => {
      const response = await global.api.apiCall('GET', '/bulletins?fields=id,filename,station_name&limit=3');

      expect(response.status).toBe(200);
      if (response.data.data.length > 0) {
        const first = response.data.data[0];
        expect(first).toHaveProperty('id');
        expect(first).toHaveProperty('filename');
        expect(first).toHaveProperty('station_name');
      }
    });

    test('sort descending', async () => {
      const response = await global.api.apiCall('GET', '/bulletins?sort=-created_at&limit=5');

      expect(response.status).toBe(200);
    });

    test('filter by duration', async () => {
      const response = await global.api.apiCall('GET', '/bulletins?filter[duration_seconds][gte]=0');

      expect(response.status).toBe(200);
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

      const response = await global.api.apiCall('GET', `/bulletins?filter%5Bcreated_at%5D%5Bgte%5D=${yesterday}&filter%5Bcreated_at%5D%5Blte%5D=${today}`);

      expect(response.status).toBe(200);
    });
  });
});
