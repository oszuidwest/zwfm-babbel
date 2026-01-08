/**
 * Babbel station-voices tests.
 * Tests station-voice relationship management and jingle functionality.
 */

const fs = require('fs');
const { execSync } = require('child_process');

describe('Station-Voices', () => {
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

  // Helper to create station-voice
  const createStationVoice = async (stationId, voiceId, mixPoint = 2.0) => {
    const response = await global.api.apiCall('POST', '/station-voices', {
      station_id: parseInt(stationId),
      voice_id: parseInt(voiceId),
      mix_point: mixPoint
    });

    if (response.status === 201) {
      const id = global.api.parseJsonField(response.data, 'id');
      if (id) {
        global.resources.track('stationVoices', id);
        return id;
      }
    }
    return null;
  };

  describe('Station-Voice Creation', () => {
    let stationId, voiceId, svId;

    beforeAll(async () => {
      stationId = await createStation('SV Test Station');
      voiceId = await createVoice('SV Test Voice');
    });

    test('creates station-voice relationship', async () => {
      svId = await createStationVoice(stationId, voiceId, 2.5);

      expect(svId).not.toBeNull();
    });

    test('rejects duplicate relationship', async () => {
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(stationId),
        voice_id: parseInt(voiceId),
        mix_point: 3.0
      });

      expect(response.status).toBe(409);
    });
  });

  describe('Station-Voice with Audio', () => {
    let stationId, voiceId, svId;
    const testAudio = '/tmp/test_jingle.wav';

    beforeAll(async () => {
      stationId = await createStation('Audio Test Station');
      voiceId = await createVoice('Audio Test Voice');

      // Create test audio file if ffmpeg available
      if (!fs.existsSync(testAudio)) {
        try {
          execSync(`ffmpeg -f lavfi -i anullsrc=r=44100:cl=stereo -t 1 -f wav "${testAudio}" 2>/dev/null`, { stdio: 'ignore' });
        } catch {
          // ffmpeg not available
        }
      }
    });

    test('creates station-voice and uploads jingle', async () => {
      if (!fs.existsSync(testAudio)) {
        console.log('Skipping audio test - ffmpeg not available');
        return;
      }

      // Create station-voice
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(stationId),
        voice_id: parseInt(voiceId),
        mix_point: 1.5
      });

      expect(response.status).toBe(201);
      svId = global.api.parseJsonField(response.data, 'id');
      global.resources.track('stationVoices', svId);

      // Upload jingle
      const uploadResponse = await global.api.uploadFile(
        `/station-voices/${svId}/audio`,
        {},
        testAudio,
        'jingle'
      );

      expect(uploadResponse.status).toBe(201);
    });
  });

  describe('Station-Voice Listing', () => {
    beforeAll(async () => {
      const station1 = await createStation('List Station 1');
      const station2 = await createStation('List Station 2');
      const voice1 = await createVoice('List Voice 1');
      const voice2 = await createVoice('List Voice 2');

      await createStationVoice(station1, voice1, 1.0);
      await createStationVoice(station2, voice2, 2.0);
    });

    test('lists station-voices with correct structure', async () => {
      const response = await global.api.apiCall('GET', '/station-voices');

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
      expect(Array.isArray(response.data.data)).toBe(true);

      if (response.data.data.length > 0) {
        const first = response.data.data[0];
        expect(first).toHaveProperty('id');
        expect(first).toHaveProperty('station_id');
        expect(first).toHaveProperty('voice_id');
        expect(first).toHaveProperty('mix_point');
      }
    });
  });

  describe('Audio Fields and Filtering', () => {
    let sv1Id, sv2Id;
    const testAudio = '/tmp/test_jingle_filter.wav';

    beforeAll(async () => {
      const station1 = await createStation('Audio Filter Test Station 1');
      const station2 = await createStation('Audio Filter Test Station 2');
      const voice1 = await createVoice('Audio Filter Test Voice 1');
      const voice2 = await createVoice('Audio Filter Test Voice 2');

      sv1Id = await createStationVoice(station1, voice1, 1.0);
      sv2Id = await createStationVoice(station2, voice2, 2.0);
    });

    test('audio_url and audio_file fields present', async () => {
      const response = await global.api.apiCall('GET', `/station-voices/${sv1Id}`);

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('audio_url');
      expect(typeof response.data.audio_url).toBe('string');
      expect(response.data).toHaveProperty('audio_file');
    });

    test('filters station-voices without audio', async () => {
      const response = await global.api.apiCall('GET', '/station-voices?filter%5Baudio_url%5D=');

      expect(response.status).toBe(200);
      const results = response.data.data || [];
      const allWithoutAudio = results.every(sv => sv.audio_file === '');
      expect(allWithoutAudio).toBe(true);
    });
  });

  describe('Modern Query Parameters', () => {
    let stationIds = [];
    let voiceIds = [];
    let svIds = [];

    beforeAll(async () => {
      const testStations = ['Alpha Radio', 'Beta FM', 'Gamma Broadcasting', 'Delta News', 'Echo Station'];
      const testVoices = ['John Announcer', 'Sarah News', 'Mike Voice', 'Lisa Host', 'Tom News'];
      const mixPoints = [1.0, 2.5, 3.0, 1.5, 2.0];

      for (const name of testStations) {
        const id = await createStation(name);
        if (id) stationIds.push(id);
      }

      for (const name of testVoices) {
        const id = await createVoice(name);
        if (id) voiceIds.push(id);
      }

      for (let i = 0; i < 5; i++) {
        if (stationIds[i] && voiceIds[i]) {
          const svId = await createStationVoice(stationIds[i], voiceIds[i], mixPoints[i]);
          if (svId) svIds.push(svId);
        }
      }
    });

    test('search parameter works', async () => {
      const response = await global.api.apiCall('GET', '/station-voices?search=Radio');

      expect(response.status).toBe(200);
    });

    test('filter by station_id', async () => {
      const response = await global.api.apiCall('GET', `/station-voices?filter[station_id]=${stationIds[0]}`);

      expect(response.status).toBe(200);
      const results = response.data.data || [];
      const matches = results.filter(sv => sv.station_id == stationIds[0]);
      expect(matches.length).toBeGreaterThan(0);
    });

    test('filter by voice_id', async () => {
      const response = await global.api.apiCall('GET', `/station-voices?filter[voice_id]=${voiceIds[1]}`);

      expect(response.status).toBe(200);
    });

    test('filter with in operator', async () => {
      const ids = stationIds.slice(0, 3).join(',');
      const response = await global.api.apiCall('GET', `/station-voices?filter[station_id][in]=${ids}`);

      expect(response.status).toBe(200);
    });

    test('filter mix_point with gte operator', async () => {
      const response = await global.api.apiCall('GET', '/station-voices?filter[mix_point][gte]=2.0');

      expect(response.status).toBe(200);
      const results = response.data.data || [];
      results.forEach(sv => {
        expect(parseFloat(sv.mix_point)).toBeGreaterThanOrEqual(2.0);
      });
    });

    test('filter mix_point with between operator', async () => {
      const response = await global.api.apiCall('GET', '/station-voices?filter[mix_point][between]=1.5,2.5');

      expect(response.status).toBe(200);
      const results = response.data.data || [];
      results.forEach(sv => {
        const mp = parseFloat(sv.mix_point);
        expect(mp).toBeGreaterThanOrEqual(1.5);
        expect(mp).toBeLessThanOrEqual(2.5);
      });
    });

    test('sort by mix_point descending', async () => {
      const response = await global.api.apiCall('GET', '/station-voices?sort=-mix_point');

      expect(response.status).toBe(200);
      const results = response.data.data || [];
      if (results.length > 1) {
        const isSorted = results.every((sv, i) =>
          i === 0 || parseFloat(sv.mix_point) <= parseFloat(results[i - 1].mix_point)
        );
        expect(isSorted).toBe(true);
      }
    });

    test('field selection', async () => {
      const response = await global.api.apiCall('GET', '/station-voices?fields=id,mix_point');

      expect(response.status).toBe(200);
      const results = response.data.data || [];
      if (results.length > 0) {
        expect(results[0]).toHaveProperty('id');
        expect(results[0]).toHaveProperty('mix_point');
      }
    });

    test('pagination with limit', async () => {
      const response = await global.api.apiCall('GET', '/station-voices?limit=2&offset=1');

      expect(response.status).toBe(200);
      const results = response.data.data || [];
      expect(results.length).toBeLessThanOrEqual(2);
    });

    test('complex combined query', async () => {
      const response = await global.api.apiCall('GET',
        '/station-voices?filter[mix_point][gte]=1.5&sort=-mix_point&fields=id,mix_point&limit=10');

      expect(response.status).toBe(200);
    });
  });

  describe('Station-Voice Updates', () => {
    let svId;

    beforeAll(async () => {
      const stationId = await createStation('Update Test Station');
      const voiceId = await createVoice('Update Test Voice');
      svId = await createStationVoice(stationId, voiceId, 1.0);
    });

    test('updates mix_point', async () => {
      const response = await global.api.apiCall('PUT', `/station-voices/${svId}`, {
        mix_point: 3.5
      });

      expect(response.status).toBe(200);

      // Verify update
      const getResponse = await global.api.apiCall('GET', `/station-voices/${svId}`);
      expect(parseFloat(getResponse.data.mix_point)).toBe(3.5);
    });

    test('rejects update of non-existent station-voice', async () => {
      const response = await global.api.apiCall('PUT', '/station-voices/99999', {
        mix_point: 5.0
      });

      expect(response.status).toBe(404);
    });
  });

  describe('Station-Voice Deletion', () => {
    test('deletes station-voice successfully', async () => {
      const stationId = await createStation('Delete Test Station');
      const voiceId = await createVoice('Delete Test Voice');
      const svId = await createStationVoice(stationId, voiceId, 2.0);

      expect(svId).not.toBeNull();

      const response = await global.api.apiCall('DELETE', `/station-voices/${svId}`);
      expect(response.status).toBe(204);

      // Verify deletion
      const getResponse = await global.api.apiCall('GET', `/station-voices/${svId}`);
      expect(getResponse.status).toBe(404);

      global.resources.untrack('stationVoices', svId);
    });

    test('returns 404 for non-existent station-voice', async () => {
      const response = await global.api.apiCall('DELETE', '/station-voices/99999');

      expect(response.status).toBe(404);
    });
  });
});
