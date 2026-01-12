/**
 * Babbel station-voices tests.
 * Tests station-voice relationship management and jingle functionality.
 */

const fs = require('fs');
const { execSync } = require('child_process');
const stationVoicesSchema = require('../lib/schemas/station-voices.schema');
const { generateQueryTests } = require('../lib/generators');

describe('Station-Voices', () => {
  // Helper to create station-voice with dependencies
  const createStationVoiceWithDeps = async (stationName, voiceName, mixPoint = 2.0) => {
    const station = await global.helpers.createStation(global.resources, stationName);
    const voice = await global.helpers.createVoice(global.resources, voiceName);

    const response = await global.api.apiCall('POST', '/station-voices', {
      station_id: parseInt(station.id, 10),
      voice_id: parseInt(voice.id, 10),
      mix_point: mixPoint
    });

    if (response.status === 201) {
      global.resources.track('stationVoices', response.data.id);
      return { id: response.data.id, stationId: station.id, voiceId: voice.id };
    }
    return null;
  };

  // Setup function for query tests - creates test data
  const setupQueryTestData = async () => {
    const testData = [
      { station: 'QueryStation1', voice: 'QueryVoice1', mix: 1.0 },
      { station: 'QueryStation2', voice: 'QueryVoice2', mix: 2.5 },
      { station: 'QueryStation3', voice: 'QueryVoice3', mix: 3.0 }
    ];

    const ids = [];
    for (const data of testData) {
      const result = await createStationVoiceWithDeps(data.station, data.voice, data.mix);
      if (result) ids.push(result.id);
    }
    return ids;
  };

  // Generate query parameter tests with custom setup
  generateQueryTests(stationVoicesSchema, setupQueryTestData);

  // === BUSINESS LOGIC TESTS ===
  // Tests specific to station-voice behavior that can't be generated

  describe('Station-Voice CRUD', () => {
    let stationId, voiceId, svId;

    beforeAll(async () => {
      const station = await global.helpers.createStation(global.resources, 'CRUD Test Station');
      const voice = await global.helpers.createVoice(global.resources, 'CRUD Test Voice');
      stationId = station.id;
      voiceId = voice.id;
    });

    test('creates station-voice relationship', async () => {
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(stationId, 10),
        voice_id: parseInt(voiceId, 10),
        mix_point: 2.5
      });

      expect(response.status).toBe(201);
      expect(response.data).toHaveProperty('id');
      svId = response.data.id;
      global.resources.track('stationVoices', svId);
    });

    test('retrieves station-voice by ID', async () => {
      const response = await global.api.apiCall('GET', `/station-voices/${svId}`);

      expect(response.status).toBe(200);
      expect(response.data.station_id).toBe(parseInt(stationId, 10));
      expect(response.data.voice_id).toBe(parseInt(voiceId, 10));
    });

    test('rejects duplicate relationship', async () => {
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(stationId, 10),
        voice_id: parseInt(voiceId, 10),
        mix_point: 3.0
      });

      expect(response.status).toBe(409);
    });

    test('updates mix_point', async () => {
      const response = await global.api.apiCall('PUT', `/station-voices/${svId}`, {
        mix_point: 4.5
      });

      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/station-voices/${svId}`);
      expect(parseFloat(getResponse.data.mix_point)).toBe(4.5);
    });

    test('returns 404 for non-existent station-voice', async () => {
      const response = await global.api.apiCall('GET', '/station-voices/999999');
      expect(response.status).toBe(404);
    });
  });

  describe('Station-Voice Deletion', () => {
    test('deletes station-voice successfully', async () => {
      const result = await createStationVoiceWithDeps('Delete Test Station', 'Delete Test Voice', 2.0);
      expect(result).not.toBeNull();

      const response = await global.api.apiCall('DELETE', `/station-voices/${result.id}`);
      expect(response.status).toBe(204);

      const getResponse = await global.api.apiCall('GET', `/station-voices/${result.id}`);
      expect(getResponse.status).toBe(404);

      global.resources.untrack('stationVoices', result.id);
    });

    test('returns 404 for non-existent deletion', async () => {
      const response = await global.api.apiCall('DELETE', '/station-voices/999999');
      expect(response.status).toBe(404);
    });
  });

  describe('Station-Voice Audio', () => {
    const testAudio = '/tmp/test_jingle.wav';

    beforeAll(async () => {
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

      const result = await createStationVoiceWithDeps('Audio Test Station', 'Audio Test Voice', 1.5);
      expect(result).not.toBeNull();

      const uploadResponse = await global.api.uploadFile(
        `/station-voices/${result.id}/audio`,
        {},
        testAudio,
        'jingle'
      );

      expect(uploadResponse.status).toBe(201);
    });

    test('audio_url and audio_file fields present', async () => {
      const result = await createStationVoiceWithDeps('AudioFields Test Station', 'AudioFields Test Voice', 2.0);
      expect(result).not.toBeNull();

      const response = await global.api.apiCall('GET', `/station-voices/${result.id}`);

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('audio_url');
      expect(typeof response.data.audio_url).toBe('string');
      expect(response.data).toHaveProperty('audio_file');
    });
  });

  describe('Validation', () => {
    test('rejects missing station_id', async () => {
      const voice = await global.helpers.createVoice(global.resources, 'ValidationVoice1');
      const response = await global.api.apiCall('POST', '/station-voices', {
        voice_id: parseInt(voice.id, 10),
        mix_point: 2.0
      });

      expect(response.status).toBe(422);
    });

    test('rejects missing voice_id', async () => {
      const station = await global.helpers.createStation(global.resources, 'ValidationStation1');
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(station.id, 10),
        mix_point: 2.0
      });

      expect(response.status).toBe(422);
    });

    test('rejects invalid station_id', async () => {
      const voice = await global.helpers.createVoice(global.resources, 'ValidationVoice2');
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: 999999,
        voice_id: parseInt(voice.id, 10),
        mix_point: 2.0
      });

      expect([404, 422]).toContain(response.status);
    });

    test('rejects invalid voice_id', async () => {
      const station = await global.helpers.createStation(global.resources, 'ValidationStation2');
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(station.id, 10),
        voice_id: 999999,
        mix_point: 2.0
      });

      expect([404, 422]).toContain(response.status);
    });
  });
});
