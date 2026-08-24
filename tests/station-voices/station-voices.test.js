const stationVoicesSchema = require('../lib/schemas/station-voices.schema');
const { generateCrudTests, generateQueryTests, generateValidationTests } = require('../lib/generators');

describe('Station-Voices', () => {
  // Setup function creates dependencies and returns data to merge with createValidData
  const createDependencies = async () => {
    const station = await global.helpers.createStation(global.resources, `SVDep_${Date.now()}`);
    const voice = await global.helpers.createVoice(global.resources, `SVDep_${Date.now()}`);
    return {
      station_id: station.id,
      voice_id: voice.id
    };
  };

  // Setup function for query tests - creates multiple station-voices for testing
  const setupQueryTestData = async () => {
    const testData = [
      { station: 'QueryStation1', voice: 'QueryVoice1', mix: 1.0 },
      { station: 'QueryStation2', voice: 'QueryVoice2', mix: 2.5 },
      { station: 'QueryStation3', voice: 'QueryVoice3', mix: 3.0 }
    ];

    const ids = [];
    for (const data of testData) {
      const station = await global.helpers.createStation(global.resources, data.station);
      const voice = await global.helpers.createVoice(global.resources, data.voice);

      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: station.id,
        voice_id: voice.id,
        mix_point: data.mix
      });

      if (response.status === 201) {
        global.resources.track('stationVoices', response.data.id);
        ids.push(response.data.id);
      }
    }
    return ids;
  };

  // Generate standard tests using generators
  generateCrudTests(stationVoicesSchema, createDependencies);
  generateQueryTests(stationVoicesSchema, setupQueryTestData);
  generateValidationTests(stationVoicesSchema, createDependencies);

  // === BUSINESS LOGIC TESTS ===
  // Tests specific to station-voice behavior that can't be generated

  describe('Duplicate Detection', () => {
    test('when creating duplicate station-voice pair, then returns 409', async () => {
      // Create a station-voice
      const station = await global.helpers.createStation(global.resources, 'DupStation');
      const voice = await global.helpers.createVoice(global.resources, 'DupVoice');
      const data = {
        station_id: station.id,
        voice_id: voice.id,
        mix_point: 2.5
      };

      const first = await global.api.apiCall('POST', '/station-voices', data);
      expect(first.status).toBe(201);
      global.resources.track('stationVoices', first.data.id);

      // Try to create duplicate
      const duplicate = await global.api.apiCall('POST', '/station-voices', data);

      expect(duplicate.status).toBe(409);
    });
  });

  describe('Station-Voice Audio', () => {
    const testAudio = '/tmp/test_jingle.wav';
    let audioAvailable = false;

    beforeAll(() => {
      audioAvailable = global.helpers.createTestAudioFile(testAudio, 1);
      if (!audioAvailable) {
        console.warn('Audio tests will be skipped (ffmpeg not available)');
      }
    });

    afterAll(() => {
      global.helpers.cleanupTempFile(testAudio);
    });

    test('when uploading jingle, then attached', async () => {
      if (!audioAvailable) return;

      const station = await global.helpers.createStation(global.resources, 'AudioTestStation');
      const voice = await global.helpers.createVoice(global.resources, 'AudioTestVoice');
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: station.id,
        voice_id: voice.id,
        mix_point: 1.5
      });
      expect(response.status).toBe(201);
      global.resources.track('stationVoices', response.data.id);

      const uploadResponse = await global.api.uploadFile(
        `/station-voices/${response.data.id}/audio`,
        {},
        testAudio,
        'jingle'
      );

      expect(uploadResponse.status).toBe(201);
    });

    test('when fetching, then audio fields present', async () => {
      const station = await global.helpers.createStation(global.resources, 'AudioFieldsStation');
      const voice = await global.helpers.createVoice(global.resources, 'AudioFieldsVoice');
      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: station.id,
        voice_id: voice.id,
        mix_point: 2.0
      });
      expect(response.status).toBe(201);
      global.resources.track('stationVoices', response.data.id);

      const getResponse = await global.api.apiCall('GET', `/station-voices/${response.data.id}`);

      expect(getResponse.status).toBe(200);
      expect(getResponse.data).toHaveProperty('audio_url');
      expect(typeof getResponse.data.audio_url).toBe('string');
      expect(getResponse.data).toHaveProperty('audio_file');
    });

    test('when filtering has_audio, then partitions by jingle presence', async () => {
      if (!audioAvailable) return;

      // Two voices on one station, only one with a jingle
      const station = await global.helpers.createStation(global.resources, 'HasAudioFilterStation');
      const voiceWith = await global.helpers.createVoice(global.resources, 'HasAudioFilterVoice1');
      const voiceWithout = await global.helpers.createVoice(global.resources, 'HasAudioFilterVoice2');

      const withJingle = await global.api.apiCall('POST', '/station-voices', {
        station_id: station.id,
        voice_id: voiceWith.id,
        mix_point: 1.0
      });
      const withoutJingle = await global.api.apiCall('POST', '/station-voices', {
        station_id: station.id,
        voice_id: voiceWithout.id,
        mix_point: 1.0
      });
      expect(withJingle.status).toBe(201);
      expect(withoutJingle.status).toBe(201);
      global.resources.track('stationVoices', withJingle.data.id);
      global.resources.track('stationVoices', withoutJingle.data.id);

      const uploadResponse = await global.api.uploadFile(
        `/station-voices/${withJingle.data.id}/audio`,
        {},
        testAudio,
        'jingle'
      );
      expect(uploadResponse.status).toBe(201);

      // Has_audio partitions the station's pairs
      const withResponse = await global.api.apiCall(
        'GET',
        `/station-voices?filter[station_id]=${station.id}&filter[has_audio]=true`
      );
      expect(withResponse.status).toBe(200);
      expect(withResponse.data.data.map((sv) => sv.id)).toEqual([withJingle.data.id]);

      const withoutResponse = await global.api.apiCall(
        'GET',
        `/station-voices?filter[station_id]=${station.id}&filter[has_audio]=false`
      );
      expect(withoutResponse.status).toBe(200);
      expect(withoutResponse.data.data.map((sv) => sv.id)).toEqual([withoutJingle.data.id]);
    });
  });

  describe('Foreign Key Validation', () => {
    test('when station_id invalid, then returns error', async () => {
      const voice = await global.helpers.createVoice(global.resources, 'FKValidationVoice');

      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: 999999,
        voice_id: voice.id,
        mix_point: 2.0
      });

      expect([404, 422]).toContain(response.status);
    });

    test('when voice_id invalid, then returns error', async () => {
      const station = await global.helpers.createStation(global.resources, 'FKValidationStation');

      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: station.id,
        voice_id: 999999,
        mix_point: 2.0
      });

      expect([404, 422]).toContain(response.status);
    });
  });
});
