const stationVoicesSchema = require('../lib/schemas/station-voices.schema');
const { generateCrudTests, generateQueryTests, generateValidationTests } = require('../lib/generators');
const { createMySQLExecutor } = require('../lib/MySQLHelper');

describe('Station-Voices', () => {
  const createDependencies = async () => {
    const station = await global.helpers.createStation(global.resources, `SVDep_${Date.now()}`);
    const voice = await global.helpers.createVoice(global.resources, `SVDep_${Date.now()}`);
    return {
      station_id: station.id,
      voice_id: voice.id
    };
  };

  // Every sortable field rises with the fixture index except id, the default
  // sort key: the links are created as 1, 0, 2.
  const setupQueryTestData = async () => {
    const fixtures = [];
    for (const [index, mix] of [1.0, 2.5, 3.0].entries()) {
      const station = await global.helpers.createStation(global.resources, `QueryStation${index + 1}`);
      const voice = await global.helpers.createVoice(global.resources, `QueryVoice${index + 1}`);
      fixtures.push({ station, voice, mix });
    }

    const ids = [];
    for (const index of [1, 0, 2]) {
      const { station, voice, mix } = fixtures[index];
      const stationVoice = await global.helpers.createStationVoice(global.resources, station.id, voice.id, mix);
      expect(stationVoice).not.toBeNull();
      ids[index] = stationVoice.id;
    }
    createMySQLExecutor().setTimestamps('station_voices', ids.map((id, index) => [id, { created_at: index, updated_at: index }]));
    return ids;
  };

  generateCrudTests(stationVoicesSchema, createDependencies);
  generateQueryTests(stationVoicesSchema, setupQueryTestData);
  generateValidationTests(stationVoicesSchema, createDependencies);

  describe('Duplicate Detection', () => {
    test('when creating duplicate station-voice pair, then returns 409', async () => {
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

      const duplicate = await global.api.apiCall('POST', '/station-voices', data);

      expect(duplicate.status).toBe(409);
      expect(duplicate.data.code).toBe('stationvoice.duplicate');
    });
  });

  describe('Station-Voice Audio', () => {
    const testAudio = '/tmp/test_jingle.wav';

    beforeAll(() => {
      if (!global.helpers.createTestAudioFile(testAudio, 1)) {
        throw new Error('Station-voice audio tests require ffmpeg');
      }
    });

    afterAll(() => {
      global.helpers.cleanupTempFile(testAudio);
    });

    test('when uploading jingle, then attached', async () => {
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
    test('when station_id references a missing resource, then returns 422', async () => {
      const voice = await global.helpers.createVoice(global.resources, 'FKValidationVoice');

      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: 999999,
        voice_id: voice.id,
        mix_point: 2.0
      });

      expect(response.status).toBe(422);
      expect(response.data.errors).toEqual([expect.objectContaining({ field: 'station_id', code: 'not_found' })]);
    });

    test('when voice_id references a missing resource, then returns 422', async () => {
      const station = await global.helpers.createStation(global.resources, 'FKValidationStation');

      const response = await global.api.apiCall('POST', '/station-voices', {
        station_id: station.id,
        voice_id: 999999,
        mix_point: 2.0
      });

      expect(response.status).toBe(422);
      expect(response.data.errors).toEqual([expect.objectContaining({ field: 'voice_id', code: 'not_found' })]);
    });
  });
});
