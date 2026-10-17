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

  // Every two sortable fields order some pair of fixtures oppositely, so a
  // field mapped to another field's column fails a sort test. id, the default
  // sort key, rises with the fixture index; station and voice ids rise with
  // their index in stations and voices.
  const setupQueryTestData = async () => {
    const stations = [];
    const voices = [];
    for (let n = 1; n <= 4; n++) {
      stations.push(await global.helpers.createStation(global.resources, `QueryStation${n}`));
      voices.push(await global.helpers.createVoice(global.resources, `QueryVoice${n}`));
    }

    const fixtures = [
      // [station index, voice index, mix_point, created_at, updated_at]
      [2, 1, 2.5, 1, 4],
      [0, 3, 3.0, 0, 6],
      [3, 0, 1.0, 3, 7],
      [1, 2, 2.0, 2, 5]
    ];
    const ids = [];
    const timestamps = [];
    for (const [station, voice, mix, createdAt, updatedAt] of fixtures) {
      const stationVoice = await global.helpers.createStationVoice(global.resources, stations[station].id, voices[voice].id, mix);
      expect(stationVoice).not.toBeNull();
      ids.push(stationVoice.id);
      timestamps.push([stationVoice.id, { created_at: createdAt, updated_at: updatedAt }]);
    }
    createMySQLExecutor().setTimestamps('station_voices', timestamps);
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

    test('when changing station or voice with a jingle, then returns 409 and keeps the pair', async () => {
      const station = await global.helpers.createStation(global.resources, 'JingleLockStation');
      const otherStation = await global.helpers.createStation(global.resources, 'JingleLockStation2');
      const voice = await global.helpers.createVoice(global.resources, 'JingleLockVoice');
      const otherVoice = await global.helpers.createVoice(global.resources, 'JingleLockVoice2');
      const stationVoice = await global.helpers.createStationVoice(global.resources, station.id, voice.id, 1.0);
      expect(stationVoice).not.toBeNull();

      const uploadResponse = await global.api.uploadFile(
        `/station-voices/${stationVoice.id}/audio`,
        {},
        testAudio,
        'jingle'
      );
      expect(uploadResponse.status).toBe(201);

      for (const change of [{ station_id: otherStation.id }, { voice_id: otherVoice.id }]) {
        const conflict = await global.api.apiCall('PUT', `/station-voices/${stationVoice.id}`, change);
        expect(conflict.status).toBe(409);
        expect(conflict.data.code).toBe('stationvoice.jingle_locked');
      }

      const resend = await global.api.apiCall('PUT', `/station-voices/${stationVoice.id}`, {
        station_id: station.id,
        voice_id: voice.id,
        mix_point: 2.0
      });
      expect(resend.status).toBe(200);
      expect(resend.data).toMatchObject({ station_id: station.id, voice_id: voice.id, mix_point: 2.0 });

      const jingle = await global.api.apiCall('GET', `/station-voices/${stationVoice.id}/audio`, null, {
        responseType: 'arraybuffer'
      });
      expect(jingle.status).toBe(200);
    });

    test('when changing station or voice without a jingle, then moves the pair', async () => {
      const station = await global.helpers.createStation(global.resources, 'NoJingleMoveStation');
      const otherStation = await global.helpers.createStation(global.resources, 'NoJingleMoveStation2');
      const voice = await global.helpers.createVoice(global.resources, 'NoJingleMoveVoice');
      const otherVoice = await global.helpers.createVoice(global.resources, 'NoJingleMoveVoice2');
      const stationVoice = await global.helpers.createStationVoice(global.resources, station.id, voice.id, 1.0);
      expect(stationVoice).not.toBeNull();

      const moved = await global.api.apiCall('PUT', `/station-voices/${stationVoice.id}`, {
        station_id: otherStation.id,
        voice_id: otherVoice.id
      });

      expect(moved.status).toBe(200);
      expect(moved.data).toMatchObject({ station_id: otherStation.id, voice_id: otherVoice.id });
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
