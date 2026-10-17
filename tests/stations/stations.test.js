const stationsSchema = require('../lib/schemas/stations.schema');
const { generateCrudTests, generateQueryTests, generateValidationTests } = require('../lib/generators');
const { createMySQLExecutor } = require('../lib/MySQLHelper');

describe('Stations', () => {
  // Every sortable field rises with the fixture index except name, the
  // default sort key, which lists the fixtures as 1, 0, 2.
  const setupQueryTestData = async () => {
    const ids = [];
    for (const [index, letter] of ['B', 'A', 'C'].entries()) {
      const station = await global.helpers.createStation(global.resources, `QuerySort${letter}`, index + 3, index + 1);
      expect(station).not.toBeNull();
      ids.push(station.id);
    }
    createMySQLExecutor().setTimestamps('stations', ids.map((id, index) => [id, { created_at: index, updated_at: index }]));
    return ids;
  };

  generateCrudTests(stationsSchema);
  generateQueryTests(stationsSchema, setupQueryTestData);
  generateValidationTests(stationsSchema);

  describe('Station Dependencies', () => {
    let stationId;
    let voiceId;

    beforeAll(async () => {
      const station = await global.helpers.createStation(
        global.resources,
        'DependencyTestStation',
        5,
        2.0
      );
      expect(station).not.toBeNull();
      stationId = station.id;

      const voice = await global.helpers.createVoice(global.resources, 'DependencyTestVoice');
      expect(voice).not.toBeNull();
      voiceId = voice.id;
    });

    test('when deleting station with station-voices, then returns dependency conflict', async () => {
      const svResponse = await global.api.apiCall('POST', '/station-voices', {
        station_id: stationId,
        voice_id: voiceId,
        mix_point: 3.0
      });
      expect(svResponse.status).toBe(201);

      global.resources.track('stationVoices', svResponse.data.id);

      const deleteResponse = await global.api.apiCall('DELETE', `/stations/${stationId}`);

      expect(deleteResponse.status).toBe(409);
      expect(deleteResponse.data.code).toBe('station.has_dependencies');
    });
  });

  describe('Station Configuration Limits', () => {
    test('when max_stories_per_block at maximum, then accepted', async () => {
      const data = {
        name: `MaxStoriesTest_${Date.now()}`,
        max_stories_per_block: 50,
        pause_seconds: 2.0
      };

      const response = await global.api.apiCall('POST', '/stations', data);

      expect(response.status).toBe(201);

      if (response.data?.id) {
        global.resources.track('stations', response.data.id);
      }
    });

    test('when pause_seconds at maximum, then accepted', async () => {
      const data = {
        name: `MaxPauseTest_${Date.now()}`,
        max_stories_per_block: 5,
        pause_seconds: 60.0
      };

      const response = await global.api.apiCall('POST', '/stations', data);

      expect(response.status).toBe(201);

      if (response.data?.id) {
        global.resources.track('stations', response.data.id);
      }
    });

    test('when values at minimum, then accepted', async () => {
      const data = {
        name: `MinValuesTest_${Date.now()}`,
        max_stories_per_block: 1,
        pause_seconds: 0
      };

      const response = await global.api.apiCall('POST', '/stations', data);

      expect(response.status).toBe(201);

      if (response.data?.id) {
        global.resources.track('stations', response.data.id);
      }
    });
  });
});
