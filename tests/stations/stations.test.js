const stationsSchema = require('../lib/schemas/stations.schema');
const { generateCrudTests, generateQueryTests, generateValidationTests } = require('../lib/generators');
const { createMySQLExecutor } = require('../lib/MySQLHelper');

describe('Stations', () => {
  // Every two sortable fields order some pair of fixtures oppositely, so a
  // field mapped to another field's column fails a sort test. name, the
  // default sort key, lists them as 1, 0, 3, 2; id rises with the fixture
  // index.
  const setupQueryTestData = async () => {
    const fixtures = [
      // [name, max_stories_per_block, pause_seconds, created_at, updated_at]
      ['B', 5, 2, 3, 4],
      ['A', 3, 4, 0, 6],
      ['D', 6, 1, 2, 7],
      ['C', 4, 3, 1, 5]
    ];
    const ids = [];
    const timestamps = [];
    for (const [index, [letter, maxStories, pauseSeconds, createdAt, updatedAt]] of fixtures.entries()) {
      const station = await global.helpers.createStation(global.resources, `QuerySort${letter}_${index < 3 ? 'querykeep' : 'querydrop'}`, maxStories, pauseSeconds);
      ids.push(station.id);
      timestamps.push([station.id, { created_at: createdAt, updated_at: updatedAt }]);
    }
    createMySQLExecutor().setTimestamps('stations', timestamps);
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
      stationId = station.id;

      const voice = await global.helpers.createVoice(global.resources, 'DependencyTestVoice');
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
