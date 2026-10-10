const stationsSchema = require('../lib/schemas/stations.schema');
const { generateCrudTests, generateQueryTests, generateValidationTests } = require('../lib/generators');

describe('Stations', () => {
  // Generate standard CRUD, Query, and Validation tests
  generateCrudTests(stationsSchema);
  generateQueryTests(stationsSchema);
  generateValidationTests(stationsSchema);

  // === BUSINESS LOGIC TESTS ===
  // Tests specific to station behavior that can't be generated

  describe('Station Dependencies', () => {
    let stationId;
    let voiceId;

    beforeAll(async () => {
      // Create station and voice for dependency testing
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
      // Create station-voice relationship
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

      // Cleanup
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

      // Cleanup
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

      // Cleanup
      if (response.data?.id) {
        global.resources.track('stations', response.data.id);
      }
    });
  });
});
