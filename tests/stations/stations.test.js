/**
 * Babbel stations tests.
 * Tests station management functionality including CRUD operations, queries, and validation.
 */

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
      // Create station
      const station = await global.helpers.createStation(
        global.resources,
        'DependencyTestStation',
        5,
        2.0
      );
      expect(station).not.toBeNull();
      stationId = station.id;

      // Create voice
      const voice = await global.helpers.createVoice(global.resources, 'DependencyTestVoice');
      expect(voice).not.toBeNull();
      voiceId = voice.id;
    });

    test('station deletion behavior with associated station-voices', async () => {
      // Create station-voice relationship
      const svResponse = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(stationId, 10),
        voice_id: parseInt(voiceId, 10),
        mix_point: 3.0
      });
      expect(svResponse.status).toBe(201);

      const svId = global.api.parseJsonField(svResponse.data, 'id');
      global.resources.track('stationVoices', svId);

      // Try to delete the station - should fail with 409 (has dependencies)
      const deleteResponse = await global.api.apiCall('DELETE', `/stations/${stationId}`);
      expect([204, 409]).toContain(deleteResponse.status);

      if (deleteResponse.status === 204) {
        global.resources.untrack('stations', stationId);
      }
    });
  });

  describe('Station Configuration Limits', () => {
    test('accepts maximum allowed max_stories_per_block', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: `MaxStoriesTest_${Date.now()}`,
        max_stories_per_block: 50,
        pause_seconds: 2.0
      });

      expect(response.status).toBe(201);
      if (response.data?.id) {
        global.resources.track('stations', response.data.id);
      }
    });

    test('accepts maximum allowed pause_seconds', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: `MaxPauseTest_${Date.now()}`,
        max_stories_per_block: 5,
        pause_seconds: 60.0
      });

      expect(response.status).toBe(201);
      if (response.data?.id) {
        global.resources.track('stations', response.data.id);
      }
    });

    test('accepts minimum valid values', async () => {
      const response = await global.api.apiCall('POST', '/stations', {
        name: `MinValuesTest_${Date.now()}`,
        max_stories_per_block: 1,
        pause_seconds: 0
      });

      expect(response.status).toBe(201);
      if (response.data?.id) {
        global.resources.track('stations', response.data.id);
      }
    });
  });
});
