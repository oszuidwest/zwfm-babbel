/**
 * Babbel stations tests.
 * Tests station management functionality including CRUD operations, queries, and validation.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
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
      // Arrange: Create station and voice for dependency testing
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

    test('when deleting station with station-voices, then protected or cascades', async () => {
      // Arrange: Create station-voice relationship
      const svResponse = await global.api.apiCall('POST', '/station-voices', {
        station_id: parseInt(stationId, 10),
        voice_id: parseInt(voiceId, 10),
        mix_point: 3.0
      });
      expect(svResponse.status).toBe(201);

      const svId = global.api.parseJsonField(svResponse.data, 'id');
      global.resources.track('stationVoices', svId);

      // Act
      const deleteResponse = await global.api.apiCall('DELETE', `/stations/${stationId}`);

      // Assert: Should either protect (409) or cascade delete (204)
      expect([204, 409]).toContain(deleteResponse.status);

      // Cleanup: Untrack if deleted
      if (deleteResponse.status === 204) {
        global.resources.untrack('stations', stationId);
      }
    });
  });

  describe('Station Configuration Limits', () => {
    test('when max_stories_per_block at maximum, then accepted', async () => {
      // Arrange
      const data = {
        name: `MaxStoriesTest_${Date.now()}`,
        max_stories_per_block: 50,
        pause_seconds: 2.0
      };

      // Act
      const response = await global.api.apiCall('POST', '/stations', data);

      // Assert
      expect(response.status).toBe(201);

      // Cleanup
      if (response.data?.id) {
        global.resources.track('stations', response.data.id);
      }
    });

    test('when pause_seconds at maximum, then accepted', async () => {
      // Arrange
      const data = {
        name: `MaxPauseTest_${Date.now()}`,
        max_stories_per_block: 5,
        pause_seconds: 60.0
      };

      // Act
      const response = await global.api.apiCall('POST', '/stations', data);

      // Assert
      expect(response.status).toBe(201);

      // Cleanup
      if (response.data?.id) {
        global.resources.track('stations', response.data.id);
      }
    });

    test('when values at minimum, then accepted', async () => {
      // Arrange
      const data = {
        name: `MinValuesTest_${Date.now()}`,
        max_stories_per_block: 1,
        pause_seconds: 0
      };

      // Act
      const response = await global.api.apiCall('POST', '/stations', data);

      // Assert
      expect(response.status).toBe(201);

      // Cleanup
      if (response.data?.id) {
        global.resources.track('stations', response.data.id);
      }
    });
  });
});
