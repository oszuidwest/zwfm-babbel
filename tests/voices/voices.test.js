/**
 * Babbel voices tests.
 * Tests voice management functionality including CRUD operations, queries, and validation.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

const voicesSchema = require('../lib/schemas/voices.schema');
const { generateCrudTests, generateQueryTests, generateValidationTests } = require('../lib/generators');

describe('Voices', () => {
  // Generate standard CRUD, Query, and Validation tests
  generateCrudTests(voicesSchema);
  generateQueryTests(voicesSchema);
  generateValidationTests(voicesSchema);

  // === BUSINESS LOGIC TESTS ===
  // Tests specific to voice behavior that can't be generated

  describe('Voice with Associated Stories', () => {
    let stationId;
    let voiceId;

    beforeAll(async () => {
      // Arrange: Create station and voice for dependency testing
      const station = await global.helpers.createStation(
        global.resources,
        'VoiceTestStation',
        4,
        2.0
      );
      expect(station).not.toBeNull();
      stationId = station.id;

      const voice = await global.helpers.createVoice(global.resources, 'AssociatedVoice');
      expect(voice).not.toBeNull();
      voiceId = voice.id;
    });

    test('when deleting voice with stories, then protected or cascades', async () => {
      // Arrange: Create story with voice dependency
      const storyData = {
        title: 'Voice Association Test Story',
        text: 'Test content for voice association.',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: new Date().toISOString().split('T')[0],
        end_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        weekdays: 127,
        target_stations: [parseInt(stationId, 10)]
      };

      const storyResponse = await global.api.apiCall('POST', '/stories', storyData);
      expect(storyResponse.status).toBe(201);

      const storyId = global.api.parseJsonField(storyResponse.data, 'id');
      global.resources.track('stories', storyId);

      // Act
      const deleteResponse = await global.api.apiCall('DELETE', `/voices/${voiceId}`);

      // Assert: Should either protect (409) or cascade delete (204)
      expect([204, 409]).toContain(deleteResponse.status);

      // Cleanup: Untrack if deleted
      if (deleteResponse.status === 204) {
        global.resources.untrack('voices', voiceId);
      }
    });
  });
});
