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
    let voiceId;

    beforeAll(async () => {
      const voice = await global.helpers.createVoice(global.resources, 'AssociatedVoice');
      expect(voice).not.toBeNull();
      voiceId = voice.id;
    });

    test('when deleting voice with stories, then returns dependency conflict', async () => {
      // Create story with voice dependency
      const storyData = {
        title: 'Voice Association Test Story',
        text: 'Test content for voice association.',
        voice_id: voiceId,
        status: 'active',
        start_date: new Date().toISOString().split('T')[0],
        end_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
        weekdays: 127
      };

      const storyResponse = await global.api.apiCall('POST', '/stories', storyData);
      expect(storyResponse.status).toBe(201);

      global.resources.track('stories', storyResponse.data.id);

      const deleteResponse = await global.api.apiCall('DELETE', `/voices/${voiceId}`);

      expect(deleteResponse.status).toBe(409);
      expect(deleteResponse.data.code).toBe('voice.has_dependencies');
    });
  });
});
