const voicesSchema = require('../lib/schemas/voices.schema');
const { generateCrudTests, generateQueryTests, generateValidationTests } = require('../lib/generators');
const { createMySQLExecutor } = require('../lib/MySQLHelper');

describe('Voices', () => {
  // Every sortable field rises with the fixture index except name, the
  // default sort key, which lists the fixtures as 1, 0, 2.
  const setupQueryTestData = async () => {
    const ids = [];
    for (const letter of ['B', 'A', 'C']) {
      const voice = await global.helpers.createVoice(global.resources, `QuerySort${letter}`);
      expect(voice).not.toBeNull();
      ids.push(voice.id);
    }
    createMySQLExecutor().setTimestamps('voices', ids.map((id, index) => [id, { created_at: index, updated_at: index }]));
    return ids;
  };

  generateCrudTests(voicesSchema);
  generateQueryTests(voicesSchema, setupQueryTestData);
  generateValidationTests(voicesSchema);

  describe('Voice with Associated Stories', () => {
    let voiceId;

    beforeAll(async () => {
      const voice = await global.helpers.createVoice(global.resources, 'AssociatedVoice');
      expect(voice).not.toBeNull();
      voiceId = voice.id;
    });

    test('when deleting voice with stories, then returns dependency conflict', async () => {
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
