const voicesSchema = require('../lib/schemas/voices.schema');
const { generateCrudTests, generateQueryTests, generateValidationTests } = require('../lib/generators');
const { createMySQLExecutor } = require('../lib/MySQLHelper');

describe('Voices', () => {
  // Every two sortable fields order some pair of fixtures oppositely, so a
  // field mapped to another field's column fails a sort test. id rises with
  // the fixture index. The other three keys use distinct, nonmonotonic
  // permutations so neither direction can be satisfied by an ID-order read.
  const setupQueryTestData = async () => {
    const ids = [];
    for (const [index, letter] of ['B', 'A', 'D', 'C'].entries()) {
      const voice = await global.helpers.createVoice(global.resources, `QuerySort${letter}_${index < 3 ? 'querykeep' : 'querydrop'}`);
      ids.push(voice.id);
    }
    createMySQLExecutor().setTimestamps('voices', ids.map((id, index) => [id, { created_at: [2, 0, 1, 3][index], updated_at: [0, 3, 2, 1][index] }]));
    return ids;
  };

  generateCrudTests(voicesSchema);
  generateQueryTests(voicesSchema, setupQueryTestData);
  generateValidationTests(voicesSchema);

  describe('Voice with Associated Stories', () => {
    let voiceId;

    beforeAll(async () => {
      const voice = await global.helpers.createVoice(global.resources, 'AssociatedVoice');
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
