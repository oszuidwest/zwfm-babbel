/**
 * Babbel voices tests.
 * Tests voice management functionality including CRUD operations and story associations.
 */

describe('Voices', () => {
  // Helper to create voice with unique name
  const createVoice = async (name) => {
    const result = await global.helpers.createVoice(global.resources, name);
    return result ? { id: result.id, name: result.name } : null;
  };

  describe('Voice Creation', () => {
    let createdVoice;

    test('creates a valid voice', async () => {
      createdVoice = await createVoice('Test Voice 1');

      expect(createdVoice).not.toBeNull();
      expect(createdVoice.id).toBeDefined();
    });

    test('created voice can be retrieved', async () => {
      const response = await global.api.apiCall('GET', `/voices/${createdVoice.id}`);

      expect(response.status).toBe(200);
      expect(response.data.name).toBe(createdVoice.name);
    });

    test('rejects duplicate voice name', async () => {
      const duplicateResponse = await global.api.apiCall('POST', '/voices', { name: createdVoice.name });

      expect(duplicateResponse.status).toBe(409);
    });

    test('rejects voice creation without name', async () => {
      const invalidResponse = await global.api.apiCall('POST', '/voices', {});

      expect(invalidResponse.status).toBe(422);
    });
  });

  describe('Voice Listing', () => {
    beforeAll(async () => {
      await createVoice('List Test Voice 1');
      await createVoice('List Test Voice 2');
      await createVoice('List Test Voice 3');
    });

    test('returns voices in data array', async () => {
      const response = await global.api.apiCall('GET', '/voices');

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
      expect(Array.isArray(response.data.data)).toBe(true);
      expect(response.data.data.length).toBeGreaterThan(0);
    });
  });

  describe('Modern Query Parameters', () => {
    let queryTestIds = [];

    beforeAll(async () => {
      const testVoices = [
        'Alpha Voice',
        'Beta Announcer',
        'Gamma Newsreader',
        'Delta Broadcasting Voice',
        'Echo Radio Voice',
        'Foxtrot News Voice'
      ];

      for (const voiceName of testVoices) {
        const voiceData = await createVoice(voiceName);
        if (voiceData && voiceData.id) {
          queryTestIds.push(voiceData.id);
        }
      }
    });

    const runQuery = async (path) => {
      const response = await global.api.apiCall('GET', path);
      expect(response.status).toBe(200);
      return response;
    };

    const queryCases = [
      {
        name: 'search parameter filters results',
        path: '/voices?search=Voice',
        assert: (response) => {
          const results = response.data.data || [];
          const voiceMatches = results.filter(v => v.name && v.name.includes('Voice'));
          expect(voiceMatches.length).toBeGreaterThan(0);
        }
      },
      {
        name: 'filter by exact ID returns single voice',
        path: () => `/voices?filter[id]=${queryTestIds[0]}`,
        assert: (response) => {
          const results = response.data.data || [];
          const exactMatches = results.filter(v => v.id == queryTestIds[0]);
          expect(exactMatches.length).toBe(1);
        }
      },
      {
        name: 'filter with in operator returns multiple voices',
        path: () => {
          const ids = queryTestIds.slice(0, 3).join(',');
          return `/voices?filter[id][in]=${ids}`;
        },
        assert: (response) => {
          const results = response.data.data || [];
          const inMatches = results.filter(v => queryTestIds.slice(0, 3).includes(String(v.id)));
          expect(inMatches.length).toBe(3);
        }
      },
      {
        name: 'sort ascending by name',
        path: '/voices?sort=name',
        assert: (response) => {
          const results = response.data.data || [];
          if (results.length > 1) {
            const isSorted = results.every((v, i) =>
              i === 0 || (v.name && results[i - 1].name && v.name >= results[i - 1].name)
            );
            expect(isSorted).toBe(true);
          }
        }
      },
      {
        name: 'sort descending by name',
        path: '/voices?sort=-name',
        assert: (response) => {
          const results = response.data.data || [];
          if (results.length > 1) {
            const isSorted = results.every((v, i) =>
              i === 0 || (v.name && results[i - 1].name && v.name <= results[i - 1].name)
            );
            expect(isSorted).toBe(true);
          }
        }
      },
      {
        name: 'sort by created_at descending accepted',
        path: '/voices?sort=-created_at'
      },
      {
        name: 'multiple sort fields accepted',
        path: '/voices?sort=name,-created_at'
      },
      {
        name: 'field selection includes requested fields',
        path: '/voices?fields=id,name',
        assert: (response) => {
          const results = response.data.data || [];
          if (results.length > 0) {
            const firstVoice = results[0];
            expect(firstVoice).toHaveProperty('id');
            expect(firstVoice).toHaveProperty('name');
          }
        }
      },
      {
        name: 'field selection with timestamps includes timestamps',
        path: '/voices?fields=id,name,created_at,updated_at',
        assert: (response) => {
          const results = response.data.data || [];
          if (results.length > 0) {
            const firstVoice = results[0];
            expect(firstVoice).toHaveProperty('created_at');
            expect(firstVoice).toHaveProperty('updated_at');
          }
        }
      },
      {
        name: 'pagination with limit and offset',
        path: '/voices?limit=2&offset=1',
        assert: (response) => {
          const results = response.data.data || [];
          expect(results.length).toBeLessThanOrEqual(2);
        }
      },
      {
        name: 'complex combined query accepted',
        path: () => {
          const ids = queryTestIds.slice(2, 5).join(',');
          return `/voices?search=Voice&filter[id][in]=${ids}&sort=-name&fields=id,name&limit=10`;
        }
      },
      {
        name: 'filter with not operator is accepted',
        path: () => `/voices?filter[id][not]=${queryTestIds[0]}`
      }
    ];

    test.each(queryCases)('$name', async ({ path, assert }) => {
      const response = await runQuery(typeof path === 'function' ? path() : path);
      if (assert) {
        await assert(response);
      }
    });
  });

  describe('Voice Updates', () => {
    let testVoice;
    let duplicateVoice;

    beforeAll(async () => {
      testVoice = await createVoice('Update Test Voice');
      duplicateVoice = await createVoice('Duplicate Test Voice');
    });

    test('updates voice name', async () => {
      const updateResponse = await global.api.apiCall('PUT', `/voices/${testVoice.id}`, {
        name: 'Updated Voice Name'
      });

      expect(updateResponse.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/voices/${testVoice.id}`);
      expect(getResponse.data.name).toBe('Updated Voice Name');
    });

    test('rejects duplicate name on update', async () => {
      const duplicateResponse = await global.api.apiCall('PUT', `/voices/${testVoice.id}`, {
        name: duplicateVoice.name
      });

      expect(duplicateResponse.status).toBe(409);
    });

    test('rejects update of non-existent voice', async () => {
      const response = await global.api.apiCall('PUT', '/voices/99999', {
        name: 'Non-existent'
      });

      expect(response.status).toBe(404);
    });
  });

  describe('Voice Deletion', () => {
    test('deletes voice successfully', async () => {
      const voiceData = await createVoice('Delete Test Voice');
      expect(voiceData).not.toBeNull();

      const deleteResponse = await global.api.apiCall('DELETE', `/voices/${voiceData.id}`);
      expect(deleteResponse.status).toBe(204);

      // Verify deletion
      const getResponse = await global.api.apiCall('GET', `/voices/${voiceData.id}`);
      expect(getResponse.status).toBe(404);

      // Untrack since already deleted
      global.resources.untrack('voices', voiceData.id);
    });

    test('returns 404 for non-existent voice deletion', async () => {
      const response = await global.api.apiCall('DELETE', '/voices/99999');

      expect(response.status).toBe(404);
    });
  });

  describe('Voice with Associated Stories', () => {
    let stationId;
    let voiceData;

    beforeAll(async () => {
      const station = await global.helpers.createStation(
        global.resources,
        'VoiceTestStation',
        4,
        2.0
      );
      expect(station).not.toBeNull();
      stationId = station.id;

      // Create voice
      voiceData = await createVoice('Story Test Voice');
      expect(voiceData).not.toBeNull();
    });

    test('creates story with voice and handles voice deletion', async () => {
      const storyData = {
        title: 'Test Story with Voice',
        text: 'This is a test story.',
        voice_id: parseInt(voiceData.id, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 127,
        target_stations: [parseInt(stationId, 10)]
      };

      const storyResponse = await global.api.apiCall('POST', '/stories', storyData);
      expect(storyResponse.status).toBe(201);

      const storyId = global.api.parseJsonField(storyResponse.data, 'id');
      global.resources.track('stories', storyId);

      // Try to delete the voice (should fail with 409 or succeed with cascade)
      const deleteResponse = await global.api.apiCall('DELETE', `/voices/${voiceData.id}`);

      // Either 409 (protected) or 204 (cascade delete) is valid
      expect([204, 409]).toContain(deleteResponse.status);
    });
  });
});
