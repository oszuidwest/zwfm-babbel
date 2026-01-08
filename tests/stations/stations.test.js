/**
 * Babbel stations tests.
 * Tests station management functionality including CRUD operations and validation.
 */

describe('Stations', () => {
  // Helper to track created stations for this test suite
  const createdStationIds = [];

  const createStation = async (name, maxStories = 5, pauseSeconds = 2.0) => {
    const station = await global.helpers.createStation(
      global.resources,
      name,
      maxStories,
      pauseSeconds
    );
    if (station?.id) {
      createdStationIds.push(station.id);
    }
    return station;
  };

  describe('Station Creation', () => {
    const testStations = [
      { name: 'CRUD Test FM', max: 5, pause: 2.0 },
      { name: 'Another Test Station', max: 3, pause: 1.5 },
      { name: 'Validation Station', max: 10, pause: 3.0 }
    ];

    test.each(testStations)(
      'creates station: $name',
      async ({ name, max, pause }) => {
        const station = await createStation(name, max, pause);

        expect(station).not.toBeNull();
        expect(station.id).toBeDefined();

        // Verify station data
        const verifyResponse = await global.api.apiCall('GET', `/stations/${station.id}`);
        expect(verifyResponse.status).toBe(200);
        expect(verifyResponse.data.name).toBe(station.name);
        expect(verifyResponse.data).toHaveProperty('created_at');
        expect(verifyResponse.data).toHaveProperty('updated_at');
      }
    );
  });

  describe('Station Reading', () => {
    test('lists all stations', async () => {
      const response = await global.api.apiCall('GET', '/stations');

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
      expect(Array.isArray(response.data.data)).toBe(true);
    });

    test('station list has correct structure', async () => {
      const response = await global.api.apiCall('GET', '/stations');

      expect(response.status).toBe(200);
      if (response.data.data.length > 0) {
        const firstStation = response.data.data[0];
        expect(firstStation).toHaveProperty('id');
        expect(firstStation).toHaveProperty('name');
        expect(firstStation).toHaveProperty('max_stories_per_block');
        expect(firstStation).toHaveProperty('pause_seconds');
      }
    });

    test('retrieves individual station', async () => {
      if (createdStationIds.length === 0) {
        await createStation('ReadTest');
      }

      const stationId = createdStationIds[0];
      const response = await global.api.apiCall('GET', `/stations/${stationId}`);

      expect(response.status).toBe(200);
      expect(String(response.data.id)).toBe(String(stationId));
      expect(response.data).toHaveProperty('name');
    });
  });

  describe('Modern Query Parameters', () => {
    let queryTestIds = [];

    beforeAll(async () => {
      const testStations = [
        { name: 'Alpha Radio', max: 3, pause: 1.0 },
        { name: 'Beta FM', max: 5, pause: 2.0 },
        { name: 'Gamma Station', max: 7, pause: 3.0 },
        { name: 'Delta Broadcasting', max: 10, pause: 2.5 },
        { name: 'Echo Radio Network', max: 5, pause: 1.5 }
      ];

      for (const station of testStations) {
        const created = await createStation(station.name, station.max, station.pause);
        if (created) {
          queryTestIds.push(created.id);
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
        path: '/stations?search=Radio',
        assert: (response) => {
          const results = response.data.data || [];
          const radioStations = results.filter(s => s.name && s.name.includes('Radio'));
          expect(radioStations.length).toBeGreaterThan(0);
        }
      },
      {
        name: 'filter with exact match',
        path: '/stations?filter[max_stories_per_block]=5',
        assert: (response) => {
          const results = response.data.data || [];
          const exactMatches = results.filter(s => s.max_stories_per_block === 5);
          expect(exactMatches.length).toBeGreaterThan(0);
        }
      },
      {
        name: 'filter with gte operator',
        path: '/stations?filter[max_stories_per_block][gte]=7',
        assert: (response) => {
          const results = response.data.data || [];
          results.forEach(s => {
            expect(s.max_stories_per_block).toBeGreaterThanOrEqual(7);
          });
        }
      },
      {
        name: 'multiple filters combined',
        path: '/stations?filter[max_stories_per_block][gte]=5&filter[pause_seconds][lte]=2.0'
      },
      {
        name: 'sort ascending by name',
        path: '/stations?sort=name',
        assert: (response) => {
          const results = response.data.data || [];
          if (results.length > 1) {
            const isSorted = results.every((s, i) =>
              i === 0 || s.name >= results[i - 1].name
            );
            expect(isSorted).toBe(true);
          }
        }
      },
      {
        name: 'sort descending by max_stories_per_block',
        path: '/stations?sort=-max_stories_per_block',
        assert: (response) => {
          const results = response.data.data || [];
          if (results.length > 1) {
            const isSorted = results.every((s, i) =>
              i === 0 || s.max_stories_per_block <= results[i - 1].max_stories_per_block
            );
            expect(isSorted).toBe(true);
          }
        }
      },
      {
        name: 'multiple sort fields accepted',
        path: '/stations?sort=max_stories_per_block,-name'
      },
      {
        name: 'field selection returns only requested fields',
        path: '/stations?fields=id,name',
        assert: (response) => {
          const results = response.data.data || [];
          if (results.length > 0) {
            const firstStation = results[0];
            expect(firstStation).toHaveProperty('id');
            expect(firstStation).toHaveProperty('name');
            expect(firstStation).not.toHaveProperty('max_stories_per_block');
            expect(firstStation).not.toHaveProperty('pause_seconds');
          }
        }
      },
      {
        name: 'pagination with limit and offset',
        path: '/stations?limit=2&offset=1',
        assert: (response) => {
          const results = response.data.data || [];
          expect(results.length).toBeLessThanOrEqual(2);
        }
      },
      {
        name: 'complex combined query accepted',
        path: '/stations?search=Station&filter[max_stories_per_block][gte]=5&sort=-pause_seconds&fields=id,name,pause_seconds&limit=10'
      },
      {
        name: 'filter with in operator',
        path: () => {
          const ids = queryTestIds.slice(0, 3).join(',');
          return `/stations?filter[id][in]=${ids}`;
        }
      },
      {
        name: 'filter with between operator',
        path: '/stations?filter[pause_seconds][between]=1.5,2.5',
        assert: (response) => {
          const results = response.data.data || [];
          results.forEach(s => {
            expect(s.pause_seconds).toBeGreaterThanOrEqual(1.5);
            expect(s.pause_seconds).toBeLessThanOrEqual(2.5);
          });
        }
      }
    ];

    test.each(queryCases)('$name', async ({ path, assert }) => {
      const response = await runQuery(typeof path === 'function' ? path() : path);
      if (assert) {
        await assert(response);
      }
    });
  });

  describe('Station Updates', () => {
    let updateStationId;

    beforeAll(async () => {
      const station = await createStation('Update Test');
      updateStationId = station?.id;
    });

    test('updates station with PUT', async () => {
      expect(updateStationId).toBeDefined();

      const updateData = {
        name: 'Updated Test Station',
        max_stories_per_block: 7,
        pause_seconds: 2.5
      };

      const response = await global.api.apiCall('PUT', `/stations/${updateStationId}`, updateData);
      expect(response.status).toBe(200);

      // Verify update
      const verifyResponse = await global.api.apiCall('GET', `/stations/${updateStationId}`);
      expect(verifyResponse.status).toBe(200);
      expect(verifyResponse.data.name).toBe('Updated Test Station');
      expect(verifyResponse.data.max_stories_per_block).toBe(7);
      expect(verifyResponse.data.pause_seconds).toBe(2.5);
    });

    test('second update works', async () => {
      const updateData = {
        name: 'Second Update Station',
        max_stories_per_block: 8,
        pause_seconds: 3.0
      };

      const response = await global.api.apiCall('PUT', `/stations/${updateStationId}`, updateData);
      expect(response.status).toBe(200);

      const verifyResponse = await global.api.apiCall('GET', `/stations/${updateStationId}`);
      expect(verifyResponse.data.name).toBe('Second Update Station');
      expect(verifyResponse.data.max_stories_per_block).toBe(8);
    });
  });

  describe('Station Validation', () => {
    const validationTests = [
      { data: {}, description: 'Missing required fields' },
      { data: { name: '' }, description: 'Empty name' },
      { data: { name: 'Test', max_stories_per_block: -1 }, description: 'Negative max stories' },
      { data: { name: 'Test', max_stories_per_block: 0 }, description: 'Zero max stories' },
      { data: { name: 'Test', max_stories_per_block: 5, pause_seconds: -1 }, description: 'Negative pause seconds' },
      { data: { name: 'Test', max_stories_per_block: 5, pause_seconds: 'invalid' }, description: 'Invalid pause seconds type' }
    ];

    test.each(validationTests)(
      'rejects: $description',
      async ({ data }) => {
        const response = await global.api.apiCall('POST', '/stations', data);

        expect(response.status).toBeHttpError();
      }
    );
  });

  describe('Duplicate Station Names', () => {
    test('rejects duplicate station name', async () => {
      const station = await createStation('Unique Test Station');
      expect(station).not.toBeNull();

      // Try to create duplicate
      const response = await global.api.apiCall('POST', '/stations', {
        name: station.name,
        max_stories_per_block: 3,
        pause_seconds: 1.5
      });

      expect(response.status).toBeHttpError();
    });
  });

  describe('Station Deletion', () => {
    test('deletes station successfully', async () => {
      const station = await createStation('Delete Test');
      expect(station).not.toBeNull();

      const response = await global.api.apiCall('DELETE', `/stations/${station.id}`);
      expect(response.status).toBe(204);

      // Verify deletion
      const verifyResponse = await global.api.apiCall('GET', `/stations/${station.id}`);
      expect(verifyResponse.status).toBe(404);

      // Untrack since deleted
      global.resources.untrack('stations', station.id);
    });
  });
});
