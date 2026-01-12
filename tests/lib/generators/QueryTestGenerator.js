/**
 * QueryTestGenerator - Generates query parameter tests for API resources.
 * Covers: search, sort, filter (exact, in, not, gte, lte, between), pagination, field selection.
 */

/**
 * Generates query parameter tests based on resource schema.
 * @param {Object} schema - Resource schema with query configuration
 * @param {Function} [setupFn] - Optional async function to create test data, returns array of IDs
 */
function generateQueryTests(schema, setupFn = null) {
  const { endpoint, name, query } = schema;

  if (!query) {
    throw new Error(`Schema for ${name} missing 'query' configuration`);
  }

  describe(`${name} Query Parameters`, () => {
    let testIds = [];

    beforeAll(async () => {
      if (setupFn) {
        testIds = await setupFn();
      }
    });

    // === SEARCH TESTS ===
    if (query.searchFields?.length > 0) {
      describe('Search', () => {
        test('search parameter returns 200', async () => {
          const response = await global.api.apiCall('GET', `${endpoint}?search=test`);
          expect(response.status).toBe(200);
          expect(response.data).toHaveProperty('data');
        });

        test('empty search returns all results', async () => {
          const response = await global.api.apiCall('GET', `${endpoint}?search=`);
          expect(response.status).toBe(200);
        });
      });
    }

    // === SORT TESTS ===
    if (query.sortableFields?.length > 0) {
      describe('Sorting', () => {
        query.sortableFields.forEach(field => {
          test(`sorts ascending by ${field}`, async () => {
            const response = await global.api.apiCall('GET', `${endpoint}?sort=${field}`);
            expect(response.status).toBe(200);

            const results = response.data.data || [];
            if (results.length > 1) {
              const isSorted = results.every((item, i) => {
                if (i === 0) return true;
                const curr = item[field];
                const prev = results[i - 1][field];
                if (curr === null || curr === undefined) return true;
                if (prev === null || prev === undefined) return true;
                return curr >= prev;
              });
              expect(isSorted).toBe(true);
            }
          });

          test(`sorts descending by ${field}`, async () => {
            const response = await global.api.apiCall('GET', `${endpoint}?sort=-${field}`);
            expect(response.status).toBe(200);

            const results = response.data.data || [];
            if (results.length > 1) {
              const isSorted = results.every((item, i) => {
                if (i === 0) return true;
                const curr = item[field];
                const prev = results[i - 1][field];
                if (curr === null || curr === undefined) return true;
                if (prev === null || prev === undefined) return true;
                return curr <= prev;
              });
              expect(isSorted).toBe(true);
            }
          });
        });

        if (query.sortableFields.length >= 2) {
          test('accepts multiple sort fields', async () => {
            const fields = query.sortableFields.slice(0, 2);
            const response = await global.api.apiCall('GET', `${endpoint}?sort=${fields.join(',')}`);
            expect(response.status).toBe(200);
          });

          test('accepts mixed sort directions', async () => {
            const response = await global.api.apiCall(
              'GET',
              `${endpoint}?sort=${query.sortableFields[0]},-${query.sortableFields[1]}`
            );
            expect(response.status).toBe(200);
          });
        }
      });
    }

    // === FILTER TESTS ===
    if (query.filterableFields?.length > 0) {
      describe('Filtering', () => {
        // Basic filter operations for all fields
        query.filterableFields.forEach(field => {
          test(`filters by ${field} with exact match`, async () => {
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}]=1`);
            expect(response.status).toBe(200);
          });

          test(`filters by ${field} with in operator`, async () => {
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}][in]=1,2,3`);
            expect(response.status).toBe(200);
          });

          test(`filters by ${field} with not operator`, async () => {
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}][not]=999999`);
            expect(response.status).toBe(200);
          });
        });

        // Numeric operators for numeric fields
        const numericFields = query.filterableFields.filter(f =>
          query.numericFields?.includes(f) || ['id'].includes(f)
        );

        numericFields.forEach(field => {
          test(`filters by ${field} with gte operator`, async () => {
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}][gte]=1`);
            expect(response.status).toBe(200);

            const results = response.data.data || [];
            results.forEach(item => {
              if (item[field] !== null && item[field] !== undefined) {
                expect(item[field]).toBeGreaterThanOrEqual(1);
              }
            });
          });

          test(`filters by ${field} with lte operator`, async () => {
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}][lte]=999999`);
            expect(response.status).toBe(200);
          });

          test(`filters by ${field} with between operator`, async () => {
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}][between]=1,999999`);
            expect(response.status).toBe(200);

            const results = response.data.data || [];
            results.forEach(item => {
              if (item[field] !== null && item[field] !== undefined) {
                expect(item[field]).toBeGreaterThanOrEqual(1);
                expect(item[field]).toBeLessThanOrEqual(999999);
              }
            });
          });
        });

        // Test combining multiple filters
        if (query.filterableFields.length >= 2) {
          test('accepts multiple filters combined', async () => {
            const f1 = query.filterableFields[0];
            const f2 = query.filterableFields[1];
            const response = await global.api.apiCall(
              'GET',
              `${endpoint}?filter[${f1}][gte]=1&filter[${f2}][not]=999999`
            );
            expect(response.status).toBe(200);
          });
        }
      });
    }

    // === PAGINATION TESTS ===
    describe('Pagination', () => {
      test('pagination with limit', async () => {
        const response = await global.api.apiCall('GET', `${endpoint}?limit=2`);
        expect(response.status).toBe(200);
        expect(response.data.data.length).toBeLessThanOrEqual(2);
      });

      test('pagination with limit and offset', async () => {
        const response = await global.api.apiCall('GET', `${endpoint}?limit=2&offset=1`);
        expect(response.status).toBe(200);
        expect(response.data.data.length).toBeLessThanOrEqual(2);
        expect(response.data).toHaveProperty('offset', 1);
      });

      test('response includes pagination metadata', async () => {
        const response = await global.api.apiCall('GET', `${endpoint}?limit=5`);
        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('total');
        expect(response.data).toHaveProperty('limit');
        expect(response.data).toHaveProperty('offset');
      });

      test('large offset returns empty data array', async () => {
        const response = await global.api.apiCall('GET', `${endpoint}?limit=10&offset=999999`);
        expect(response.status).toBe(200);
        expect(response.data.data).toEqual([]);
      });
    });

    // === FIELD SELECTION TESTS ===
    if (query.selectableFields?.length > 0) {
      describe('Field Selection', () => {
        test('returns only requested fields', async () => {
          const requestedFields = ['id', query.selectableFields[1]].filter(Boolean);
          const response = await global.api.apiCall(
            'GET',
            `${endpoint}?fields=${requestedFields.join(',')}`
          );
          expect(response.status).toBe(200);

          const results = response.data.data || [];
          if (results.length > 0) {
            requestedFields.forEach(field => {
              expect(results[0]).toHaveProperty(field);
            });

            // Verify excluded fields are not present
            if (schema.excludeOnFieldSelect?.length > 0) {
              schema.excludeOnFieldSelect.forEach(excluded => {
                if (!requestedFields.includes(excluded)) {
                  expect(results[0]).not.toHaveProperty(excluded);
                }
              });
            }
          }
        });

        test('field selection with timestamps', async () => {
          // Only include updated_at if it's in selectableFields
          const hasUpdatedAt = query.selectableFields?.includes('updated_at');
          const fields = hasUpdatedAt ? 'id,created_at,updated_at' : 'id,created_at';

          const response = await global.api.apiCall(
            'GET',
            `${endpoint}?fields=${fields}`
          );
          expect(response.status).toBe(200);

          const results = response.data.data || [];
          if (results.length > 0) {
            expect(results[0]).toHaveProperty('id');
            expect(results[0]).toHaveProperty('created_at');
            if (hasUpdatedAt) {
              expect(results[0]).toHaveProperty('updated_at');
            }
          }
        });

        test('selecting single field works', async () => {
          const response = await global.api.apiCall('GET', `${endpoint}?fields=id`);
          expect(response.status).toBe(200);

          const results = response.data.data || [];
          if (results.length > 0) {
            expect(results[0]).toHaveProperty('id');
          }
        });
      });
    }

    // === COMBINED QUERY TESTS ===
    describe('Combined Queries', () => {
      test('complex combined query accepted', async () => {
        const params = new URLSearchParams();

        if (query.searchFields?.length > 0) {
          params.append('search', 'test');
        }
        if (query.sortableFields?.length > 0) {
          params.append('sort', `-${query.sortableFields[0]}`);
        }
        if (query.filterableFields?.length > 0) {
          params.append(`filter[${query.filterableFields[0]}][gte]`, '1');
        }
        if (query.selectableFields?.length > 0) {
          params.append('fields', query.selectableFields.slice(0, 3).join(','));
        }
        params.append('limit', '10');

        const response = await global.api.apiCall('GET', `${endpoint}?${params}`);
        expect(response.status).toBe(200);
      });

      test('search + sort + pagination combined', async () => {
        const params = new URLSearchParams();

        if (query.searchFields?.length > 0) {
          params.append('search', 'a');
        }
        if (query.sortableFields?.length > 0) {
          params.append('sort', query.sortableFields[0]);
        }
        params.append('limit', '5');
        params.append('offset', '0');

        const response = await global.api.apiCall('GET', `${endpoint}?${params}`);
        expect(response.status).toBe(200);
        expect(response.data.data.length).toBeLessThanOrEqual(5);
      });
    });
  });
}

module.exports = { generateQueryTests };
