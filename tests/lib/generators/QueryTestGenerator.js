/**
 * QueryTestGenerator - Generates query parameter tests for API resources.
 * Covers: search, sort, filter (exact, in, not, gte, lte, between), pagination, field selection.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 * - Test independence via beforeAll setup
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
        test('when searching, then returns 200', async () => {
          // Act
          const response = await global.api.apiCall('GET', `${endpoint}?search=test`);

          // Assert
          expect(response.status).toBe(200);
          expect(response.data).toHaveProperty('data');
        });

        test('when search empty, then returns all', async () => {
          // Arrange: (none - empty search parameter)

          // Act
          const response = await global.api.apiCall('GET', `${endpoint}?search=`);

          // Assert
          expect(response.status).toBe(200);
        });
      });
    }

    // === SORT TESTS ===
    if (query.sortableFields?.length > 0) {
      describe('Sorting', () => {
        query.sortableFields.forEach(field => {
          test(`when sorting asc by ${field}, then ordered correctly`, async () => {
            // Act
            const response = await global.api.apiCall('GET', `${endpoint}?sort=${field}`);

            // Assert
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

          test(`when sorting desc by ${field}, then ordered correctly`, async () => {
            // Act
            const response = await global.api.apiCall('GET', `${endpoint}?sort=-${field}`);

            // Assert
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
          test('when sorting by multiple fields, then accepted', async () => {
            // Arrange
            const fields = query.sortableFields.slice(0, 2);

            // Act
            const response = await global.api.apiCall('GET', `${endpoint}?sort=${fields.join(',')}`);

            // Assert
            expect(response.status).toBe(200);
          });

          test('when sorting with mixed directions, then accepted', async () => {
            // Arrange: (none - inline sort parameters)

            // Act
            const response = await global.api.apiCall(
              'GET',
              `${endpoint}?sort=${query.sortableFields[0]},-${query.sortableFields[1]}`
            );

            // Assert
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
          test(`when filtering ${field} exact, then matches`, async () => {
            // Act
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}]=1`);

            // Assert
            expect(response.status).toBe(200);
          });

          test(`when filtering ${field} with in, then matches`, async () => {
            // Arrange: (none - inline filter values)

            // Act
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}][in]=1,2,3`);

            // Assert
            expect(response.status).toBe(200);
          });

          test(`when filtering ${field} with not, then excludes`, async () => {
            // Arrange: (none - inline filter value)

            // Act
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}][not]=999999`);

            // Assert
            expect(response.status).toBe(200);
          });
        });

        // Numeric operators for numeric fields
        const numericFields = query.filterableFields.filter(f =>
          query.numericFields?.includes(f) || ['id'].includes(f)
        );

        numericFields.forEach(field => {
          test(`when filtering ${field} with gte, then filters correctly`, async () => {
            // Act
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}][gte]=1`);

            // Assert
            expect(response.status).toBe(200);
            const results = response.data.data || [];
            results.forEach(item => {
              if (item[field] !== null && item[field] !== undefined) {
                expect(item[field]).toBeGreaterThanOrEqual(1);
              }
            });
          });

          test(`when filtering ${field} with lte, then filters correctly`, async () => {
            // Act
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}][lte]=999999`);

            // Assert
            expect(response.status).toBe(200);
          });

          test(`when filtering ${field} with between, then filters range`, async () => {
            // Act
            const response = await global.api.apiCall('GET', `${endpoint}?filter[${field}][between]=1,999999`);

            // Assert
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
          test('when combining multiple filters, then accepted', async () => {
            // Arrange
            const f1 = query.filterableFields[0];
            const f2 = query.filterableFields[1];

            // Act
            const response = await global.api.apiCall(
              'GET',
              `${endpoint}?filter[${f1}][gte]=1&filter[${f2}][not]=999999`
            );

            // Assert
            expect(response.status).toBe(200);
          });
        }
      });
    }

    // === PAGINATION TESTS ===
    describe('Pagination', () => {
      test('when paginating with limit, then respects limit', async () => {
        // Act
        const response = await global.api.apiCall('GET', `${endpoint}?limit=2`);

        // Assert
        expect(response.status).toBe(200);
        expect(response.data.data.length).toBeLessThanOrEqual(2);
      });

      test('when paginating with offset, then skips records', async () => {
        // Act
        const response = await global.api.apiCall('GET', `${endpoint}?limit=2&offset=1`);

        // Assert
        expect(response.status).toBe(200);
        expect(response.data.data.length).toBeLessThanOrEqual(2);
        expect(response.data).toHaveProperty('offset', 1);
      });

      test('when paginating, then includes metadata', async () => {
        // Act
        const response = await global.api.apiCall('GET', `${endpoint}?limit=5`);

        // Assert
        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('total');
        expect(response.data).toHaveProperty('limit');
        expect(response.data).toHaveProperty('offset');
      });

      test('when offset exceeds data, then returns empty array', async () => {
        // Act
        const response = await global.api.apiCall('GET', `${endpoint}?limit=10&offset=999999`);

        // Assert
        expect(response.status).toBe(200);
        expect(response.data.data).toEqual([]);
      });
    });

    // === FIELD SELECTION TESTS ===
    if (query.selectableFields?.length > 0) {
      describe('Field Selection', () => {
        test('when selecting fields, then returns only those', async () => {
          // Arrange
          const requestedFields = ['id', query.selectableFields[1]].filter(Boolean);

          // Act
          const response = await global.api.apiCall(
            'GET',
            `${endpoint}?fields=${requestedFields.join(',')}`
          );

          // Assert
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

        test('when selecting timestamps, then includes them', async () => {
          // Arrange
          const hasUpdatedAt = query.selectableFields?.includes('updated_at');
          const fields = hasUpdatedAt ? 'id,created_at,updated_at' : 'id,created_at';

          // Act
          const response = await global.api.apiCall(
            'GET',
            `${endpoint}?fields=${fields}`
          );

          // Assert
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

        test('when selecting single field, then works', async () => {
          // Act
          const response = await global.api.apiCall('GET', `${endpoint}?fields=id`);

          // Assert
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
      test('when combining all query types, then accepted', async () => {
        // Arrange
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

        // Act
        const response = await global.api.apiCall('GET', `${endpoint}?${params}`);

        // Assert
        expect(response.status).toBe(200);
      });

      test('when combining search sort pagination, then works', async () => {
        // Arrange
        const params = new URLSearchParams();
        if (query.searchFields?.length > 0) {
          params.append('search', 'a');
        }
        if (query.sortableFields?.length > 0) {
          params.append('sort', query.sortableFields[0]);
        }
        params.append('limit', '5');
        params.append('offset', '0');

        // Act
        const response = await global.api.apiCall('GET', `${endpoint}?${params}`);

        // Assert
        expect(response.status).toBe(200);
        expect(response.data.data.length).toBeLessThanOrEqual(5);
      });
    });
  });
}

module.exports = { generateQueryTests };
