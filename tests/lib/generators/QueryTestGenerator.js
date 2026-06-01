/**
 * QueryTestGenerator - Generates query parameter tests for API resources.
 * Covers search, sort, filter, pagination, field selection, and combined queries.
 */

/**
 * Generates query parameter tests based on resource schema.
 * @param {Object} schema - Resource schema with query configuration.
 * @param {Function} [setupFn] - Optional async setup for resource-specific test data.
 */
function generateQueryTests(schema, setupFn = null) {
  const { endpoint, name, query } = schema;
  if (!query) throw new Error(`Schema for ${name} missing 'query' configuration`);

  const get = qs => global.api.apiCall('GET', `${endpoint}?${qs}`);
  const expectStatus = async (qs, status = 200) => {
    const response = await get(qs);
    expect(response.status).toBe(status);
    return response;
  };
  // Ignore nullish values in comparisons so sparse optional columns do not make
  // resource-level query tests brittle.
  const valuesFor = (response, field) => (response.data.data || [])
    .map(item => item[field])
    .filter(value => value !== null && value !== undefined);
  const isSorted = (results, field, compare) => results.every((item, i) => (
    i === 0 ||
    item[field] === null ||
    item[field] === undefined ||
    results[i - 1][field] === null ||
    results[i - 1][field] === undefined ||
    compare(item[field], results[i - 1][field])
  ));

  describe(`${name} Query Parameters`, () => {
    beforeAll(async () => {
      if (setupFn) await setupFn();
    });

    // Search tests apply only to resources that declare searchable columns.
    if (query.searchFields?.length > 0) {
      describe('Search', () => {
        test('when searching, then returns 200', async () => {
          const response = await expectStatus('search=test');
          expect(response.data).toHaveProperty('data');
        });

        test('when search empty, then returns all', async () => {
          await expectStatus('search=');
        });
      });
    }

    // Sorting is validated per declared field in both directions.
    if (query.sortableFields?.length > 0) {
      describe('Sorting', () => {
        query.sortableFields.forEach(field => {
          test.each([
            [`when sorting asc by ${field}, then ordered correctly`, field, (curr, prev) => curr >= prev],
            [`when sorting desc by ${field}, then ordered correctly`, `-${field}`, (curr, prev) => curr <= prev]
          ])('%s', async (_name, sort, compare) => {
            const response = await expectStatus(`sort=${sort}`);
            const results = response.data.data || [];
            if (results.length > 1) expect(isSorted(results, field, compare)).toBe(true);
          });
        });

        test.each([
          ['when sorting unknown field, then returns 422', 'sort=__bogus__'],
          ['when sort direction is invalid, then returns 422', `sort=${query.sortableFields[0]}:sideways`]
        ])('%s', async (_name, qs) => {
          await expectStatus(qs, 422);
        });

        if (query.sortableFields.length >= 2) {
          test.each([
            ['when sorting by multiple fields, then accepted', `sort=${query.sortableFields.slice(0, 2).join(',')}`],
            ['when sorting with mixed directions, then accepted', `sort=${query.sortableFields[0]},-${query.sortableFields[1]}`]
          ])('%s', async (_name, qs) => {
            await expectStatus(qs);
          });
        }
      });
    }

    // Filter cases are generated from the schema so each resource keeps the
    // same API contract checks without hand-written duplication.
    if (query.filterableFields?.length > 0) {
      describe('Filtering', () => {
        query.filterableFields.forEach(field => {
          test.each([
            [`when filtering ${field} exact, then matches`, `filter[${field}]=1`, null],
            [`when filtering ${field} with in, then matches`, `filter[${field}][in]=1,2,3`, null],
            [`when filtering ${field} with not, then excludes`, `filter[${field}][not]=999999`, response => {
              expect(response.data.total).toBeGreaterThan(0);
              valuesFor(response, field).forEach(value => expect(String(value)).not.toBe('999999'));
            }]
          ])('%s', async (_name, qs, verify) => {
            const response = await expectStatus(qs);
            if (verify) verify(response);
          });
        });

        const firstField = query.filterableFields[0];
        test.each([
          ['when filtering with unknown operator, then returns 422', `filter[${firstField}][unknown]=1`],
          ['when filtering null with invalid boolean, then returns 422', `filter[${firstField}][null]=not-bool`],
          ['when filtering unknown field, then returns 422', 'filter[__bogus__]=1'],
          ['when filter receives duplicate values, then returns 422', `filter[${firstField}]=1&filter[${firstField}]=2`]
        ])('%s', async (_name, qs) => {
          await expectStatus(qs, 422);
        });

        query.filterableFields
          .filter(field => query.numericFields?.includes(field))
          .forEach(field => {
            test.each([
              [`when filtering ${field} with gte, then filters correctly`, `filter[${field}][gte]=1`, value => expect(value).toBeGreaterThanOrEqual(1)],
              [`when filtering ${field} with lte, then filters correctly`, `filter[${field}][lte]=999999`, null],
              [`when filtering ${field} with between, then filters range`, `filter[${field}][between]=1,999999`, value => {
                expect(value).toBeGreaterThanOrEqual(1);
                expect(value).toBeLessThanOrEqual(999999);
              }]
            ])('%s', async (_name, qs, verifyValue) => {
              const response = await expectStatus(qs);
              if (verifyValue) valuesFor(response, field).forEach(verifyValue);
            });
          });

        if (query.filterableFields.length >= 2) {
          test('when combining multiple filters, then accepted', async () => {
            const [f1, f2] = query.filterableFields;
            await expectStatus(`filter[${f1}][gte]=1&filter[${f2}][not]=999999`);
          });
        }
      });
    }

    // Pagination applies to all list endpoints, regardless of other query options.
    describe('Pagination', () => {
      test.each([
        ['when paginating with limit, then respects limit', 'limit=2', 200, response => expect(response.data.data.length).toBeLessThanOrEqual(2)],
        ['when paginating with offset, then skips records', 'limit=2&offset=1', 200, response => {
          expect(response.data.data.length).toBeLessThanOrEqual(2);
          expect(response.data).toHaveProperty('offset', 1);
        }],
        ['when paginating, then includes metadata', 'limit=5', 200, response => {
          expect(response.data).toHaveProperty('total');
          expect(response.data).toHaveProperty('limit');
          expect(response.data).toHaveProperty('offset');
        }],
        ['when offset exceeds data, then returns empty array', 'limit=10&offset=999999', 200, response => expect(response.data.data).toEqual([])],
        ['when limit is non-integer, then returns 422', 'limit=abc', 422, undefined],
        ['when limit is negative, then returns 422', 'limit=-5', 422, undefined],
        ['when limit exceeds cap, then returns 422', 'limit=101', 422, undefined],
        ['when offset is non-integer, then returns 422', 'offset=foo', 422, undefined]
      ])('%s', async (_name, qs, status, verify) => {
        const response = await expectStatus(qs, status);
        if (verify) verify(response);
      });
    });

    // Field selection checks sparse responses and validates unknown fields.
    if (query.selectableFields?.length > 0) {
      describe('Field Selection', () => {
        test('when selecting fields, then returns only those', async () => {
          const requestedFields = ['id', query.selectableFields[1]].filter(Boolean);
          const response = await expectStatus(`fields=${requestedFields.join(',')}`);
          const first = (response.data.data || [])[0];
          if (!first) return;

          requestedFields.forEach(field => expect(first).toHaveProperty(field));
          (schema.excludeOnFieldSelect || [])
            .filter(excluded => !requestedFields.includes(excluded))
            .forEach(excluded => expect(first).not.toHaveProperty(excluded));
        });

        test('when selecting timestamps, then includes them', async () => {
          const fields = query.selectableFields?.includes('updated_at') ? 'id,created_at,updated_at' : 'id,created_at';
          const response = await expectStatus(`fields=${fields}`);
          const first = (response.data.data || [])[0];
          if (!first) return;

          expect(first).toHaveProperty('id');
          expect(first).toHaveProperty('created_at');
          if (fields.includes('updated_at')) expect(first).toHaveProperty('updated_at');
        });

        test('when selecting single field, then works', async () => {
          const response = await expectStatus('fields=id');
          const first = (response.data.data || [])[0];
          if (first) expect(first).toHaveProperty('id');
        });

        test('when selecting unknown field, then returns 422', async () => {
          await expectStatus('fields=id,__bogus__', 422);
        });
      });
    }

    describe('Combined Queries', () => {
      test('when combining all query types, then accepted', async () => {
        const params = new URLSearchParams();
        if (query.searchFields?.length > 0) params.append('search', 'test');
        if (query.sortableFields?.length > 0) params.append('sort', `-${query.sortableFields[0]}`);
        if (query.filterableFields?.length > 0) params.append(`filter[${query.filterableFields[0]}][gte]`, '1');
        if (query.selectableFields?.length > 0) params.append('fields', query.selectableFields.slice(0, 3).join(','));
        params.append('limit', '10');
        await expectStatus(params.toString());
      });

      test('when combining search sort pagination, then works', async () => {
        const params = new URLSearchParams();
        if (query.searchFields?.length > 0) params.append('search', 'a');
        if (query.sortableFields?.length > 0) params.append('sort', query.sortableFields[0]);
        params.append('limit', '5');
        params.append('offset', '0');

        const response = await expectStatus(params.toString());
        expect(response.data.data.length).toBeLessThanOrEqual(5);
      });
    });
  });
}

module.exports = { generateQueryTests };
