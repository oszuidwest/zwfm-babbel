const { declaresQueryParameter, getFilterContracts, filterExamples, validFilterCases, invalidFilterCases } = require('../QueryFilterContract');
const { createMySQLExecutor } = require('../MySQLHelper');

/**
 * Generates list-query contract tests from a resource schema.
 * @param {Object} schema
 * @param {Function|null} [setupFn]
 */
function generateQueryTests(schema, setupFn = null) {
  const { endpoint, name, query } = schema;
  if (!query) throw new Error(`Schema for ${name} missing 'query' configuration`);
  const filters = getFilterContracts(endpoint);

  const get = qs => global.api.apiCall('GET', `${endpoint}?${qs}`);
  const expectStatus = async (qs, status = 200) => {
    const response = await get(qs);
    expect(response.status).toBe(status);
    return response;
  };
  // Optional fields may be absent from the fixtures.
  const expectItemsWith = (response, field) => {
    const items = (response.data.data || []).filter(item => item[field] !== null && item[field] !== undefined);
    expect(items.length).toBeGreaterThan(0);
    return items;
  };
  const expectValuesFor = (response, field) => expectItemsWith(response, field).map(item => item[field]);
  const mysql = createMySQLExecutor();
  const table = endpoint.slice(1).replaceAll('-', '_');
  // Returns numeric sort keys. Strings follow the column collation, which
  // JavaScript cannot reproduce exactly, so MySQL ranks them; equal values
  // share a rank and may come back in any order. Dates compare as instants.
  // Assumes each field is a same-named column of the table named after the
  // endpoint.
  const sortKeys = (response, field) => {
    const items = expectItemsWith(response, field);
    const { value } = filters[field];
    if (value.format === 'date' || value.format === 'date-time') return items.map(item => Date.parse(item[field]));
    if (value.type === 'string') {
      const ranks = mysql.rankByColumn(table, field, items.map(item => item.id));
      return items.map(item => ranks.get(item.id));
    }
    return items.map(item => item[field]);
  };

  describe(`${name} Query Parameters`, () => {
    beforeAll(async () => {
      if (setupFn) await setupFn();
    });

    if (query.searchFields?.length > 0) {
      describe('Search', () => {
        test('when searching, then returns 200', async () => {
          expect.hasAssertions();
          const response = await expectStatus('search=test');
          expect(response.data).toHaveProperty('data');
        });

        test('when search empty, then returns all', async () => {
          expect.hasAssertions();
          await expectStatus('search=');
        });
      });
    }

    if (query.sortableFields?.length > 0) {
      describe('Sorting', () => {
        query.sortableFields.forEach(field => {
          if (!filters[field]) throw new Error(`${name} sortableFields: ${field} is not a documented filter for ${endpoint}`);
          test.each([
            [`when sorting asc by ${field}, then ordered correctly`, field, 1],
            [`when sorting desc by ${field}, then ordered correctly`, `-${field}`, -1]
          ])('%s', async (_name, sort, direction) => {
            expect.hasAssertions();
            const response = await expectStatus(`sort=${sort}`);
            const keys = sortKeys(response, field);
            // A missing rank or unparsable date would sort to the end unnoticed.
            expect(keys.every(Number.isFinite)).toBe(true);
            expect(keys).toEqual([...keys].sort((a, b) => direction * (a - b)));
          });
        });

        test.each([
          ['when sorting unknown field, then returns a sort 422', 'sort=__bogus__'],
          ['when sort direction is invalid, then returns a sort 422', `sort=${query.sortableFields[0]}:sideways`]
        ])('%s', async (_name, qs) => {
          expect.hasAssertions();
          const response = await expectStatus(qs, 422);
          expect(response.data.errors.map(error => error.field)).toEqual(['sort']);
        });

        if (query.sortableFields.length >= 2) {
          test.each([
            ['when sorting by multiple fields, then accepted', `sort=${query.sortableFields.slice(0, 2).join(',')}`],
            ['when sorting with mixed directions, then accepted', `sort=${query.sortableFields[0]},-${query.sortableFields[1]}`]
          ])('%s', async (_name, qs) => {
            expect.hasAssertions();
            await expectStatus(qs);
          });
        }
      });
    }

    if (query.filterableFields?.length > 0) {
      describe('Filtering', () => {
        query.filterableFields.forEach(field => {
          const contract = filters[field];
          if (!contract) throw new Error(`${name} filterableFields: ${field} is not a documented filter for ${endpoint}`);
          const notValue = filterExamples(contract).at(-1);
          test(`when filtering ${field} with not, then excludes`, async () => {
            expect.hasAssertions();
            const response = await expectStatus(`filter[${field}][not]=${notValue}`);
            expect(response.data.total).toBeGreaterThan(0);
            expectValuesFor(response, field).forEach(value => expect(String(value)).not.toBe(notValue));
          });
        });

        // Labels documented under "Error labels" in openapi.yaml.
        const firstField = query.filterableFields[0];
        test.each([
          ['when filtering with unknown operator, then the 422 names the key', `filter[${firstField}][unknown]=1`, `filter[${firstField}][unknown]`, 'invalid_choice'],
          ['when filtering unknown field, then the 422 names the key', 'filter[__bogus__]=1', 'filter[__bogus__]', 'unknown_field'],
          ['when filter receives duplicate values, then the 422 names the key', `filter[${firstField}]=1&filter[${firstField}]=2`, `filter[${firstField}]`, 'duplicate']
        ])('%s', async (_name, qs, field, code) => {
          expect.hasAssertions();
          const response = await expectStatus(qs, 422);
          expect(response.data.errors.map(error => [error.field, error.code])).toEqual([[field, code]]);
        });

        query.filterableFields
          .filter(field => ['integer', 'number'].includes(filters[field].value.type) && filters[field].operators.between)
          .forEach(field => {
            const [low, high] = filterExamples(filters[field]).map(Number);
            test.each([
              [`when filtering ${field} with gte, then filters correctly`, `filter[${field}][gte]=${low}`, value => expect(value).toBeGreaterThanOrEqual(low)],
              [`when filtering ${field} with lte, then filters correctly`, `filter[${field}][lte]=${high}`, value => expect(value).toBeLessThanOrEqual(high)],
              [`when filtering ${field} with between, then filters range`, `filter[${field}][between]=${low},${high}`, value => {
                expect(value).toBeGreaterThanOrEqual(low);
                expect(value).toBeLessThanOrEqual(high);
              }]
            ])('%s', async (_name, qs, verifyValue) => {
              expect.hasAssertions();
              const response = await expectStatus(qs);
              expectValuesFor(response, field).forEach(verifyValue);
            });
          });

        if (query.filterableFields.length >= 2) {
          test('when combining multiple filters, then accepted', async () => {
            expect.hasAssertions();
            const [f1, f2] = query.filterableFields;
            await expectStatus(`filter[${f1}][gte]=1&filter[${f2}][not]=999999`);
          });
        }
      });
    }

    // OpenAPI declares trashed only where the resource has soft deletion.
    describe('Soft-delete scope', () => {
      const supported = declaresQueryParameter(endpoint, 'trashed') ? 200 : 422;
      test.each([['only', supported], ['with', supported], ['bogus', 422]])(
        'when trashed=%s, then returns %i',
        async (value, status) => {
          expect.hasAssertions();
          const response = await expectStatus(`trashed=${value}`, status);
          if (status === 422) expect(response.data.errors[0].field).toBe('trashed');
        }
      );
    });

    // Acceptance and rejection need no matching rows, so every documented field
    // is tested; result checks stay on filterableFields.
    describe('Filter contract', () => {
      for (const [field, contract] of Object.entries(filters)) {
        test.each(validFilterCases(contract).map(([operator, value]) => [
          operator ? `filter[${field}][${operator}]` : `filter[${field}]`,
          value
        ]))('when %s=%s is valid, then accepted', async (key, value) => {
          expect.hasAssertions();
          const response = await expectStatus(`${key}=${encodeURIComponent(value)}`);
          expect(Array.isArray(response.data.data)).toBe(true);
        });
        test.each(invalidFilterCases(contract))(
          `when filter[${field}][%s]=%s is invalid, then returns a field-specific 422`,
          async (operator, value) => {
            const key = `filter[${field}][${operator}]`;
            const response = await expectStatus(`${key}=${encodeURIComponent(value)}`, 422);
            expect(response.headers['content-type']).toMatch(/application\/problem\+json/);
            expect(response.data.errors[0].field).toBe(key);
          }
        );
      }
    });

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
        expect.hasAssertions();
        const response = await expectStatus(qs, status);
        if (verify) verify(response);
      });
    });

    if (query.selectableFields?.length > 0) {
      describe('Field Selection', () => {
        test('when selecting fields, then returns only those', async () => {
          expect.hasAssertions();
          const requestedFields = ['id', query.selectableFields[1]].filter(Boolean);
          const response = await expectStatus(`fields=${requestedFields.join(',')}`);
          expect(response.data.data.length).toBeGreaterThan(0);
          const first = response.data.data[0];

          expect(Object.keys(first).sort()).toEqual([...requestedFields].sort());
        });

        test('when selecting timestamps, then includes them', async () => {
          expect.hasAssertions();
          const fields = query.selectableFields?.includes('updated_at') ? 'id,created_at,updated_at' : 'id,created_at';
          const response = await expectStatus(`fields=${fields}`);
          expect(response.data.data.length).toBeGreaterThan(0);
          const first = response.data.data[0];

          expect(first).toHaveProperty('id');
          expect(first).toHaveProperty('created_at');
          if (fields.includes('updated_at')) expect(first).toHaveProperty('updated_at');
        });

        test('when selecting single field, then works', async () => {
          expect.hasAssertions();
          const response = await expectStatus('fields=id');
          expect(response.data.data.length).toBeGreaterThan(0);
          expect(response.data.data[0]).toHaveProperty('id');
        });

        test('when selecting unknown field, then returns 422', async () => {
          expect.hasAssertions();
          await expectStatus('fields=id,__bogus__', 422);
        });
      });
    }

    describe('Combined Queries', () => {
      test('when combining all query types, then accepted', async () => {
        expect.hasAssertions();
        const params = new URLSearchParams();
        if (query.searchFields?.length > 0) params.append('search', 'test');
        if (query.sortableFields?.length > 0) params.append('sort', `-${query.sortableFields[0]}`);
        if (query.filterableFields?.length > 0) params.append(`filter[${query.filterableFields[0]}][gte]`, '1');
        if (query.selectableFields?.length > 0) params.append('fields', query.selectableFields.slice(0, 3).join(','));
        params.append('limit', '10');
        await expectStatus(params.toString());
      });

      test('when combining search sort pagination, then works', async () => {
        expect.hasAssertions();
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

function generateTrashedTests(endpoint, filter) {
  // Flags are the sorted deleted_at presence of the listed records.
  test.each([
    ['omitted', '', [false]],
    ['only', '&trashed=only', [true]],
    ['with', '&trashed=with', [false, true]]
  ])('when trashed is %s, then the listed records have deleted flags %j', async (_name, trashed, flags) => {
    const response = await global.api.apiCall('GET', `${endpoint}?${filter()}${trashed}`);
    expect(response.status).toBe(200);
    expect(response.data.data.map(record => record.deleted_at !== null).sort()).toEqual(flags);
  });

  test('when trashed=only, then every listed record is deleted', async () => {
    const response = await global.api.apiCall('GET', `${endpoint}?trashed=only&limit=100`);
    expect(response.status).toBe(200);
    expect(response.data.data.length).toBeGreaterThan(0);
    response.data.data.forEach(record => expect(record.deleted_at).toEqual(expect.any(String)));
  });
}

module.exports = { generateQueryTests, generateTrashedTests };
