const { declaresQueryParameter, getFilterContracts, validFilterCases, invalidFilterCases } = require('../QueryFilterContract');
const { createMySQLExecutor } = require('../MySQLHelper');

/**
 * Generates list-query contract tests from a resource schema.
 *
 * Sort tests list only the fixtures whose ids setupFn resolves to. Every
 * sortable field needs two distinct values among them, or an ignored or
 * reversed sort would pass. The default order may sort at most one of these
 * fields: an ignored sort returns that order, so it passes one direction of
 * every field the order happens to sort.
 * @param {Object} schema
 * @param {Function} setupFn Creates the fixtures and resolves to their ids.
 */
function generateQueryTests(schema, setupFn) {
  const { endpoint, name, query } = schema;
  if (!query) throw new Error(`Schema for ${name} missing 'query' configuration`);
  if (!setupFn) throw new Error(`${name} query tests need a setupFn that resolves to fixture ids`);
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
  const sorted = (keys, direction) => keys.toSorted((a, b) => direction * (a - b));

  describe(`${name} Query Parameters`, () => {
    let fixtureIds;
    // Lists only the fixtures and checks that the page holds exactly the
    // expected ones. Rows from other tests could otherwise fill the page.
    const listFixtures = async (qs = '', expected = fixtureIds) => {
      const response = await expectStatus(`filter[id][in]=${fixtureIds.join(',')}${qs}`);
      expect(sorted(response.data.data.map(item => item.id), 1)).toEqual(sorted(expected, 1));
      return response;
    };

    beforeAll(async () => {
      fixtureIds = await setupFn();
    });

    if (query.searchFields?.length > 0) {
      describe('Search', () => {
        test('when searching, then returns 200', async () => {
          expect.hasAssertions();
          const response = await expectStatus('search=test');
          expect(response.data.data.length).toBeGreaterThan(0);
          for (const item of response.data.data) {
            expect(query.searchFields.some(field => String(item[field]).toLowerCase().includes('test'))).toBe(true);
          }
        });

        test('when search empty, then returns all', async () => {
          expect.hasAssertions();
          const unfiltered = await expectStatus('limit=1');
          const emptySearch = await expectStatus('search=&limit=1');
          expect(emptySearch.data.total).toBe(unfiltered.data.total);
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
            const response = await listFixtures(`&sort=${sort}`);
            const keys = sortKeys(response, field);
            // Every fixture needs a key: a missing rank sorts to the end and an
            // unparsable date (NaN) compares equal to everything, so either
            // would hide a wrong order.
            expect(keys).toHaveLength(fixtureIds.length);
            expect(keys.every(Number.isFinite)).toBe(true);
            // Collation-equal strings share a rank, so the Set counts distinct
            // keys the way the comparison below does.
            expect(new Set(keys).size).toBeGreaterThan(1);
            expect(keys).toEqual(sorted(keys, direction));
          });
        });

        test('when sort is omitted, then at most one sortable field lists the fixtures in order', async () => {
          expect.hasAssertions();
          const response = await listFixtures();
          const ordered = query.sortableFields.filter(field => {
            const keys = sortKeys(response, field);
            return [1, -1].some(direction => sorted(keys, direction).every((key, index) => key === keys[index]));
          });
          expect(ordered.length).toBeLessThanOrEqual(1);
        });

        test.each([
          ['when sorting unknown field, then returns a sort 422', 'sort=__bogus__', 'unknown_field'],
          ['when sort direction is invalid, then returns a sort 422', `sort=${query.sortableFields[0]}:sideways`, 'invalid_choice']
        ])('%s', async (_name, qs, code) => {
          expect.hasAssertions();
          const response = await expectStatus(qs, 422);
          expect(response.data.errors.map(error => [error.field, error.code])).toEqual([['sort', code]]);
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
      // Result checks list only the fixtures, and every filterable field needs
      // two distinct values among them: a filter must drop one fixture and
      // keep another.
      describe('Filtering', () => {
        let listed;
        beforeAll(async () => {
          listed = await listFixtures();
        });

        // MySQL comparisons never match NULL, so keep only sees fixtures
        // with a value. Every value and bound below drops a fixture, so an
        // ignored filter fails; an empty expected set would also let a filter
        // that matches nothing pass.
        const expectFiltered = async (field, qs, keep) => {
          const expected = expectItemsWith(listed, field).filter(item => keep(item[field])).map(item => item.id);
          expect(expected.length).toBeGreaterThan(0);
          await listFixtures(`&${qs}`, expected);
        };

        query.filterableFields.forEach(field => {
          if (!filters[field]) throw new Error(`${name} filterableFields: ${field} is not a documented filter for ${endpoint}`);
          test(`when filtering ${field} with not, then excludes the fixtures with that value`, async () => {
            expect.hasAssertions();
            const [excluded] = expectValuesFor(listed, field);
            await expectFiltered(field, `filter[${field}][not]=${encodeURIComponent(excluded)}`, value => value !== excluded);
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

        // Bounds come from the distinct fixture values: gte the second lowest
        // drops the lowest, lte the second highest drops the highest, and
        // between on the second lowest alone also drops the highest when
        // there are at least three values.
        query.filterableFields
          .filter(field => ['integer', 'number'].includes(filters[field].value.type) && filters[field].operators.between)
          .forEach(field => {
            test.each([
              ['gte', ({ secondLowest }) => [secondLowest, value => value >= secondLowest]],
              ['lte', ({ secondHighest }) => [secondHighest, value => value <= secondHighest]],
              ['between', ({ secondLowest }) => [`${secondLowest},${secondLowest}`, value => value === secondLowest]]
            ])(`when filtering ${field} with %s, then lists only the fixtures in range`, async (operator, bounds) => {
              expect.hasAssertions();
              const levels = sorted([...new Set(expectValuesFor(listed, field))], 1);
              expect(levels.length).toBeGreaterThan(1);
              const [raw, inRange] = bounds({ secondLowest: levels[1], secondHighest: levels.at(-2) });
              await expectFiltered(field, `filter[${field}][${operator}]=${raw}`, inRange);
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
      const supported = declaresQueryParameter(endpoint, 'trashed');
      const cases = supported
        ? [['bogus', 422, 'invalid_choice']]
        : [['only', 422, 'unsupported'], ['bogus', 422, 'unsupported']];
      test.each(cases)('when trashed=%s, then returns %i', async (value, status, code) => {
        expect.hasAssertions();
        const response = await expectStatus(`trashed=${value}`, status);
        expect(response.data.errors.map(error => [error.field, error.code])).toEqual([['trashed', code]]);
      });
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
          async (operator, value, code) => {
            const key = `filter[${field}][${operator}]`;
            const response = await expectStatus(`${key}=${encodeURIComponent(value)}`, 422);
            expect(response.headers['content-type']).toMatch(/application\/problem\+json/);
            expect(response.data.errors.map(error => [error.field, error.code])).toEqual([[key, code]]);
          }
        );
      }
    });

    describe('Pagination', () => {
      // An ignored offset returns the first row instead of the second.
      test('when paginating with offset, then skips records', async () => {
        expect.hasAssertions();
        const response = await listFixtures('&sort=id&limit=1&offset=1', [sorted(fixtureIds, 1)[1]]);
        expect(response.data).toHaveProperty('offset', 1);
        expect(response.data.total).toBe(fixtureIds.length);
      });

      test.each([
        ['when paginating with limit, then respects limit', 'limit=2', response => expect(response.data.data.length).toBeLessThanOrEqual(2)],
        ['when offset exceeds data, then returns empty array', 'limit=10&offset=999999', response => expect(response.data.data).toEqual([])]
      ])('%s', async (_name, qs, verify) => {
        expect.hasAssertions();
        const response = await expectStatus(qs);
        verify(response);
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

        test('when selecting unknown field, then returns 422', async () => {
          expect.hasAssertions();
          const response = await expectStatus('fields=id,__bogus__', 422);
          expect(response.data.errors.map(error => [error.field, error.code])).toEqual([['fields', 'unknown_field']]);
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
