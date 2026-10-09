const { getFilterContracts, filterExamples, invalidFilterCases } = require('./QueryFilterContract');
const schemas = require('./schemas');

describe('Query filter contract', () => {
  test.each(Object.values(schemas))(
    'every selected $name filter has a documented contract and rejection coverage',
    ({ endpoint, query }) => {
      const filters = getFilterContracts(endpoint);
      for (const field of query.filterableFields) {
        expect(filters).toHaveProperty(field);
        expect(filterExamples(filters[field]).length).toBeGreaterThan(0);
      }
      for (const contract of Object.values(filters)) {
        expect(invalidFilterCases(contract).length).toBeGreaterThan(0);
      }
    }
  );

  test('nullable values and presence filters retain their distinct operators', () => {
    const filters = getFilterContracts('/stories');
    expect(filters.voice_id.operators).toHaveProperty('null');
    expect(filters.id.operators).not.toHaveProperty('null');
    expect(filters.has_audio.value.type).toBe('boolean');
    expect(filters.has_audio.operators).not.toHaveProperty('in');
    expect(filters.is_breaking.operators).toHaveProperty('in');
    expect(filters.weekdays.operators).toHaveProperty('band');
    expect(filters.weekdays.operators).not.toHaveProperty('between');
  });

  test('enum and timestamp examples come from the filter value contract', () => {
    const filters = getFilterContracts('/stories');
    expect(filterExamples(filters.status)).toEqual(['draft', 'active', 'expired']);
    expect(filterExamples(filters.created_at)[0]).toBe('2024-01-01T00:00:00Z');
    expect(filterExamples(filters.start_date)[0]).toBe('2024-01-01');
  });

  test.each([
    ['/stories', 'weekdays', ['band', '128']],
    ['/stories', 'voice_id', ['in', '1,abc']],
    ['/stories', 'start_date', ['between', '2024-01-01,2024-02-30']],
    ['/stories', 'status', ['in', 'draft,unknown']],
    ['/voices', 'id', ['like', '1']],
    ['/station-voices', 'mix_point', ['eq', 'NaN']],
    ['/bulletins', 'created_at', ['eq', '2024-01-01T25:00:00Z']],
    ['/stations', 'max_stories_per_block', ['null', 'true']]
  ])('%s %s keeps the regression case %j', (endpoint, field, regression) => {
    expect(invalidFilterCases(getFilterContracts(endpoint)[field])).toContainEqual(regression);
  });
});
