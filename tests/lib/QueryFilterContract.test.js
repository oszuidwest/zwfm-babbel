const { getFilterContracts, validFilterCases } = require('./QueryFilterContract');

describe('validFilterCases', () => {
  test.each([
    ['/stations', 'created_at', '2024-01-01T01:00:00+01:00'],
    ['/stations', 'pause_seconds', '1.5'],
    ['/stories', 'weekdays', '127']
  ])('when %s %s has a stricter-mapping boundary, then eq sends %s', (endpoint, field, value) => {
    expect(validFilterCases(getFilterContracts(endpoint)[field])).toContainEqual(['eq', value]);
  });
});
