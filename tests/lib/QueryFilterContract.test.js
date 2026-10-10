const { getFilterContracts, validFilterCases } = require('./QueryFilterContract');

const fields = Object.values(require('./schemas')).flatMap(({ endpoint }) => Object.entries(getFilterContracts(endpoint))
  .map(([field, contract]) => [`${endpoint} ${field}`, contract]));

describe('validFilterCases', () => {
  test.each(fields)('when %s is documented, then every operator gets a case', (_name, contract) => {
    const cases = validFilterCases(contract);

    expect(new Set(cases.map(([operator]) => operator))).toEqual(new Set(['', ...Object.keys(contract.operators)]));
    if (contract.operators.null) {
      expect(cases.filter(([operator]) => operator === 'null').map(([, raw]) => raw)).toEqual(['true', 'false']);
    }
  });

  test.each([
    ['/stations', 'created_at', '2024-01-01T01:00:00+01:00'],
    ['/stations', 'pause_seconds', '1.5'],
    ['/stories', 'weekdays', '127']
  ])('when %s %s has a stricter-mapping boundary, then eq sends %s', (endpoint, field, value) => {
    expect(validFilterCases(getFilterContracts(endpoint)[field])).toContainEqual(['eq', value]);
  });
});
