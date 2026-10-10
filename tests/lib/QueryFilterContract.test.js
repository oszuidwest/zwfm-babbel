const { getFilterContracts, validFilterCases } = require('./QueryFilterContract');

const endpoints = ['/stations', '/voices', '/stories', '/users', '/bulletins', '/station-voices'];
const fields = endpoints.flatMap(endpoint => Object.entries(getFilterContracts(endpoint))
  .map(([field, contract]) => [`${endpoint} ${field}`, contract]));

describe('validFilterCases', () => {
  test.each(fields)('when %s is documented, then every operator gets a case', (_name, contract) => {
    const cases = validFilterCases(contract);
    const operators = new Set(cases.map(([operator]) => operator));

    expect([...operators].sort()).toEqual(['', ...Object.keys(contract.operators)].sort());
    if (contract.operators.null) {
      expect(cases.filter(([operator]) => operator === 'null').map(([, raw]) => raw)).toEqual(['true', 'false']);
    }
  });

  test.each(fields)('when %s takes a list or range, then the value has at least two parts', (_name, contract) => {
    for (const [operator, raw] of validFilterCases(contract)) {
      if (operator === 'in' || operator === 'between') expect(raw.split(',').length).toBeGreaterThanOrEqual(2);
    }
  });

  test.each([
    ['/stations created_at', '2024-01-01T01:00:00+01:00'],
    ['/stations pause_seconds', '1.5'],
    ['/stories weekdays', '127']
  ])('when %s has a stricter-mapping boundary, then eq sends %s', (name, value) => {
    const [, contract] = fields.find(([field]) => field === name);
    expect(validFilterCases(contract)).toContainEqual(['eq', value]);
  });
});
