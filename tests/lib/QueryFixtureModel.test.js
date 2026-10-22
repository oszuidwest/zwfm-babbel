const { isolatedSearchCase, independentFilters, matchingSearchIDs } = require('./QueryFixtureModel');

describe('Query fixture mutation models', () => {
  const rows = [
    { id: 1, title: 'Headline Alpha', text: 'Body One querykeep', role: 'viewer' },
    { id: 2, title: 'Headline Beta', text: 'Body Two querykeep', role: 'editor' },
    { id: 3, title: 'Headline Gamma', text: 'Body Three querykeep', role: 'viewer' },
    { id: 4, title: 'Headline Delta', text: 'Body Four querydrop', role: 'editor' }
  ];

  test.each(['title', 'text'])('isolated %s search fails if that field is omitted or uses equality', field => {
    const fields = ['title', 'text'];
    const plan = isolatedSearchCase(rows, fields, field);
    expect(plan.term.length).toBeGreaterThan(0);
    const target = rows.find(row => plan.ids.includes(row.id));
    expect(target[field]).toContain(plan.term);
    expect(plan.term.length).toBeLessThan(target[field].length);
    expect(plan.ids.length).toBeLessThan(rows.length);
    expect(matchingSearchIDs(rows, fields.filter(other => other !== field), plan.term)).not.toEqual(plan.ids);
    const equalityIDs = rows.filter(row => fields.some(other => other === field
      ? row[other].toLowerCase() === plan.term.toLowerCase()
      : row[other].toLowerCase().includes(plan.term.toLowerCase()))).map(row => row.id);
    expect(equalityIDs).not.toEqual(plan.ids);
  });

  test('short or universally shared inner terms cannot create weak search tests', () => {
    for (const titles of [['a', 'ab'], ['AxZ', 'BxY']]) {
      expect(() => isolatedSearchCase(titles.map((title, index) => ({ id: index, title })), ['title'], 'title')).toThrow(/strict substring/);
    }
  });

  test('ambiguous search fields cannot silently produce a weak test', () => {
    expect(() => isolatedSearchCase([{ id: 1, title: 'same', text: 'same' }], ['title', 'text'], 'title')).toThrow(/isolated/);
  });

  test('dropping either combined filter changes the exact expected set', () => {
    const plan = independentFilters(rows, ['id', 'role']);
    expect(plan.ids.length).toBeGreaterThan(0);
    for (const filter of plan.filters) expect(rows.filter(filter.keep).map(row => row.id)).not.toEqual(plan.ids);
  });

  test('fixtures without two independently selective predicates are rejected', () => {
    expect(() => independentFilters([{ id: 1, role: 'viewer' }, { id: 2, role: 'viewer' }], ['id', 'role'])).toThrow(/independently selective/);
  });
});
