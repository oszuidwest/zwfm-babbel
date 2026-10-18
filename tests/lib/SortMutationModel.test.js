const { unnoticedSortMappings } = require('./SortMutationModel');

describe('SortMutationModel', () => {
  test.each([
    ['fields that rise together', { a: [0, 1, 2], b: [0, 1, 2] }, [['a', 'b'], ['b', 'a']]],
    ['a column whose ties can be arranged in field order', { a: [0, 1, 2], b: [0, 1, 1] }, [['a', 'b'], ['b', 'a']]],
    ['opposite orders', { a: [0, 1, 2], b: [2, 1, 0] }, []],
    ['orders that differ in one pair', { a: [0, 1, 2], b: [1, 0, 2] }, []],
    ['orders that disagree only between non-adjacent rows', { a: [0, 5, 1], b: [1, 5, 0] }, []],
    ['a tied field with a discordant pair', { a: [0, 1, 1], b: [2, 0, 1] }, []],
    ['three fields where two rise together', { a: [0, 1, 2], b: [1, 0, 2], c: [0, 1, 2] }, [['a', 'c'], ['c', 'a']]]
  ])('when the fixtures hold %s %j, then the unnoticed mappings are %j', (_name, keysByField, expected) => {
    expect(unnoticedSortMappings(keysByField)).toEqual(expected);
  });

  test('when every field but the default rises with the fixture index, then each pair among them is unnoticed', () => {
    const rising = [0, 1, 2];
    const keysByField = { id: rising, name: [1, 0, 2], created_at: rising, updated_at: rising };
    expect(unnoticedSortMappings(keysByField)).toHaveLength(6);
  });
});
