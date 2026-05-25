const { parseFiniteNumber, parseSafeInteger } = require('./numeric');

describe('numeric guards', () => {
  test('when safe integer input is decimal, then it is accepted', () => {
    expect(parseSafeInteger(42, 'id')).toBe(42);
    expect(parseSafeInteger('42', 'id')).toBe(42);
    expect(parseSafeInteger(' -42 ', 'id')).toBe(-42);
  });

  test.each([
    NaN,
    Infinity,
    1.5,
    true,
    [],
    {},
    '',
    ' ',
    '1.5',
    '0x10',
    '1e2',
    '1 OR 1=1'
  ])('when safe integer input is %p, then it is rejected', value => {
    expect(() => parseSafeInteger(value, 'id')).toThrow(/id/);
  });

  test('when finite number input is plain decimal, then it is accepted', () => {
    expect(parseFiniteNumber(1.25, 'duration')).toBe(1.25);
    expect(parseFiniteNumber('1.25', 'duration')).toBe(1.25);
    expect(parseFiniteNumber(' .5 ', 'duration')).toBe(0.5);
    expect(parseFiniteNumber('-0.5', 'duration')).toBe(-0.5);
  });

  test.each([
    NaN,
    Infinity,
    true,
    [],
    {},
    new Date('2024-01-01T00:00:00Z'),
    '',
    ' ',
    '\n',
    '0x10',
    '1e2',
    'Infinity',
    '1; cat /etc/passwd'
  ])('when finite number input is %p, then it is rejected', value => {
    expect(() => parseFiniteNumber(value, 'duration')).toThrow(/duration/);
  });
});
