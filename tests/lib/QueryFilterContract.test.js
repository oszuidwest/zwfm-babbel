const { getSearchFields, assertSearchFields } = require('./QueryFilterContract');

describe('Search field contract', () => {
  test.each(['stations', 'voices', 'stories', 'users', 'bulletins', 'station-voices'])(
    '%s schema matches its documented search fields', resource => {
      const schema = require(`./schemas/${resource}.schema`);
      expect(() => assertSearchFields(schema.endpoint, schema.query.searchFields)).not.toThrow();
    }
  );

  test.each(['/stories/{id}/bulletins', '/stations/{id}/bulletins'])(
    '%s declares the bulletin search contract', endpoint => {
      expect(getSearchFields(endpoint)).toEqual(['filename']);
    }
  );

  test.each([[], ['title'], ['text'], ['title', 'unknown'], ['title', 'text', 'text']].map(fields => [fields]))(
    'a mismatched story schema %j fails', fields => {
      expect(() => assertSearchFields('/stories', fields)).toThrow(/differ from OpenAPI/);
    }
  );

  test('search field order does not change the contract', () => {
    expect(() => assertSearchFields('/stories', ['text', 'title'])).not.toThrow();
  });
});
