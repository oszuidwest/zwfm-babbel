const { getSearchFields } = require('./QueryFilterContract');

describe('Search field contract', () => {
  test.each(['/stories/{id}/bulletins', '/stations/{id}/bulletins'])(
    '%s declares the bulletin search contract', endpoint => {
      expect(getSearchFields(endpoint)).toEqual(['filename']);
    }
  );
});
