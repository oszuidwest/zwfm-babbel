const OpenApiContractValidator = require('./OpenApiContractValidator');

describe('OpenApiContractValidator', () => {
  test('when JSON response is malformed, then error includes operation context', () => {
    const validator = new OpenApiContractValidator(documentFor({
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['ok'],
            properties: { ok: { type: 'boolean' } }
          }
        }
      }
    }));

    expect(() => validator.validateResponse({
      method: 'GET',
      operationPath: '/things',
      response: {
        status: 200,
        headers: { 'content-type': 'application/json' },
        data: '{invalid json}'
      }
    })).toThrow('GET /things response 200 application/json contains invalid JSON');
  });

  test('when integer header is invalid, then error names the header', () => {
    const validator = new OpenApiContractValidator(documentFor({
      headers: {
        Age: {
          schema: { type: 'integer' }
        }
      }
    }));

    expect(() => validator.validateResponse({
      method: 'GET',
      operationPath: '/things',
      response: {
        status: 200,
        headers: {
          age: 'abc',
          'content-type': 'application/json'
        },
        data: { ok: true }
      }
    })).toThrow('GET /things header Age has invalid integer value "abc"');
  });

  test('when boolean header is invalid, then error names the header', () => {
    const validator = new OpenApiContractValidator(documentFor({
      headers: {
        'X-Enabled': {
          schema: { type: 'boolean' }
        }
      }
    }));

    expect(() => validator.validateResponse({
      method: 'GET',
      operationPath: '/things',
      response: {
        status: 200,
        headers: {
          'x-enabled': 'maybe',
          'content-type': 'application/json'
        },
        data: { ok: true }
      }
    })).toThrow('GET /things header X-Enabled has invalid boolean value "maybe"');
  });
});

function documentFor(responseSpec) {
  return {
    openapi: '3.1.0',
    paths: {
      '/things': {
        get: {
          responses: {
            200: {
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['ok'],
                    properties: { ok: { type: 'boolean' } }
                  }
                }
              },
              ...responseSpec
            }
          }
        }
      }
    }
  };
}
