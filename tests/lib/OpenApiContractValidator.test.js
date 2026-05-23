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

  test('when number header cannot be parsed, then error names the header', () => {
    const validator = new OpenApiContractValidator(documentFor({
      headers: {
        'X-Score': {
          schema: { type: 'number' }
        }
      }
    }));

    expect(() => validator.validateResponse({
      method: 'GET',
      operationPath: '/things',
      response: {
        status: 200,
        headers: {
          'x-score': 'abc',
          'content-type': 'application/json'
        },
        data: { ok: true }
      }
    })).toThrow('GET /things header X-Score has invalid number value "abc"');
  });

  test('when required response header missing, then error names the header', () => {
    const validator = new OpenApiContractValidator(documentFor({
      headers: {
        'X-Trace-ID': {
          schema: { type: 'string' }
        }
      }
    }));

    expect(() => validator.validateResponse({
      method: 'GET',
      operationPath: '/things',
      response: {
        status: 200,
        headers: { 'content-type': 'application/json' },
        data: { ok: true }
      }
    })).toThrow('GET /things missing response header X-Trace-ID');
  });

  test('when operation is not declared, then error names the operation', () => {
    const validator = new OpenApiContractValidator(documentFor({}));

    expect(() => validator.validateResponse({
      method: 'POST',
      operationPath: '/things',
      response: { status: 200, headers: {}, data: {} }
    })).toThrow('OpenAPI operation not found: POST /things');
  });

  test('when response status is undeclared, then error lists declared statuses', () => {
    const validator = new OpenApiContractValidator(documentFor({}));

    expect(() => validator.validateResponse({
      method: 'GET',
      operationPath: '/things',
      response: {
        status: 418,
        headers: { 'content-type': 'application/json' },
        data: { ok: true }
      }
    })).toThrow('GET /things returned undeclared status 418; declared 200');
  });

  test('when response status matches 4XX pattern, then validation succeeds', () => {
    const document = {
      openapi: '3.1.0',
      paths: {
        '/things': {
          get: {
            responses: {
              '4XX': {
                content: {
                  'application/json': {
                    schema: { type: 'object', properties: { error: { type: 'string' } } }
                  }
                }
              }
            }
          }
        }
      }
    };

    const validator = new OpenApiContractValidator(document);

    expect(() => validator.validateResponse({
      method: 'GET',
      operationPath: '/things',
      response: {
        status: 404,
        headers: { 'content-type': 'application/json' },
        data: { error: 'not found' }
      }
    })).not.toThrow();
  });

  test('when response content-type does not match declared, then error lists options', () => {
    const validator = new OpenApiContractValidator(documentFor({}));

    expect(() => validator.validateResponse({
      method: 'GET',
      operationPath: '/things',
      response: {
        status: 200,
        headers: { 'content-type': 'text/plain' },
        data: 'hello'
      }
    })).toThrow(/returned content-type text\/plain; expected one of application\/json/);
  });

  test('when response media type matches a wildcard, then validation succeeds', () => {
    const document = {
      openapi: '3.1.0',
      paths: {
        '/picture': {
          get: {
            responses: {
              200: {
                content: { 'image/*': {} }
              }
            }
          }
        }
      }
    };

    const validator = new OpenApiContractValidator(document);

    expect(() => validator.validateResponse({
      method: 'GET',
      operationPath: '/picture',
      response: {
        status: 200,
        headers: { 'content-type': 'image/png' },
        data: Buffer.alloc(0)
      }
    })).not.toThrow();
  });

  test('when response body fails schema validation, then error includes the violation', () => {
    const validator = new OpenApiContractValidator(documentFor({}));

    expect(() => validator.validateResponse({
      method: 'GET',
      operationPath: '/things',
      response: {
        status: 200,
        headers: { 'content-type': 'application/json' },
        data: { ok: 'yes' }
      }
    })).toThrow(/does not match schema/);
  });

  test('when request is sent to an operation without a body, then validateRequest throws', () => {
    const document = {
      openapi: '3.1.0',
      paths: {
        '/things': {
          delete: { responses: { 204: {} } }
        }
      }
    };

    const validator = new OpenApiContractValidator(document);

    expect(() => validator.validateRequest({
      method: 'DELETE',
      operationPath: '/things',
      body: { unexpected: true }
    })).toThrow('DELETE /things does not define a request body');
  });

  test('when required request body is missing, then validateRequest throws', () => {
    const document = {
      openapi: '3.1.0',
      paths: {
        '/things': {
          post: {
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: { type: 'object', required: ['name'], properties: { name: { type: 'string' } } }
                }
              }
            },
            responses: { 201: {} }
          }
        }
      }
    };

    const validator = new OpenApiContractValidator(document);

    expect(() => validator.validateRequest({
      method: 'POST',
      operationPath: '/things'
    })).toThrow('POST /things requires a request body');
  });

  test('when request media type is not accepted, then validateRequest lists the supported types', () => {
    const document = {
      openapi: '3.1.0',
      paths: {
        '/things': {
          post: {
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: { type: 'object' }
                }
              }
            },
            responses: { 201: {} }
          }
        }
      }
    };

    const validator = new OpenApiContractValidator(document);

    expect(() => validator.validateRequest({
      method: 'POST',
      operationPath: '/things',
      mediaType: 'text/csv',
      body: 'a,b,c'
    })).toThrow(/does not accept text\/csv; accepts application\/json/);
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
