const path = require('path');

const OpenApiContractValidator = require('./OpenApiContractValidator');

const SPEC_PATH = path.join(__dirname, '../../openapi.yaml');

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
          required: true,
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

  test('when an optional declared response header is missing, then validation succeeds', () => {
    const validator = new OpenApiContractValidator(documentFor({
      headers: {
        'Content-Range': {
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
    })).not.toThrow();
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

  test('when response omits a required resource field, then validateResponse throws', () => {
    const validator = new OpenApiContractValidator(documentFor({
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['id', 'name', 'created_at'],
            properties: {
              id: { type: 'integer' },
              name: { type: 'string' },
              created_at: { type: 'string' }
            }
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
        data: { id: 1, name: 'incomplete' }
      }
    })).toThrow(/required property 'created_at'/);
  });

  test('when required query parameter is missing, then validateRequestParameters throws', () => {
    const validator = new OpenApiContractValidator(documentWithParameters([
      { name: 'max_age', in: 'query', required: true, schema: { type: 'integer', minimum: 0 } }
    ]));

    expect(() => validator.validateRequestParameters({
      method: 'GET',
      operationPath: '/things',
      query: {}
    })).toThrow('GET /things query parameter max_age is required');
  });

  test('when query parameter violates its schema, then validateRequestParameters throws', () => {
    const validator = new OpenApiContractValidator(documentWithParameters([
      { name: 'limit', in: 'query', required: false, schema: { type: 'integer', minimum: 1 } }
    ]));

    expect(() => validator.validateRequestParameters({
      method: 'GET',
      operationPath: '/things',
      query: { limit: '0' }
    })).toThrow(/query parameter limit does not match schema/);
  });

  test('when path parameter is zero for a minimum 1 schema, then validateRequestParameters throws', () => {
    const validator = new OpenApiContractValidator(documentWithParameters([
      { name: 'id', in: 'path', required: true, schema: { type: 'integer', minimum: 1 } }
    ]));

    expect(() => validator.validateRequestParameters({
      method: 'GET',
      operationPath: '/things',
      pathParams: { id: '0' }
    })).toThrow(/path parameter id does not match schema/);
  });

  test('when header parameter name differs in case, then validateRequestParameters matches it', () => {
    const validator = new OpenApiContractValidator(documentWithParameters([
      { name: 'Range', in: 'header', required: false, schema: { type: 'string' } }
    ]));

    expect(() => validator.validateRequestParameters({
      method: 'GET',
      operationPath: '/things',
      headers: { range: 'bytes=0-99' }
    })).not.toThrow();
  });

  test('when deepObject parameter is declared, then validateRequestParameters skips it', () => {
    const validator = new OpenApiContractValidator(documentWithParameters([
      { name: 'filter', in: 'query', style: 'deepObject', explode: true, schema: { type: 'object' } }
    ]));

    expect(() => validator.validateRequestParameters({
      method: 'GET',
      operationPath: '/things',
      query: { 'filter[name]': 'Radio' }
    })).not.toThrow();
  });
});

describe('openapi.yaml contract invariants', () => {
  let document;

  const LIST_OPERATIONS = [
    ['get', '/api/v1/stations'],
    ['get', '/api/v1/voices'],
    ['get', '/api/v1/stories'],
    ['get', '/api/v1/users'],
    ['get', '/api/v1/bulletins'],
    ['get', '/api/v1/stations/{id}/bulletins'],
    ['get', '/api/v1/stories/{id}/bulletins'],
    ['get', '/api/v1/bulletins/{id}/stories'],
    ['get', '/api/v1/station-voices']
  ];

  const AUDIO_DOWNLOAD_OPERATIONS = [
    ['get', '/public/stations/{id}/bulletin.wav'],
    ['get', '/api/v1/stories/{id}/audio'],
    ['get', '/api/v1/bulletins/{id}/audio'],
    ['get', '/api/v1/station-voices/{id}/audio']
  ];

  const REQUIRED_SCHEMA_FIELDS = {
    Station: ['id', 'name', 'max_stories_per_block', 'pause_seconds', 'created_at', 'updated_at'],
    Voice: ['id', 'name', 'created_at', 'updated_at'],
    Story: [
      'id', 'title', 'text', 'voice_id', 'audio_file', 'audio_url', 'duration_seconds',
      'status', 'start_date', 'end_date', 'weekdays', 'is_breaking',
      'created_at', 'updated_at', 'deleted_at'
    ],
    User: [
      'id', 'username', 'full_name', 'email', 'role', 'last_login_at',
      'login_count', 'deleted_at', 'created_at', 'updated_at'
    ],
    StationVoice: ['id', 'station_id', 'voice_id', 'audio_file', 'audio_url', 'mix_point', 'created_at', 'updated_at'],
    BulletinResponse: ['id', 'station_id', 'filename', 'duration_seconds', 'file_size', 'story_count', 'created_at']
  };

  beforeAll(async () => {
    const validator = await OpenApiContractValidator.fromFile(SPEC_PATH);
    document = validator.document;
  });

  test.each(LIST_OPERATIONS)('when listing via %s %s, then 422 is declared', (method, operationPath) => {
    expect(Object.keys(document.paths[operationPath][method].responses)).toContain('422');
  });

  test('when an operation uses the shared id path parameter, then 400 is declared', () => {
    for (const [operationPath, pathItem] of Object.entries(document.paths)) {
      if (!operationPath.includes('{id}') || operationPath.startsWith('/public/')) {
        continue;
      }
      for (const [method, operation] of Object.entries(pathItem)) {
        const statuses = Object.keys(operation.responses || {});
        expect({ method, operationPath, has400: statuses.includes('400') })
          .toEqual({ method, operationPath, has400: true });
      }
    }
  });

  test('when the shared id path parameter is declared, then it requires a positive integer', () => {
    const idParameter = document.paths['/api/v1/stations/{id}'].get.parameters
      .find((parameter) => parameter.name === 'id' && parameter.in === 'path');
    expect(idParameter.schema.minimum).toBe(1);
  });

  test.each(AUDIO_DOWNLOAD_OPERATIONS)(
    'when downloading audio via %s %s, then byte-range responses are declared',
    (method, operationPath) => {
      const operation = document.paths[operationPath][method];
      const statuses = Object.keys(operation.responses);
      expect(statuses).toEqual(expect.arrayContaining(['206', '304', '416']));
      const rangeParameter = operation.parameters.find(
        (parameter) => parameter.name === 'Range' && parameter.in === 'header'
      );
      expect(rangeParameter).toBeDefined();
      const ifModifiedSinceParameter = operation.parameters.find(
        (parameter) => parameter.name === 'If-Modified-Since' && parameter.in === 'header'
      );
      expect(ifModifiedSinceParameter).toBeDefined();
    }
  );

  test('when generating a bulletin with an audio/wav Accept header, then byte-range responses are declared', () => {
    // POST bulletins serves the WAV through the same file-serving path, but 304
    // does not apply: conditional If-Modified-Since handling is GET/HEAD only.
    const operation = document.paths['/api/v1/stations/{id}/bulletins'].post;
    expect(Object.keys(operation.responses)).toEqual(expect.arrayContaining(['206', '416']));
    const rangeParameter = operation.parameters.find(
      (parameter) => parameter.name === 'Range' && parameter.in === 'header'
    );
    expect(rangeParameter).toBeDefined();
  });

  test.each(Object.entries(REQUIRED_SCHEMA_FIELDS))(
    'when the %s schema is published, then its always-present fields stay required',
    (schemaName, expectedRequired) => {
      const schema = document.components.schemas[schemaName];
      expect((schema.required || []).sort()).toEqual([...expectedRequired].sort());
    }
  );

  test('when a timeout can occur, then 504 is declared with the internal.timeout problem example', () => {
    for (const [method, operationPath] of [
      ['get', '/public/stations/{id}/bulletin.wav'],
      ['post', '/api/v1/stations/{id}/bulletins'],
      ['post', '/api/v1/stories/{id}/tts']
    ]) {
      const response = document.paths[operationPath][method].responses['504'];
      expect(response).toBeDefined();
      const example = response.content['application/problem+json'].example;
      expect(example.status).toBe(504);
      expect(example.code).toBe('internal.timeout');
    }
  });

  test('when permission is denied, then the forbidden example uses the insufficient-permissions type', () => {
    const forbidden = document.paths['/api/v1/stations'].get.responses['403'];
    const example = forbidden.content['application/problem+json'].examples.insufficient_permissions.value;
    expect(example.type).toBe('https://babbel.api/problems/insufficient-permissions');
  });

  test('when no stories are available, then the example uses the bulletin.no_stories type', () => {
    const unprocessable = document.paths['/api/v1/stations/{id}/bulletins'].post.responses['422'];
    const example = unprocessable.content['application/problem+json'].examples.no_stories.value;
    expect(example.type).toBe('https://babbel.api/problems/bulletin.no_stories');
    expect(example.code).toBe('bulletin.no_stories');
  });

  test('when a conflict occurs, then examples use resource-specific problem types', () => {
    const conflict = document.paths['/api/v1/stations'].post.responses['409'];
    const examples = conflict.content['application/problem+json'].examples;
    expect(examples.duplicate_name.value.type).toBe('https://babbel.api/problems/station.duplicate');
    expect(examples.dependency_constraint.value.type).toBe('https://babbel.api/problems/station.has_dependencies');
  });
});

function documentWithParameters(parameters) {
  return {
    openapi: '3.1.0',
    paths: {
      '/things': {
        get: {
          parameters,
          responses: {
            200: {
              content: {
                'application/json': {
                  schema: { type: 'object' }
                }
              }
            }
          }
        }
      }
    }
  };
}

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
