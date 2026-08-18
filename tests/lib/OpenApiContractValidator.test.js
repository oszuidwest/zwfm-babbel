const path = require('path');

const SwaggerParser = require('@apidevtools/swagger-parser');

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

  // All three bulletin listings $ref the same bulletinFilter parameter.
  const BULLETIN_FILTER_FIELDS = [
    'id', 'station_id', 'filename', 'duration_seconds', 'file_size', 'story_count', 'file_purged_at', 'created_at'
  ];

  const TYPED_FILTER_OPERATIONS = [
    ['get', '/api/v1/stations', ['id', 'name', 'max_stories_per_block', 'pause_seconds', 'created_at', 'updated_at']],
    ['get', '/api/v1/voices', ['id', 'name', 'elevenlabs_voice_id', 'created_at', 'updated_at']],
    ['get', '/api/v1/stories', [
      'id', 'title', 'text', 'voice_id', 'audio_url', 'has_audio', 'status', 'start_date', 'end_date',
      'duration_seconds', 'weekdays', 'is_breaking', 'created_at', 'updated_at', 'deleted_at'
    ]],
    ['get', '/api/v1/users', ['id', 'username', 'full_name', 'email', 'role', 'created_at', 'updated_at']],
    ['get', '/api/v1/bulletins', BULLETIN_FILTER_FIELDS],
    ['get', '/api/v1/stations/{id}/bulletins', BULLETIN_FILTER_FIELDS],
    ['get', '/api/v1/stories/{id}/bulletins', BULLETIN_FILTER_FIELDS],
    ['get', '/api/v1/station-voices', [
      'id', 'station_id', 'voice_id', 'audio_url', 'has_audio', 'mix_point', 'created_at', 'updated_at'
    ]]
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
    // These invariants only read the dereferenced document; full spec
    // validation already runs in `make validate-spec` and the integration
    // contract suite, so skip that pass here.
    document = await SwaggerParser.dereference(SPEC_PATH);
  });

  test.each(LIST_OPERATIONS)('when listing via %s %s, then 422 is declared', (method, operationPath) => {
    expect(Object.keys(document.paths[operationPath][method].responses)).toContain('422');
  });

  test.each(TYPED_FILTER_OPERATIONS)(
    'when filtering via %s %s, then only endpoint-specific fields are accepted',
    (method, operationPath, expectedFields) => {
      const operation = document.paths[operationPath][method];
      const filter = operation.parameters.find((parameter) => parameter.name === 'filter');

      expect(filter.style).toBe('deepObject');
      expect(filter.schema.additionalProperties).toBe(false);
      expect(Object.keys(filter.schema.properties).sort()).toEqual([...expectedFields].sort());
    }
  );

  test('when filtering numeric IDs and audio presence, then generated types are numeric and boolean', () => {
    const storyOperation = document.paths['/api/v1/stories'].get;
    const filter = storyOperation.parameters.find((parameter) => parameter.name === 'filter');

    expect(filter.schema.properties.id.oneOf[0].type).toBe('integer');
    expect(filter.schema.properties.voice_id.oneOf[0].type).toBe('integer');
    expect(filter.schema.properties.has_audio.oneOf[0].type).toBe('boolean');
    expect(filter.schema.properties.has_audio.oneOf[1].properties.in).toBeUndefined();
    expect(filter.schema.properties.is_breaking.oneOf[1].properties.in.type).toBe('string');
    expect(filter.schema.properties.start_date.oneOf[0].format).toBe('date');
    expect(filter.schema.properties.end_date.oneOf[0].format).toBe('date');
    expect(filter.schema.properties.audio_url.deprecated).toBe(true);
    // Documented examples use bare dates against datetime columns, so the
    // datetime value schema must accept both formats.
    expect(filter.schema.properties.created_at.oneOf[0].anyOf.map((s) => s.format).sort()).toEqual(['date', 'date-time']);
    // Weekdays is a 7-bit mask (Sun=1 ... Sat=64).
    expect(filter.schema.properties.weekdays.oneOf[0].maximum).toBe(127);
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

  test('when generating a bulletin, then only JSON metadata is declared', () => {
    const operation = document.paths['/api/v1/stations/{id}/bulletins'].post;
    expect(Object.keys(operation.responses['200'].content)).toEqual(['application/json']);
    expect(operation.parameters.some((parameter) => parameter.name === 'Accept')).toBe(false);
    expect(operation.parameters.some((parameter) => parameter.name === 'Range')).toBe(false);
  });

  test('when listing station bulletins, then latest has a separate response operation', () => {
    const listOperation = document.paths['/api/v1/stations/{id}/bulletins'].get;
    const latestOperation = document.paths['/api/v1/stations/{id}/bulletins/latest'].get;

    expect(listOperation.responses['200'].content['application/json'].schema.type).toBe('object');
    expect(listOperation.parameters.some((parameter) => parameter.name === 'latest')).toBe(false);
    expect(latestOperation.responses['200'].content['application/json'].schema.required).toContain('id');
  });

  // The not-block that rejects only-null update bodies must cover every
  // updatable field: a field present in properties but missing from
  // not.properties would make the not-subschema match (and reject) any valid
  // update that only sets that field.
  test.each(['StationVoiceUpdate', 'StoryUpdate', 'UserUpdate'])(
    'when the %s schema guards against only-null updates, then its not-block lists every updatable field',
    (schemaName) => {
      const schema = document.components.schemas[schemaName];
      expect(Object.keys(schema.not.properties).sort()).toEqual(Object.keys(schema.properties).sort());
    }
  );

  test.each(Object.entries(REQUIRED_SCHEMA_FIELDS))(
    'when the %s schema is published, then its always-present fields stay required',
    (schemaName, expectedRequired) => {
      const schema = document.components.schemas[schemaName];
      expect((schema.required || []).sort()).toEqual([...expectedRequired].sort());
    }
  );

  test('when an operation returns created JSON, then every documented field is required', () => {
    for (const [operationPath, pathItem] of Object.entries(document.paths)) {
      for (const [method, operation] of Object.entries(pathItem)) {
        const schema = operation.responses?.['201']?.content?.['application/json']?.schema;
        if (!schema) continue;

        // Composed schemas can hide properties from this top-level invariant.
        expect({
          method,
          operationPath,
          composition: ['allOf', 'oneOf', 'anyOf'].filter((keyword) => keyword in schema),
          required: (schema.required || []).sort()
        }).toEqual({
          method,
          operationPath,
          composition: [],
          required: Object.keys(schema.properties || {}).sort()
        });
      }
    }
  });

  test('when the current session is returned, then effective permissions are required and typed', () => {
    const schema = document.paths['/api/v1/sessions/current'].get.responses['200']
      .content['application/json'].schema;
    const sessionExtension = schema.allOf.find((part) => part.properties?.permissions);
    const permissions = sessionExtension.properties.permissions;

    expect(sessionExtension.required).toContain('permissions');
    expect(permissions.additionalProperties).toBe(false);

    const resources = Object.values(permissions.properties);
    expect(resources.length).toBeGreaterThan(0);
    for (const resource of resources) {
      expect(resource.type).toBe('array');
      expect(resource.items.enum.length).toBeGreaterThan(0);
      for (const action of resource.items.enum) {
        expect(['read', 'write', 'generate']).toContain(action);
      }
    }
  });

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

  test('when an operation declares an error response, then it uses Problem Details', () => {
    for (const [operationPath, pathItem] of Object.entries(document.paths)) {
      for (const [method, operation] of Object.entries(pathItem)) {
        for (const [status, response] of Object.entries(operation.responses || {})) {
          if (Number(status) < 400) continue;

          expect({ method, operationPath, status, mediaTypes: Object.keys(response.content || {}) })
            .toEqual({ method, operationPath, status, mediaTypes: ['application/problem+json'] });
          const schema = response.content['application/problem+json'].schema;
          const required = schema.required || schema.allOf?.flatMap((part) => part.required || []) || [];
          expect(required)
            .toEqual(expect.arrayContaining(['type', 'title', 'status', 'detail']));
        }
      }
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
  return documentFor({}, parameters);
}

function documentFor(responseSpec, parameters) {
  return {
    openapi: '3.1.0',
    paths: {
      '/things': {
        get: {
          ...(parameters ? { parameters } : {}),
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
