/**
 * Generates CRUD contract tests from a resource schema.
 * @param {Object} schema
 * @param {Function|null} [setupFn]
 */
function generateCrudTests(schema, setupFn = null) {
  const { endpoint, name, namePlural, createValidData, updateData } = schema;

  if (!createValidData) {
    throw new Error(`Schema for ${name} missing 'createValidData' function`);
  }

  describe(`${name} CRUD Operations`, () => {
    const sharedResource = { id: null, data: null };

    // Fresh dependencies prevent unique-key collisions between creates.
    const createData = async (suffix) => {
      const deps = setupFn ? await setupFn() : {};
      return {
        ...createValidData(suffix),
        ...deps
      };
    };

    beforeAll(async () => {
      const data = await createData('shared');
      const response = await global.api.apiCall('POST', endpoint, data);

      if (response.status !== 201 || !response.data?.id) {
        throw new Error(`Failed to create shared ${name} in beforeAll (HTTP ${response.status}): ${JSON.stringify(response.data)}`);
      }
      sharedResource.id = response.data.id;
      sharedResource.data = data;
      global.resources.track(namePlural, sharedResource.id);
    });

    describe('Create', () => {
      test(`when creating ${name}, then the response and persisted resource match`, async () => {
        const data = await createData('verify-data');
        const createResponse = await global.api.apiCall('POST', endpoint, data);
        const createdId = createResponse.data?.id;

        expect(createResponse.status).toBe(201);
        expect(createdId).toEqual(expect.any(Number));
        expect(createResponse.headers.location).toBe(`/api/v1${endpoint}/${createdId}`);

        const response = await global.api.apiCall('GET', `${endpoint}/${createdId}`);

        expect(response.status).toBe(200);
        Object.keys(data).forEach(key => {
          if (response.data[key] !== undefined) {
            expect(response.data[key]).toEqual(data[key]);
          }
        });
        expect(response.data).toHaveProperty('created_at');
        expect(response.data).toHaveProperty('updated_at');
        global.resources.track(namePlural, createdId);
      });
    });

    describe('Read', () => {
      test('when listing, then returns a paginated collection', async () => {
        const response = await global.api.apiCall('GET', endpoint);

        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('data');
        expect(Array.isArray(response.data.data)).toBe(true);
        expect(response.data).toHaveProperty('total');
        expect(response.data).toHaveProperty('limit');
        expect(response.data).toHaveProperty('offset');
        expect(typeof response.data.total).toBe('number');
      });

      test(`when fetching by ID, then returns ${name}`, async () => {
        const response = await global.api.apiCall('GET', `${endpoint}/${sharedResource.id}`);

        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('id', sharedResource.id);
      });

      test('when fetching a non-existent ID, then returns a 404 problem', async () => {
        const response = await global.api.apiCall('GET', `${endpoint}/999999`);

        expect(response.status).toBe(404);
        expect(response.data).toHaveProperty('type');
        expect(response.data).toHaveProperty('title');
        expect(response.data).toHaveProperty('status', 404);
      });
    });

    if (updateData) {
      describe('Update', () => {
        const updatePayload = updateData();

        test('when repeating an identical update, then both requests succeed and persist', async () => {
          const response = await global.api.apiCall('PUT', `${endpoint}/${sharedResource.id}`, updatePayload);
          const repeated = await global.api.apiCall('PUT', `${endpoint}/${sharedResource.id}`, updatePayload);

          expect(response.status).toBe(200);
          expect(repeated.status).toBe(200);
          const persisted = await global.api.apiCall('GET', `${endpoint}/${sharedResource.id}`);
          expect(persisted.status).toBe(200);
          const firstKey = Object.keys(updatePayload)[0];
          expect(persisted.data[firstKey]).toEqual(updatePayload[firstKey]);
        });

        test('when updating non-existent ID, then returns 404', async () => {
          // Uniqueness is validated before existence.
          const safeUpdateData = { ...updateData() };
          if (safeUpdateData.name) {
            safeUpdateData.name = `NonExistent_${Date.now()}_${Math.random().toString(36).slice(2)}`;
          }

          const response = await global.api.apiCall('PUT', `${endpoint}/999999`, safeUpdateData);

          expect(response.status).toBe(404);
        });
      });
    }

    describe('Delete', () => {
      test('when deleting, then the resource stays deleted', async () => {
        const data = await createData('delete-test');
        const createResponse = await global.api.apiCall('POST', endpoint, data);
        expect(createResponse.status).toBe(201);
        const deleteId = createResponse.data.id;

        const response = await global.api.apiCall('DELETE', `${endpoint}/${deleteId}`);

        expect(response.status).toBe(204);

        const verifyResponse = await global.api.apiCall('GET', `${endpoint}/${deleteId}`);
        expect(verifyResponse.status).toBe(404);
        const secondDelete = await global.api.apiCall('DELETE', `${endpoint}/${deleteId}`);
        expect(secondDelete.status).toBe(404);
      });

      test('when deleting non-existent ID, then returns 404', async () => {
        const response = await global.api.apiCall('DELETE', `${endpoint}/999999`);

        expect(response.status).toBe(404);
      });
    });
  });
}

module.exports = { generateCrudTests };
