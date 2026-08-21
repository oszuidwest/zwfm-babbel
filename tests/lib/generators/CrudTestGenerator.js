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
      test('when creating with valid data, then returns 201 Created', async () => {
        const data = await createData('create-test');

        const response = await global.api.apiCall('POST', endpoint, data);

        expect(response.status).toBe(201);
        expect(response.data).toHaveProperty('id');

        if (response.data?.id) {
          global.resources.track(namePlural, response.data.id);
        }
      });

      test(`when fetching created ${name}, then data matches input`, async () => {
        const data = await createData('verify-data');
        const createResponse = await global.api.apiCall('POST', endpoint, data);
        const createdId = createResponse.data?.id;

        const response = await global.api.apiCall('GET', `${endpoint}/${createdId}`);

        expect(response.status).toBe(200);
        Object.keys(data).forEach(key => {
          if (response.data[key] !== undefined) {
            expect(response.data[key]).toEqual(data[key]);
          }
        });

        if (createdId) {
          global.resources.track(namePlural, createdId);
        }
      });

      test(`when fetching created ${name}, then has timestamps`, async () => {
        const data = await createData('timestamp-check');
        const createResponse = await global.api.apiCall('POST', endpoint, data);
        const createdId = createResponse.data?.id;

        const response = await global.api.apiCall('GET', `${endpoint}/${createdId}`);

        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('created_at');
        expect(response.data).toHaveProperty('updated_at');

        if (createdId) {
          global.resources.track(namePlural, createdId);
        }
      });

      test('when creating, then returns Location header', async () => {
        const data = await createData('location-test');

        const response = await global.api.apiCall('POST', endpoint, data);

        expect(response.status).toBe(201);
        expect(response.headers).toHaveProperty('location');
        expect(response.headers.location).toContain(endpoint);

        if (response.data?.id) {
          global.resources.track(namePlural, response.data.id);
        }
      });
    });

    describe('Read', () => {
      test('when listing, then returns array', async () => {
        const response = await global.api.apiCall('GET', endpoint);

        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('data');
        expect(Array.isArray(response.data.data)).toBe(true);
      });

      test('when listing, then has pagination metadata', async () => {
        const response = await global.api.apiCall('GET', endpoint);

        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('data');
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

      test('when fetching non-existent ID, then returns 404', async () => {
        const response = await global.api.apiCall('GET', `${endpoint}/999999`);

        expect(response.status).toBe(404);
      });

      test('when resource not found, then error follows RFC 9457', async () => {
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

        test('when updating with valid data, then returns 200', async () => {
          const response = await global.api.apiCall('PUT', `${endpoint}/${sharedResource.id}`, updatePayload);

          expect(response.status).toBe(200);
        });

        test('when updating, then changes are persisted', async () => {
          const response = await global.api.apiCall('GET', `${endpoint}/${sharedResource.id}`);

          expect(response.status).toBe(200);
          const firstKey = Object.keys(updatePayload)[0];
          expect(response.data[firstKey]).toEqual(updatePayload[firstKey]);
        });

        test('when updating, then updated_at changes', async () => {
          const beforeResponse = await global.api.apiCall('GET', `${endpoint}/${sharedResource.id}`);
          const beforeTimestamp = new Date(beforeResponse.data.updated_at).getTime();

          // MySQL timestamps have one-second precision.
          await global.helpers.sleep(1100);

          await global.api.apiCall('PUT', `${endpoint}/${sharedResource.id}`, updateData());

          const afterResponse = await global.api.apiCall('GET', `${endpoint}/${sharedResource.id}`);
          const afterTimestamp = new Date(afterResponse.data.updated_at).getTime();
          expect(afterTimestamp).toBeGreaterThan(beforeTimestamp);
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
      test('when deleting, then returns 204', async () => {
        const data = await createData('delete-test');
        const createResponse = await global.api.apiCall('POST', endpoint, data);
        expect(createResponse.status).toBe(201);
        const deleteId = createResponse.data.id;

        const response = await global.api.apiCall('DELETE', `${endpoint}/${deleteId}`);

        expect(response.status).toBe(204);

        const verifyResponse = await global.api.apiCall('GET', `${endpoint}/${deleteId}`);
        expect(verifyResponse.status).toBe(404);
      });

      test('when deleting non-existent ID, then returns 404', async () => {
        const response = await global.api.apiCall('DELETE', `${endpoint}/999999`);

        expect(response.status).toBe(404);
      });

      test('when deleting twice, then second returns 404', async () => {
        const data = await createData('idempotent-test');
        const createResponse = await global.api.apiCall('POST', endpoint, data);
        expect(createResponse.status).toBe(201);
        const deleteId = createResponse.data.id;
        await global.api.apiCall('DELETE', `${endpoint}/${deleteId}`);

        const secondDelete = await global.api.apiCall('DELETE', `${endpoint}/${deleteId}`);

        expect(secondDelete.status).toBe(404);
      });
    });
  });
}

module.exports = { generateCrudTests };
