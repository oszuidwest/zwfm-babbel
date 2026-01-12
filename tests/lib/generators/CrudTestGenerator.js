/**
 * CrudTestGenerator - Generates CRUD operation tests for API resources.
 * Covers: Create, Read (single + list), Update, Delete operations.
 */

/**
 * Generates CRUD tests based on resource schema.
 * @param {Object} schema - Resource schema with CRUD configuration
 */
function generateCrudTests(schema) {
  const { endpoint, name, namePlural, createValidData, updateData } = schema;

  if (!createValidData) {
    throw new Error(`Schema for ${name} missing 'createValidData' function`);
  }

  describe(`${name} CRUD Operations`, () => {
    let createdId;
    let createdData;

    // === CREATE TESTS ===
    describe('Create', () => {
      test(`creates ${name} successfully`, async () => {
        createdData = createValidData();
        const response = await global.api.apiCall('POST', endpoint, createdData);

        expect(response.status).toBe(201);
        expect(response.data).toHaveProperty('id');

        createdId = response.data.id;
        global.resources.track(namePlural, createdId);
      });

      test(`created ${name} has correct data`, async () => {
        expect(createdId).toBeDefined();

        const response = await global.api.apiCall('GET', `${endpoint}/${createdId}`);
        expect(response.status).toBe(200);

        // Verify key fields match what was sent
        Object.keys(createdData).forEach(key => {
          if (response.data[key] !== undefined) {
            expect(response.data[key]).toEqual(createdData[key]);
          }
        });
      });

      test(`created ${name} has timestamps`, async () => {
        expect(createdId).toBeDefined();

        const response = await global.api.apiCall('GET', `${endpoint}/${createdId}`);
        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('created_at');
        expect(response.data).toHaveProperty('updated_at');
      });

      test('create returns Location header', async () => {
        const data = createValidData('location-test');
        const response = await global.api.apiCall('POST', endpoint, data);

        expect(response.status).toBe(201);
        expect(response.headers).toHaveProperty('location');
        expect(response.headers.location).toContain(endpoint);

        // Cleanup
        if (response.data?.id) {
          global.resources.track(namePlural, response.data.id);
        }
      });
    });

    // === READ TESTS ===
    describe('Read', () => {
      test(`lists ${namePlural}`, async () => {
        const response = await global.api.apiCall('GET', endpoint);

        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('data');
        expect(Array.isArray(response.data.data)).toBe(true);
      });

      test('list response has correct structure', async () => {
        const response = await global.api.apiCall('GET', endpoint);

        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('data');
        expect(response.data).toHaveProperty('total');
        expect(response.data).toHaveProperty('limit');
        expect(response.data).toHaveProperty('offset');
        expect(typeof response.data.total).toBe('number');
      });

      test(`retrieves single ${name}`, async () => {
        expect(createdId).toBeDefined();

        const response = await global.api.apiCall('GET', `${endpoint}/${createdId}`);
        expect(response.status).toBe(200);
        expect(response.data).toHaveProperty('id', createdId);
      });

      test(`returns 404 for non-existent ${name}`, async () => {
        const response = await global.api.apiCall('GET', `${endpoint}/999999`);
        expect(response.status).toBe(404);
      });

      test('404 response follows RFC 9457 format', async () => {
        const response = await global.api.apiCall('GET', `${endpoint}/999999`);
        expect(response.status).toBe(404);
        expect(response.data).toHaveProperty('type');
        expect(response.data).toHaveProperty('title');
        expect(response.data).toHaveProperty('status', 404);
      });
    });

    // === UPDATE TESTS ===
    if (updateData) {
      describe('Update', () => {
        test(`updates ${name} successfully`, async () => {
          expect(createdId).toBeDefined();

          const response = await global.api.apiCall('PUT', `${endpoint}/${createdId}`, updateData);
          expect(response.status).toBe(200);
        });

        test('update persists changes', async () => {
          expect(createdId).toBeDefined();

          const response = await global.api.apiCall('GET', `${endpoint}/${createdId}`);
          expect(response.status).toBe(200);

          // Verify at least first update field persisted
          const firstKey = Object.keys(updateData)[0];
          expect(response.data[firstKey]).toEqual(updateData[firstKey]);
        });

        test('update changes updated_at timestamp', async () => {
          expect(createdId).toBeDefined();

          const beforeResponse = await global.api.apiCall('GET', `${endpoint}/${createdId}`);
          const beforeTimestamp = new Date(beforeResponse.data.updated_at).getTime();

          // Delay to ensure timestamp difference (MySQL has 1-second precision)
          await new Promise(resolve => setTimeout(resolve, 1100));

          // Make another update with fresh data
          const freshData = createValidData('timestamp-test');
          await global.api.apiCall('PUT', `${endpoint}/${createdId}`, freshData);

          const afterResponse = await global.api.apiCall('GET', `${endpoint}/${createdId}`);
          const afterTimestamp = new Date(afterResponse.data.updated_at).getTime();

          expect(afterTimestamp).toBeGreaterThan(beforeTimestamp);
        });

        test(`returns 404 when updating non-existent ${name}`, async () => {
          const response = await global.api.apiCall('PUT', `${endpoint}/999999`, updateData);
          expect(response.status).toBe(404);
        });
      });
    }

    // === DELETE TESTS ===
    describe('Delete', () => {
      test(`deletes ${name} successfully`, async () => {
        // Create fresh resource to delete
        const data = createValidData('delete-test');
        const createResponse = await global.api.apiCall('POST', endpoint, data);
        expect(createResponse.status).toBe(201);

        const deleteId = createResponse.data.id;

        const response = await global.api.apiCall('DELETE', `${endpoint}/${deleteId}`);
        expect(response.status).toBe(204);

        // Verify deletion
        const verifyResponse = await global.api.apiCall('GET', `${endpoint}/${deleteId}`);
        expect(verifyResponse.status).toBe(404);
      });

      test(`returns 404 for non-existent ${name} deletion`, async () => {
        const response = await global.api.apiCall('DELETE', `${endpoint}/999999`);
        expect(response.status).toBe(404);
      });

      test('delete is idempotent (second delete returns 404)', async () => {
        // Create and delete
        const data = createValidData('idempotent-test');
        const createResponse = await global.api.apiCall('POST', endpoint, data);
        const deleteId = createResponse.data.id;

        await global.api.apiCall('DELETE', `${endpoint}/${deleteId}`);

        // Second delete should return 404
        const secondDelete = await global.api.apiCall('DELETE', `${endpoint}/${deleteId}`);
        expect(secondDelete.status).toBe(404);
      });
    });
  });
}

module.exports = { generateCrudTests };
