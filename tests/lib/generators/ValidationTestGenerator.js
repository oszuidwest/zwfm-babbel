/**
 * ValidationTestGenerator - Generates field validation tests for API resources.
 * Covers: required fields, type validation, boundaries, unique constraints.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

/**
 * Generates validation tests based on resource schema.
 * @param {Object} schema - Resource schema with validation configuration
 * @param {Function} [setupFn] - Optional async function to create dependencies, returns object to merge with createValidData.
 *                               Called fresh for tests that create resources (important for unique constraint resources).
 */
function generateValidationTests(schema, setupFn = null) {
  const { endpoint, name, namePlural, createValidData, validation } = schema;

  if (!validation?.fields) {
    throw new Error(`Schema for ${name} missing 'validation.fields' configuration`);
  }

  const { fields } = validation;

  describe(`${name} Validation`, () => {
    // For validation tests that expect rejection (422), we can reuse dependencies
    // For tests that create resources (201), we need fresh dependencies
    let sharedDependencyData = {};

    // Helper to create data with shared dependencies (for rejection tests)
    const createDataWithSharedDeps = (suffix) => ({
      ...createValidData(suffix),
      ...sharedDependencyData
    });

    // Helper to create data with fresh dependencies (for creation tests)
    const createDataWithFreshDeps = async (suffix) => {
      const deps = setupFn ? await setupFn() : {};
      return {
        ...createValidData(suffix),
        ...deps
      };
    };

    beforeAll(async () => {
      // Setup shared dependencies for rejection tests
      if (setupFn) {
        sharedDependencyData = await setupFn();
      }
    });

    // === REQUIRED FIELD TESTS ===
    describe('Required Fields', () => {
      test('when data empty, then returns 422', async () => {
        // Arrange: (none - empty payload to trigger validation)

        // Act
        const response = await global.api.apiCall('POST', endpoint, {});

        // Assert
        expect(response.status).toBe(422);
      });

      Object.entries(fields).forEach(([fieldName, rules]) => {
        if (rules.required) {
          test(`when ${fieldName} missing, then returns 422`, async () => {
            // Arrange
            const data = createDataWithSharedDeps(`missing-${fieldName}`);
            delete data[fieldName];

            // Act
            const response = await global.api.apiCall('POST', endpoint, data);

            // Assert
            expect(response.status).toBe(422);
          });

          test(`when ${fieldName} null, then returns 422`, async () => {
            // Arrange
            const data = createDataWithSharedDeps(`null-${fieldName}`);
            data[fieldName] = null;

            // Act
            const response = await global.api.apiCall('POST', endpoint, data);

            // Assert
            expect(response.status).toBe(422);
          });
        }
      });
    });

    // === STRING FIELD TESTS ===
    const stringFields = Object.entries(fields).filter(([_, rules]) => rules.type === 'string');

    if (stringFields.length > 0) {
      describe('String Field Validation', () => {
        stringFields.forEach(([fieldName, rules]) => {
          if (rules.required) {
            test(`when ${fieldName} empty string, then returns 422`, async () => {
              // Arrange
              const data = createDataWithSharedDeps(`empty-${fieldName}`);
              data[fieldName] = '';

              // Act
              const response = await global.api.apiCall('POST', endpoint, data);

              // Assert
              expect(response.status).toBe(422);
            });
          }

          if (rules.rejectWhitespaceOnly) {
            test(`when ${fieldName} whitespace-only, then returns 422`, async () => {
              // Arrange
              const data = createDataWithSharedDeps(`whitespace-${fieldName}`);
              data[fieldName] = '   ';

              // Act
              const response = await global.api.apiCall('POST', endpoint, data);

              // Assert
              expect(response.status).toBe(422);
            });
          }

          if (rules.maxLength) {
            test(`when ${fieldName} exceeds max length, then returns 422`, async () => {
              // Arrange
              const data = createDataWithSharedDeps(`maxlen-${fieldName}`);
              data[fieldName] = 'A'.repeat(rules.maxLength + 50);

              // Act
              const response = await global.api.apiCall('POST', endpoint, data);

              // Assert
              expect(response.status).toBe(422);
            });
          }

          if (rules.minLength && rules.minLength > 1) {
            test(`when ${fieldName} below min length, then returns 422`, async () => {
              // Arrange
              const data = createDataWithSharedDeps(`minlen-${fieldName}`);
              data[fieldName] = 'A'.repeat(rules.minLength - 1);

              // Act
              const response = await global.api.apiCall('POST', endpoint, data);

              // Assert
              expect(response.status).toBe(422);
            });
          }

          if (rules.pattern) {
            test(`when ${fieldName} invalid pattern, then returns 422`, async () => {
              // Arrange
              const data = createDataWithSharedDeps(`pattern-${fieldName}`);
              data[fieldName] = '!!!invalid!!!';

              // Act
              const response = await global.api.apiCall('POST', endpoint, data);

              // Assert
              expect(response.status).toBe(422);
            });
          }
        });
      });
    }

    // === NUMERIC FIELD TESTS ===
    const numericFields = Object.entries(fields).filter(
      ([_, rules]) => rules.type === 'integer' || rules.type === 'float'
    );

    if (numericFields.length > 0) {
      describe('Numeric Field Validation', () => {
        numericFields.forEach(([fieldName, rules]) => {
          test(`when ${fieldName} is string, then returns 422`, async () => {
            // Arrange
            const data = createDataWithSharedDeps(`string-${fieldName}`);
            data[fieldName] = 'invalid';

            // Act
            const response = await global.api.apiCall('POST', endpoint, data);

            // Assert
            expect(response.status).toBe(422);
          });

          if (rules.min !== undefined) {
            test(`when ${fieldName} below minimum, then returns 422`, async () => {
              // Arrange
              const data = createDataWithSharedDeps(`min-${fieldName}`);
              data[fieldName] = rules.min - 1;

              // Act
              const response = await global.api.apiCall('POST', endpoint, data);

              // Assert
              expect(response.status).toBe(422);
            });

            if (rules.min > 0) {
              test(`when ${fieldName} negative, then returns 422`, async () => {
                // Arrange
                const data = createDataWithSharedDeps(`neg-${fieldName}`);
                data[fieldName] = -1;

                // Act
                const response = await global.api.apiCall('POST', endpoint, data);

                // Assert
                expect(response.status).toBe(422);
              });
            }

            if (rules.min >= 1) {
              test(`when ${fieldName} zero, then returns 422`, async () => {
                // Arrange
                const data = createDataWithSharedDeps(`zero-${fieldName}`);
                data[fieldName] = 0;

                // Act
                const response = await global.api.apiCall('POST', endpoint, data);

                // Assert
                expect(response.status).toBe(422);
              });
            }
          }

          if (rules.max !== undefined) {
            test(`when ${fieldName} above maximum, then returns 422`, async () => {
              // Arrange
              const data = createDataWithSharedDeps(`max-${fieldName}`);
              data[fieldName] = rules.max + 1000;

              // Act
              const response = await global.api.apiCall('POST', endpoint, data);

              // Assert
              expect(response.status).toBe(422);
            });
          }

          if (rules.type === 'integer') {
            test(`when ${fieldName} is float, then returns 422`, async () => {
              // Arrange
              const data = createDataWithSharedDeps(`float-${fieldName}`);
              data[fieldName] = 5.5;

              // Act
              const response = await global.api.apiCall('POST', endpoint, data);

              // Assert
              expect(response.status).toBe(422);
            });
          }
        });
      });
    }

    // === ENUM FIELD TESTS ===
    const enumFields = Object.entries(fields).filter(([_, rules]) => rules.enum);

    if (enumFields.length > 0) {
      describe('Enum Field Validation', () => {
        enumFields.forEach(([fieldName, rules]) => {
          test(`when ${fieldName} invalid enum, then returns 422`, async () => {
            // Arrange
            const data = createDataWithSharedDeps(`invalid-enum-${fieldName}`);
            data[fieldName] = 'definitely_not_a_valid_enum_value';

            // Act
            const response = await global.api.apiCall('POST', endpoint, data);

            // Assert
            expect(response.status).toBe(422);
          });

          if (rules.enum.length > 0) {
            test(`when ${fieldName} valid enum, then accepted`, async () => {
              // Arrange: Use fresh dependencies since this creates a resource
              const data = await createDataWithFreshDeps(`valid-enum-${fieldName}`);
              data[fieldName] = rules.enum[0];

              // Act
              const response = await global.api.apiCall('POST', endpoint, data);

              // Assert
              expect([201, 200]).toContain(response.status);

              // Cleanup
              if (response.status === 201 && response.data?.id) {
                global.resources.track(namePlural, response.data.id);
              }
            });
          }
        });
      });
    }

    // === UNIQUE CONSTRAINT TESTS ===
    const uniqueFields = Object.entries(fields).filter(([_, rules]) => rules.unique);

    if (uniqueFields.length > 0) {
      describe('Unique Constraints', () => {
        uniqueFields.forEach(([fieldName, rules]) => {
          test(`when ${fieldName} duplicate, then returns 409`, async () => {
            // Arrange: Create unique value with fresh dependencies
            const uniqueValue = `unique${Date.now()}${process.pid}`;
            const data = await createDataWithFreshDeps(uniqueValue);
            if (rules.type === 'string') {
              data[fieldName] = uniqueValue;
            }

            // Act: Create first resource
            const first = await global.api.apiCall('POST', endpoint, data);

            // Assert first creation succeeds
            expect(first.status).toBe(201);
            if (first.data?.id) {
              global.resources.track(namePlural, first.data.id);
            }

            // Arrange: Prepare duplicate with fresh dependencies but same unique field
            const duplicateData = await createDataWithFreshDeps(`dup${uniqueValue}`);
            duplicateData[fieldName] = data[fieldName];

            // Act: Try to create duplicate
            const duplicate = await global.api.apiCall('POST', endpoint, duplicateData);

            // Assert
            expect(duplicate.status).toBe(409);
          });
        });
      });
    }

    // === ARRAY FIELD TESTS ===
    const arrayFields = Object.entries(fields).filter(([_, rules]) => rules.type === 'array');

    if (arrayFields.length > 0) {
      describe('Array Field Validation', () => {
        arrayFields.forEach(([fieldName, rules]) => {
          if (rules.required) {
            test(`when ${fieldName} empty array, then returns 422`, async () => {
              // Arrange
              const data = createDataWithSharedDeps(`empty-array-${fieldName}`);
              data[fieldName] = [];

              // Act
              const response = await global.api.apiCall('POST', endpoint, data);

              // Assert
              expect(response.status).toBe(422);
            });
          }

          test(`when ${fieldName} not array, then returns 422`, async () => {
            // Arrange
            const data = createDataWithSharedDeps(`non-array-${fieldName}`);
            data[fieldName] = 'not an array';

            // Act
            const response = await global.api.apiCall('POST', endpoint, data);

            // Assert
            expect(response.status).toBe(422);
          });
        });
      });
    }

    // === RFC 9457 ERROR FORMAT TESTS ===
    describe('Error Response Format', () => {
      test('when validation fails, then error follows RFC 9457', async () => {
        // Arrange: (none - empty payload to trigger validation error)

        // Act
        const response = await global.api.apiCall('POST', endpoint, {});

        // Assert
        expect(response.status).toBe(422);
        expect(response.data).toHaveProperty('type');
        expect(response.data).toHaveProperty('title');
        expect(response.data).toHaveProperty('status', 422);
        expect(response.data).toHaveProperty('instance');
      });
    });
  });
}

module.exports = { generateValidationTests };
