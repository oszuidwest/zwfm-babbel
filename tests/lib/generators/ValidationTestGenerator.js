/**
 * ValidationTestGenerator - Generates field validation tests for API resources.
 * Covers: required fields, type validation, boundaries, unique constraints.
 */

/**
 * Generates validation tests based on resource schema.
 * @param {Object} schema - Resource schema with validation configuration
 */
function generateValidationTests(schema) {
  const { endpoint, name, namePlural, createValidData, validation } = schema;

  if (!validation?.fields) {
    throw new Error(`Schema for ${name} missing 'validation.fields' configuration`);
  }

  const { fields } = validation;

  describe(`${name} Validation`, () => {
    // === REQUIRED FIELD TESTS ===
    describe('Required Fields', () => {
      test('rejects empty data', async () => {
        const response = await global.api.apiCall('POST', endpoint, {});
        expect(response.status).toBe(422);
      });

      Object.entries(fields).forEach(([fieldName, rules]) => {
        if (rules.required) {
          test(`rejects missing ${fieldName}`, async () => {
            const data = createValidData(`missing-${fieldName}`);
            delete data[fieldName];

            const response = await global.api.apiCall('POST', endpoint, data);
            expect(response.status).toBe(422);
          });

          test(`rejects null ${fieldName}`, async () => {
            const data = createValidData(`null-${fieldName}`);
            data[fieldName] = null;

            const response = await global.api.apiCall('POST', endpoint, data);
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
            test(`rejects empty string ${fieldName}`, async () => {
              const data = createValidData(`empty-${fieldName}`);
              data[fieldName] = '';

              const response = await global.api.apiCall('POST', endpoint, data);
              expect(response.status).toBe(422);
            });
          }

          if (rules.rejectWhitespaceOnly) {
            test(`rejects whitespace-only ${fieldName}`, async () => {
              const data = createValidData(`whitespace-${fieldName}`);
              data[fieldName] = '   ';

              const response = await global.api.apiCall('POST', endpoint, data);
              expect(response.status).toBe(422);
            });
          }

          if (rules.maxLength) {
            test(`rejects ${fieldName} exceeding max length (${rules.maxLength})`, async () => {
              const data = createValidData(`maxlen-${fieldName}`);
              data[fieldName] = 'A'.repeat(rules.maxLength + 50);

              const response = await global.api.apiCall('POST', endpoint, data);
              expect(response.status).toBe(422);
            });
          }

          if (rules.minLength && rules.minLength > 1) {
            test(`rejects ${fieldName} below min length (${rules.minLength})`, async () => {
              const data = createValidData(`minlen-${fieldName}`);
              data[fieldName] = 'A'.repeat(rules.minLength - 1);

              const response = await global.api.apiCall('POST', endpoint, data);
              expect(response.status).toBe(422);
            });
          }

          if (rules.pattern) {
            test(`rejects ${fieldName} not matching pattern`, async () => {
              const data = createValidData(`pattern-${fieldName}`);
              data[fieldName] = '!!!invalid!!!';

              const response = await global.api.apiCall('POST', endpoint, data);
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
          test(`rejects string ${fieldName}`, async () => {
            const data = createValidData(`string-${fieldName}`);
            data[fieldName] = 'invalid';

            const response = await global.api.apiCall('POST', endpoint, data);
            expect(response.status).toBe(422);
          });

          if (rules.min !== undefined) {
            test(`rejects ${fieldName} below minimum (${rules.min})`, async () => {
              const data = createValidData(`min-${fieldName}`);
              data[fieldName] = rules.min - 1;

              const response = await global.api.apiCall('POST', endpoint, data);
              expect(response.status).toBe(422);
            });

            if (rules.min > 0) {
              test(`rejects negative ${fieldName}`, async () => {
                const data = createValidData(`neg-${fieldName}`);
                data[fieldName] = -1;

                const response = await global.api.apiCall('POST', endpoint, data);
                expect(response.status).toBe(422);
              });
            }

            if (rules.min >= 1) {
              test(`rejects zero ${fieldName}`, async () => {
                const data = createValidData(`zero-${fieldName}`);
                data[fieldName] = 0;

                const response = await global.api.apiCall('POST', endpoint, data);
                expect(response.status).toBe(422);
              });
            }
          }

          if (rules.max !== undefined) {
            test(`rejects ${fieldName} above maximum (${rules.max})`, async () => {
              const data = createValidData(`max-${fieldName}`);
              data[fieldName] = rules.max + 1000;

              const response = await global.api.apiCall('POST', endpoint, data);
              expect(response.status).toBe(422);
            });
          }

          if (rules.type === 'integer') {
            test(`rejects float ${fieldName}`, async () => {
              const data = createValidData(`float-${fieldName}`);
              data[fieldName] = 5.5;

              const response = await global.api.apiCall('POST', endpoint, data);
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
          test(`rejects invalid ${fieldName} value`, async () => {
            const data = createValidData(`invalid-enum-${fieldName}`);
            data[fieldName] = 'definitely_not_a_valid_enum_value';

            const response = await global.api.apiCall('POST', endpoint, data);
            expect(response.status).toBe(422);
          });

          if (rules.enum.length > 0) {
            test(`accepts valid ${fieldName} value: ${rules.enum[0]}`, async () => {
              const data = createValidData(`valid-enum-${fieldName}`);
              data[fieldName] = rules.enum[0];

              const response = await global.api.apiCall('POST', endpoint, data);
              expect([201, 200]).toContain(response.status);

              // Cleanup if created
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
          test(`rejects duplicate ${fieldName}`, async () => {
            // Use alphanumeric-only values to support fields with pattern restrictions
            const uniqueValue = `unique${Date.now()}${process.pid}`;
            const data = createValidData(uniqueValue);

            // Ensure the unique field has the unique value
            if (rules.type === 'string') {
              data[fieldName] = uniqueValue;
            }

            // Create first
            const first = await global.api.apiCall('POST', endpoint, data);
            expect(first.status).toBe(201);

            if (first.data?.id) {
              global.resources.track(namePlural, first.data.id);
            }

            // Try duplicate with same unique field value
            const duplicateData = createValidData(`dup${uniqueValue}`);
            duplicateData[fieldName] = data[fieldName];

            const duplicate = await global.api.apiCall('POST', endpoint, duplicateData);
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
            test(`rejects empty array ${fieldName}`, async () => {
              const data = createValidData(`empty-array-${fieldName}`);
              data[fieldName] = [];

              const response = await global.api.apiCall('POST', endpoint, data);
              expect(response.status).toBe(422);
            });
          }

          test(`rejects non-array ${fieldName}`, async () => {
            const data = createValidData(`non-array-${fieldName}`);
            data[fieldName] = 'not an array';

            const response = await global.api.apiCall('POST', endpoint, data);
            expect(response.status).toBe(422);
          });
        });
      });
    }

    // === RFC 9457 ERROR FORMAT TESTS ===
    describe('Error Response Format', () => {
      test('validation errors follow RFC 9457 format', async () => {
        const response = await global.api.apiCall('POST', endpoint, {});

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
