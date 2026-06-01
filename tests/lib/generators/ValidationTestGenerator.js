/**
 * ValidationTestGenerator - Generates field validation tests for API resources.
 * Covers required fields, type validation, boundaries, enum values, unique
 * constraints, array fields, and RFC 9457 error shape.
 */

/**
 * Generates validation tests based on resource schema.
 * @param {Object} schema - Resource schema with validation configuration.
 * @param {Function} [setupFn] - Optional async dependency factory for resources
 *                               with foreign-key requirements.
 */
function generateValidationTests(schema, setupFn = null) {
  const { endpoint, name, namePlural, createValidData, validation } = schema;
  if (!validation?.fields) throw new Error(`Schema for ${name} missing 'validation.fields' configuration`);

  const { fields } = validation;

  describe(`${name} Validation`, () => {
    let sharedDependencyData = {};

    // Rejection tests can reuse dependencies because they should not create rows.
    const withSharedDeps = (suffix, mutate = () => {}) => {
      const data = { ...createValidData(suffix), ...sharedDependencyData };
      mutate(data);
      return data;
    };

    // Successful creation cases need fresh dependencies to avoid uniqueness and
    // foreign-key side effects between generated scenarios.
    const withFreshDeps = async (suffix, mutate = () => {}) => {
      const data = { ...createValidData(suffix), ...(setupFn ? await setupFn() : {}) };
      mutate(data);
      return data;
    };
    const expectPostStatus = async (data, status) => {
      const response = await global.api.apiCall('POST', endpoint, data);
      if (Array.isArray(status)) {
        expect(status).toContain(response.status);
      } else {
        expect(response.status).toBe(status);
      }
      return response;
    };
    const rejectCase = (title, suffix, mutate) => test(title, async () => {
      await expectPostStatus(withSharedDeps(suffix, mutate), 422);
    });

    beforeAll(async () => {
      if (setupFn) sharedDependencyData = await setupFn();
    });

    // Required fields are checked generically from the schema.
    describe('Required Fields', () => {
      test('when data empty, then returns 422', async () => {
        await expectPostStatus({}, 422);
      });

      Object.entries(fields).forEach(([fieldName, rules]) => {
        if (!rules.required) return;
        rejectCase(`when ${fieldName} missing, then returns 422`, `missing-${fieldName}`, data => delete data[fieldName]);
        rejectCase(`when ${fieldName} null, then returns 422`, `null-${fieldName}`, data => { data[fieldName] = null; });
      });
    });

    const stringFields = Object.entries(fields).filter(([_, rules]) => rules.type === 'string');
    if (stringFields.length > 0) {
      // String rules cover emptiness, length, whitespace, and pattern validation.
      describe('String Field Validation', () => {
        stringFields.forEach(([fieldName, rules]) => {
          [
            [rules.required, 'empty string', `empty-${fieldName}`, ''],
            [rules.rejectWhitespaceOnly, 'whitespace-only', `whitespace-${fieldName}`, '   '],
            [rules.maxLength, 'exceeds max length', `maxlen-${fieldName}`, () => 'A'.repeat(rules.maxLength + 50)],
            [rules.minLength && rules.minLength > 1, 'below min length', `minlen-${fieldName}`, () => 'A'.repeat(rules.minLength - 1)],
            [rules.pattern, 'invalid pattern', `pattern-${fieldName}`, '!!!invalid!!!']
          ].filter(([enabled]) => enabled).forEach(([, label, suffix, value]) => {
            rejectCase(`when ${fieldName} ${label}, then returns 422`, suffix, data => {
              data[fieldName] = typeof value === 'function' ? value() : value;
            });
          });
        });
      });
    }

    const numericFields = Object.entries(fields).filter(
      ([_, rules]) => rules.type === 'integer' || rules.type === 'float'
    );
    if (numericFields.length > 0) {
      // Numeric rules cover type checks and configured min/max boundaries.
      describe('Numeric Field Validation', () => {
        numericFields.forEach(([fieldName, rules]) => {
          const cases = [[true, 'is string', `string-${fieldName}`, 'invalid']];
          if (rules.min !== undefined) {
            cases.push([true, 'below minimum', `min-${fieldName}`, rules.min - 1]);
            if (rules.min > 0) cases.push([true, 'negative', `neg-${fieldName}`, -1]);
            if (rules.min >= 1) cases.push([true, 'zero', `zero-${fieldName}`, 0]);
          }
          if (rules.max !== undefined) cases.push([true, 'above maximum', `max-${fieldName}`, rules.max + 1000]);
          if (rules.type === 'integer') cases.push([true, 'is float', `float-${fieldName}`, 5.5]);

          cases.forEach(([, label, suffix, value]) => {
            rejectCase(`when ${fieldName} ${label}, then returns 422`, suffix, data => { data[fieldName] = value; });
          });
        });
      });
    }

    const enumFields = Object.entries(fields).filter(([_, rules]) => rules.enum);
    if (enumFields.length > 0) {
      // Enum tests include one valid creation path so accepted values are verified.
      describe('Enum Field Validation', () => {
        enumFields.forEach(([fieldName, rules]) => {
          rejectCase(`when ${fieldName} invalid enum, then returns 422`, `invalid-enum-${fieldName}`, data => {
            data[fieldName] = 'definitely_not_a_valid_enum_value';
          });

          if (rules.enum.length > 0) {
            test(`when ${fieldName} valid enum, then accepted`, async () => {
              const response = await expectPostStatus(
                await withFreshDeps(`valid-enum-${fieldName}`, data => { data[fieldName] = rules.enum[0]; }),
                [201, 200]
              );
              if (response.status === 201 && response.data?.id) global.resources.track(namePlural, response.data.id);
            });
          }
        });
      });
    }

    const uniqueFields = Object.entries(fields).filter(([_, rules]) => rules.unique);
    if (uniqueFields.length > 0) {
      // Unique constraints require a real first insert followed by a duplicate.
      describe('Unique Constraints', () => {
        uniqueFields.forEach(([fieldName, rules]) => {
          test(`when ${fieldName} duplicate, then returns 409`, async () => {
            const uniqueValue = `unique${Date.now()}${process.pid}`;
            const data = await withFreshDeps(uniqueValue, item => {
              if (rules.type === 'string') item[fieldName] = uniqueValue;
            });
            const first = await expectPostStatus(data, 201);
            if (first.data?.id) global.resources.track(namePlural, first.data.id);

            const duplicateData = await withFreshDeps(`dup${uniqueValue}`, item => { item[fieldName] = data[fieldName]; });
            await expectPostStatus(duplicateData, 409);
          });
        });
      });
    }

    const arrayFields = Object.entries(fields).filter(([_, rules]) => rules.type === 'array');
    if (arrayFields.length > 0) {
      // Array tests verify both required non-empty arrays and type validation.
      describe('Array Field Validation', () => {
        arrayFields.forEach(([fieldName, rules]) => {
          if (rules.required) {
            rejectCase(`when ${fieldName} empty array, then returns 422`, `empty-array-${fieldName}`, data => { data[fieldName] = []; });
          }
          rejectCase(`when ${fieldName} not array, then returns 422`, `non-array-${fieldName}`, data => { data[fieldName] = 'not an array'; });
        });
      });
    }

    describe('Error Response Format', () => {
      test('when validation fails, then error follows RFC 9457', async () => {
        const response = await expectPostStatus({}, 422);
        expect(response.data).toHaveProperty('type');
        expect(response.data).toHaveProperty('title');
        expect(response.data).toHaveProperty('status', 422);
        expect(response.data).toHaveProperty('instance');
      });
    });
  });
}

module.exports = { generateValidationTests };
