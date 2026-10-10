/**
 * Generates validation contract tests from a resource schema.
 * @param {Object} schema
 * @param {Function|null} [setupFn]
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
    // Prefer a single expected status. Pass an array only when an endpoint is
    // intentionally allowed to return one of several statuses.
    const expectPostStatus = async (data, status) => {
      const response = await global.api.apiCall('POST', endpoint, data);
      if (Array.isArray(status)) {
        expect(status).toContain(response.status);
      } else {
        expect(response.status).toBe(status);
      }
      return response;
    };
    // Rejections name the field; code is asserted where the rule is unambiguous.
    // Wrong JSON types are 400; rejected values are 422.
    const rejectCase = (title, suffix, mutate, { field, code, status = 422 } = {}) => test(title, async () => {
      const response = await expectPostStatus(withSharedDeps(suffix, mutate), status);
      if (field) {
        expect(response.data.errors).toEqual(expect.arrayContaining([
          expect.objectContaining(code ? { field, code } : { field })
        ]));
      }
    });

    beforeAll(async () => {
      if (setupFn) sharedDependencyData = await setupFn();
    });

    describe('Required Fields', () => {
      test('when data empty, then returns 422', async () => {
        await expectPostStatus({}, 422);
      });

      Object.entries(fields).forEach(([fieldName, rules]) => {
        if (!rules.required) return;
        rejectCase(`when ${fieldName} missing, then returns 422`, `missing-${fieldName}`, data => delete data[fieldName],
          { field: fieldName, code: 'required' });
        rejectCase(`when ${fieldName} null, then returns 422`, `null-${fieldName}`, data => { data[fieldName] = null; },
          { field: fieldName });
      });
    });

    const stringFields = Object.entries(fields).filter(([_, rules]) => rules.type === 'string');
    if (stringFields.length > 0) {
      describe('String Field Validation', () => {
        stringFields.forEach(([fieldName, rules]) => {
          [
            [rules.required, 'empty string', `empty-${fieldName}`, ''],
            [rules.rejectWhitespaceOnly, 'whitespace-only', `whitespace-${fieldName}`, '   '],
            [rules.maxLength, 'exceeds max length', `maxlen-${fieldName}`, () => 'A'.repeat(rules.maxLength + 50), 'too_long'],
            [rules.minLength && rules.minLength > 1, 'below min length', `minlen-${fieldName}`, () => 'A'.repeat(rules.minLength - 1), 'too_short'],
            [rules.pattern, 'invalid pattern', `pattern-${fieldName}`, '!!!invalid!!!']
          ].filter(([enabled]) => enabled).forEach(([, label, suffix, value, code]) => {
            rejectCase(`when ${fieldName} ${label}, then returns 422`, suffix, data => {
              data[fieldName] = typeof value === 'function' ? value() : value;
            }, { field: fieldName, code });
          });
        });
      });
    }

    const numericFields = Object.entries(fields).filter(
      ([_, rules]) => rules.type === 'integer' || rules.type === 'float'
    );
    if (numericFields.length > 0) {
      describe('Numeric Field Validation', () => {
        numericFields.forEach(([fieldName, rules]) => {
          const typeError = { field: fieldName, code: 'invalid_type', status: 400 };
          const rangeError = { field: fieldName, code: 'out_of_range' };
          const cases = [['is string', `string-${fieldName}`, 'invalid', typeError]];
          if (rules.min !== undefined) {
            cases.push(['below minimum', `min-${fieldName}`, rules.min - 1, rangeError]);
            if (rules.min > 0) cases.push(['negative', `neg-${fieldName}`, -1, rangeError]);
            if (rules.min >= 1) cases.push(['zero', `zero-${fieldName}`, 0, rangeError]);
          }
          if (rules.max !== undefined) cases.push(['above maximum', `max-${fieldName}`, rules.max + 1000, rangeError]);
          if (rules.type === 'integer') cases.push(['is float', `float-${fieldName}`, 5.5, typeError]);

          cases.forEach(([label, suffix, value, expected]) => {
            rejectCase(`when ${fieldName} ${label}, then returns ${expected.status ?? 422}`, suffix,
              data => { data[fieldName] = value; }, expected);
          });
        });
      });
    }

    const enumFields = Object.entries(fields).filter(([_, rules]) => rules.enum);
    if (enumFields.length > 0) {
      describe('Enum Field Validation', () => {
        enumFields.forEach(([fieldName, rules]) => {
          rejectCase(`when ${fieldName} invalid enum, then returns 422`, `invalid-enum-${fieldName}`, data => {
            data[fieldName] = 'definitely_not_a_valid_enum_value';
          }, { field: fieldName, code: 'invalid_choice' });

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
