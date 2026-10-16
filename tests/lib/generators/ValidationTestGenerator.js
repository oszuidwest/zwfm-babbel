const { getJsonRequestSchema } = require('../QueryFilterContract');

/**
 * Generates validation tests from the OpenAPI request contract. Resource
 * schemas provide fixtures only; bounds and choices have one source of truth.
 * @param {Object} schema
 * @param {Function|null} [setupFn]
 */
function generateValidationTests(schema, setupFn = null) {
  const { endpoint, name, namePlural, createValidData } = schema;
  const requestSchema = getJsonRequestSchema(endpoint);
  const required = new Set(requestSchema.required ?? []);
  const fields = Object.fromEntries(Object.entries(requestSchema.properties ?? {}).map(([field, contract]) => {
    const type = Array.isArray(contract.type) ? contract.type.find(value => value !== 'null') : contract.type;
    return [field, {
      type: type === 'number' ? 'float' : type,
      required: required.has(field),
      min: contract.minimum,
      max: contract.maximum,
      minLength: contract.minLength,
      maxLength: contract.maxLength,
      enum: contract.enum,
      pattern: contract.pattern,
      format: contract.format,
      unique: contract['x-unique'] === true
    }];
  }));

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
      expect(response.status).toBe(status);
      return response;
    };
    // Rejections name the field; code is asserted where the rule is unambiguous.
    const rejectCase = (title, suffix, mutate, { field, code } = {}) => test(title, async () => {
      const response = await expectPostStatus(withSharedDeps(suffix, mutate), 422);
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
            [rules.maxLength && rules.format !== 'email', 'exceeds max length', `maxlen-${fieldName}`, () => 'A'.repeat(rules.maxLength + 50), 'too_long'],
            [rules.minLength && rules.minLength > 1, 'below min length', `minlen-${fieldName}`, () => 'A'.repeat(rules.minLength - 1), 'too_short'],
            [rules.pattern, 'violates pattern', `pattern-${fieldName}`, rules.pattern === '\\S' ? '   ' : '!!!invalid!!!', rules.pattern === '\\S' ? 'blank' : 'invalid_format'],
            [rules.format === 'email', 'has invalid email format', `format-${fieldName}`, 'not-an-email', 'invalid_format']
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
          const rangeError = { field: fieldName, code: 'out_of_range' };
          const cases = [];
          if (rules.min !== undefined) {
            cases.push(['below minimum', `min-${fieldName}`, rules.min - 1, rangeError]);
          }
          if (rules.max !== undefined) cases.push(['above maximum', `max-${fieldName}`, rules.max + 1000, rangeError]);

          cases.forEach(([label, suffix, value, expected]) => {
            rejectCase(`when ${fieldName} ${label}, then returns 422`, suffix,
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
            const duplicate = await expectPostStatus(duplicateData, 409);
            expect(duplicate.data.code).toBe(`${name.toLowerCase()}.duplicate`);
          });
        });
      });
    }
  });
}

module.exports = { generateValidationTests };
