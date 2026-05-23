const fs = require('fs');
const path = require('path');
const SwaggerParser = require('@apidevtools/swagger-parser');
const Ajv2020 = require('ajv/dist/2020');
const addFormats = require('ajv-formats');
const YAML = require('yaml');

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'trace']);
const JSON_MEDIA_TYPES = new Set(['application/json', 'application/problem+json']);

class OpenApiContractValidator {
  constructor(document) {
    this.document = document;
    this.ajv = new Ajv2020({
      allErrors: true,
      allowUnionTypes: true,
      strict: false,
      validateFormats: true
    });
    addFormats(this.ajv);
    this.addOpenApiFormats();
    this.compiledSchemas = new WeakMap();
  }

  static async fromFile(specPath) {
    const absolutePath = path.resolve(specPath);
    const raw = fs.readFileSync(absolutePath, 'utf8');
    const parsed = YAML.parse(raw);

    await SwaggerParser.validate(parsed);
    const dereferenced = await SwaggerParser.dereference(parsed);

    return new OpenApiContractValidator(dereferenced);
  }

  addOpenApiFormats() {
    for (const format of ['binary', 'byte', 'password', 'int32', 'int64', 'float', 'double']) {
      this.ajv.addFormat(format, true);
    }
  }

  getOperationKeys() {
    const keys = [];
    for (const [operationPath, pathItem] of Object.entries(this.document.paths || {})) {
      for (const [method, operation] of Object.entries(pathItem || {})) {
        if (HTTP_METHODS.has(method) && operation) {
          keys.push(this.operationKey(method, operationPath));
        }
      }
    }
    return keys.sort();
  }

  operationKey(method, operationPath) {
    return `${method.toUpperCase()} ${operationPath}`;
  }

  validateRequest({ method, operationPath, body, mediaType = 'application/json' }) {
    const operation = this.getOperation(method, operationPath);
    const requestBody = operation.requestBody;
    if (!requestBody) {
      if (body !== undefined) {
        throw new Error(`${this.operationKey(method, operationPath)} does not define a request body`);
      }
      return;
    }

    if (body === undefined) {
      if (requestBody.required) {
        throw new Error(`${this.operationKey(method, operationPath)} requires a request body`);
      }
      return;
    }

    const content = requestBody.content || {};
    const normalizedMediaType = this.normalizeMediaType(mediaType);
    const mediaSpec = this.findMediaTypeSpec(content, normalizedMediaType);
    if (!mediaSpec) {
      throw new Error(
        `${this.operationKey(method, operationPath)} does not accept ${normalizedMediaType}; accepts ${Object.keys(content).join(', ')}`
      );
    }

    if (mediaSpec.schema) {
      this.validateSchema(
        `${this.operationKey(method, operationPath)} request ${normalizedMediaType}`,
        mediaSpec.schema,
        body
      );
    }
  }

  validateResponse({ method, operationPath, response }) {
    const operation = this.getOperation(method, operationPath);
    const responseSpec = this.getResponseSpec(operation, response.status);
    if (!responseSpec) {
      throw new Error(
        `${this.operationKey(method, operationPath)} returned undeclared status ${response.status}; declared ${Object.keys(operation.responses || {}).join(', ')}`
      );
    }

    this.validateHeaders(method, operationPath, responseSpec, response);

    const content = responseSpec.content || {};
    const contentTypes = Object.keys(content);
    if (contentTypes.length === 0) {
      return;
    }

    const actualMediaType = this.normalizeMediaType(response.headers?.['content-type'] || '');
    const mediaSpec = this.findMediaTypeSpec(content, actualMediaType);
    if (!mediaSpec) {
      throw new Error(
        `${this.operationKey(method, operationPath)} ${response.status} returned content-type ${actualMediaType || '<missing>'}; expected one of ${contentTypes.join(', ')}`
      );
    }

    if (!mediaSpec.schema || actualMediaType === 'audio/wav') {
      return;
    }

    const label = `${this.operationKey(method, operationPath)} response ${response.status} ${actualMediaType}`;
    const body = this.responseBodyForSchema(label, actualMediaType, response.data);
    this.validateSchema(
      label,
      mediaSpec.schema,
      body
    );
  }

  validateHeaders(method, operationPath, responseSpec, response) {
    const headers = responseSpec.headers || {};
    for (const [headerName, headerSpec] of Object.entries(headers)) {
      if (headerName.toLowerCase() === 'content-type') {
        continue;
      }

      const actual = response.headers?.[headerName.toLowerCase()];
      if (actual === undefined) {
        throw new Error(`${this.operationKey(method, operationPath)} missing response header ${headerName}`);
      }

      if (headerSpec.schema) {
        const value = Array.isArray(actual) ? actual[0] : actual;
        this.validateSchema(
          `${this.operationKey(method, operationPath)} header ${headerName}`,
          headerSpec.schema,
          this.coerceHeaderValue(`${this.operationKey(method, operationPath)} header ${headerName}`, headerSpec.schema, value)
        );
      }
    }
  }

  coerceHeaderValue(label, schema, value) {
    if (schema.type === 'integer') {
      if (!/^-?\d+$/.test(String(value))) {
        throw new Error(`${label} has invalid integer value ${JSON.stringify(value)}`);
      }
      const coerced = Number.parseInt(value, 10);
      if (Number.isNaN(coerced)) {
        throw new Error(`${label} has invalid integer value ${JSON.stringify(value)}`);
      }
      return coerced;
    }
    if (schema.type === 'number') {
      const coerced = Number(value);
      if (!Number.isFinite(coerced)) {
        throw new Error(`${label} has invalid number value ${JSON.stringify(value)}`);
      }
      return coerced;
    }
    if (schema.type === 'boolean') {
      if (value === true || value === 'true') {
        return true;
      }
      if (value === false || value === 'false') {
        return false;
      }
      throw new Error(`${label} has invalid boolean value ${JSON.stringify(value)}`);
    }
    return String(value);
  }

  responseBodyForSchema(label, mediaType, data) {
    if (!JSON_MEDIA_TYPES.has(mediaType)) {
      return data;
    }

    try {
      if (Buffer.isBuffer(data)) {
        return JSON.parse(data.toString('utf8'));
      }
      if (typeof data === 'string') {
        return JSON.parse(data);
      }
    } catch (error) {
      throw new Error(`${label} contains invalid JSON: ${error.message}`);
    }
    return data;
  }

  getOperation(method, operationPath) {
    const normalizedMethod = method.toLowerCase();
    const operation = this.document.paths?.[operationPath]?.[normalizedMethod];
    if (!operation) {
      throw new Error(`OpenAPI operation not found: ${this.operationKey(method, operationPath)}`);
    }
    return operation;
  }

  getResponseSpec(operation, status) {
    const responses = operation.responses || {};
    const statusKey = String(status);
    return responses[statusKey] || responses[`${statusKey[0]}XX`] || responses.default;
  }

  findMediaTypeSpec(content, actualMediaType) {
    if (content[actualMediaType]) {
      return content[actualMediaType];
    }

    for (const [mediaType, spec] of Object.entries(content)) {
      if (mediaType.endsWith('/*') && actualMediaType.startsWith(mediaType.slice(0, -1))) {
        return spec;
      }
    }

    return null;
  }

  normalizeMediaType(contentType) {
    return String(contentType).split(';', 1)[0].trim().toLowerCase();
  }

  validateSchema(label, schema, data) {
    const validate = this.compileSchema(label, schema);
    if (validate(data)) {
      return;
    }

    throw new Error(`${label} does not match schema:\n${this.ajv.errorsText(validate.errors, { separator: '\n' })}`);
  }

  compileSchema(label, schema) {
    if (!schema || typeof schema !== 'object') {
      return this.ajv.compile(schema);
    }

    if (!this.compiledSchemas.has(schema)) {
      this.compiledSchemas.set(schema, this.ajv.compile(schema));
    }
    return this.compiledSchemas.get(schema);
  }
}

module.exports = OpenApiContractValidator;
