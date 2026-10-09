const fs = require('fs');
const path = require('path');
const YAML = require('yaml');

// Test registration is synchronous, so read the local contract once at import.
const document = YAML.parse(fs.readFileSync(path.join(__dirname, '../../openapi.yaml'), 'utf8'));
const resolve = schema => schema.$ref
  ? resolve(schema.$ref.slice(2).split('/').reduce((node, key) => node[key], document))
  : schema;

function getFilterContracts(endpoint) {
  const parameters = document.paths[`/api/v1${endpoint}`].get.parameters.map(resolve);
  const filter = parameters.find(parameter => parameter.in === 'query' && parameter.name === 'filter');
  return Object.fromEntries(Object.entries(filter.schema.properties).map(([field, schema]) => {
    const variants = resolve(schema).oneOf.map(resolve);
    const operators = variants.find(variant => variant.type === 'object').properties;
    const value = { ...resolve(operators.eq) };
    // Use the first DateTimeValue format to select timestamp examples.
    value.format ??= value.anyOf?.[0]?.format;
    return [field, { value, operators }];
  }));
}

// Returns valid literals; exclusion tests use the last value.
function filterExamples({ value, operators }) {
  if (value.enum) return value.enum.map(String);
  if (value.format === 'date-time') return ['2024-01-01T00:00:00Z', '2024-12-31T23:59:59Z'];
  if (value.format === 'date') return ['2024-01-01', '2024-12-31'];
  if (value.type === 'boolean') return ['false', 'true'];
  if (value.maximum !== undefined) return ['0', '1'];
  return ['1', '999999'];
}

// Returns an invalid literal, or undefined for unrestricted text.
function invalidFilterExample({ value }) {
  if (value.enum) return 'unknown';
  if (value.format === 'date-time') return '2024-01-01T25:00:00Z';
  if (value.format === 'date') return '2024-02-30';
  if (value.type === 'boolean') return 'yes';
  if (value.maximum !== undefined) return String(value.maximum + 1);
  if (value.type === 'number') return 'NaN';
  if (value.type === 'integer') return 'abc';
  return undefined;
}

function invalidFilterCases(contract) {
  const { operators } = contract;
  const [valid] = filterExamples(contract);
  const invalid = invalidFilterExample(contract);
  const cases = [];
  if (invalid !== undefined) {
    cases.push(['eq', invalid]);
    if (operators.in) cases.push(['in', `${valid},${invalid}`]);
    if (operators.between) cases.push(['between', `${valid},${invalid}`]);
    if (operators.band) cases.push(['band', invalid]);
  }
  for (const [operator, raw] of [['like', '1'], ['in', `${valid},${valid}`], ['gte', valid], ['null', 'true']]) {
    if (!operators[operator]) cases.push([operator, raw]);
  }
  return cases;
}

module.exports = { getFilterContracts, filterExamples, invalidFilterCases };
