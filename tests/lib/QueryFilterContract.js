const fs = require('fs');
const path = require('path');
const YAML = require('yaml');

// Test registration is synchronous, so read the local contract once at import.
const document = YAML.parse(fs.readFileSync(path.join(__dirname, '../../openapi.yaml'), 'utf8'));
const resolve = schema => schema.$ref
  ? resolve(schema.$ref.slice(2).split('/').reduce((node, key) => node[key], document))
  : schema;

const queryParameter = (endpoint, name) => document.paths[`/api/v1${endpoint}`].get.parameters
  .map(resolve)
  .find(parameter => parameter.in === 'query' && parameter.name === name);

const declaresQueryParameter = (endpoint, name) => queryParameter(endpoint, name) !== undefined;

function getFilterContracts(endpoint) {
  const filter = queryParameter(endpoint, 'filter');
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
function filterExamples({ value }) {
  if (value.enum) return value.enum.map(String);
  if (value.format === 'date-time') return ['2024-01-01T00:00:00Z', '2024-12-31T23:59:59Z'];
  if (value.format === 'date') return ['2024-01-01', '2024-12-31'];
  if (value.type === 'boolean') return ['false', 'true'];
  if (value.maximum !== undefined) return ['0', '1'];
  return ['1', '999999'];
}

// Other accepted DateTimeValue spellings, sent with eq only: in and between
// split on commas, which would cut the comma fraction. The positive offset
// only arrives intact when the caller URL-encodes its plus sign.
const dateTimeSpellings = [
  '2024-01-01T01:00:00+01:00',
  '2024-01-01T00:00:00.5Z',
  '2024-01-01 00:00:00',
  '2024-01-01 00:00:00.5',
  '2024-01-01 00:00:00,5',
  '2024-01-01'
];

// Values a mapping stricter than the documented type would reject: a
// fraction for numbers, the maximum for bounded integers, and the other
// date-time spellings.
function boundaryValues({ value }) {
  if (value.type === 'number') return ['1.5'];
  if (value.maximum !== undefined) return [String(value.maximum)];
  if (value.format === 'date-time') return dateTimeSpellings;
  return [];
}

// Returns [operator, raw] pairs covering implicit equality ('') and every
// documented operator, alias, and null value, plus each boundary value with
// eq. Callers must URL-encode raw.
function validFilterCases(contract) {
  const examples = filterExamples(contract);
  const [first] = examples;
  const cases = [['', first]];
  for (const operator of Object.keys(contract.operators)) {
    if (operator === 'null') cases.push(['null', 'true'], ['null', 'false']);
    else if (operator === 'in') cases.push(['in', examples.join(',')]);
    else if (operator === 'between') cases.push(['between', `${first},${examples.at(-1)}`]);
    else cases.push([operator, first]);
  }
  for (const value of boundaryValues(contract)) cases.push(['eq', value]);
  return cases;
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

module.exports = { declaresQueryParameter, getFilterContracts, filterExamples, validFilterCases, invalidFilterCases };
