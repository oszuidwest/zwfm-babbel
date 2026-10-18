/**
 * Models a sort field mapped to the wrong column. With field mapped to
 * column, a sort test on field gets the rows in column order and checks the
 * field keys. Rows that tie on the column may come back in any order, so the
 * test only fails for sure when two rows are discordant: the column puts one
 * strictly first and the field puts it strictly last. Without such a pair,
 * both directions can pass.
 *
 * @param {Object<string, number[]>} keysByField Numeric sort keys per field,
 *   one per row, with the rows in the same order for every field.
 * @returns {Array<[string, string]>} [field, column] pairs no sort test is
 *   sure to notice.
 */
function unnoticedSortMappings(keysByField) {
  const fields = Object.keys(keysByField);
  const discordant = (a, b) => a.some((_, i) => a.some((_, j) => a[i] < a[j] && b[i] > b[j]));
  return fields.flatMap(field => fields
    .filter(column => column !== field && !discordant(keysByField[column], keysByField[field]))
    .map(column => [field, column]));
}

module.exports = { unnoticedSortMappings };
