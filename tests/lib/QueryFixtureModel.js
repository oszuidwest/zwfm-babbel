const contains = (value, term) => value != null && String(value).toLowerCase().includes(term.toLowerCase());
const matchingSearchIDs = (items, fields, term) => items.filter(item => fields.some(field => contains(item[field], term))).map(item => item.id);

// A whole field value is a literal substring term. No other search field may
// match it, or omitting the intended field could go unnoticed.
function isolatedSearchCase(items, fields, field) {
  for (const item of items) {
    const term = item[field] == null ? '' : String(item[field]);
    if (!term || items.some(row => fields.some(other => other !== field && contains(row[other], term)))) continue;
    const ids = matchingSearchIDs(items, fields, term);
    if (ids.length > 0 && ids.length < items.length) return { term, ids };
  }
  throw new Error(`Search fixtures need an isolated non-universal term for ${field}`);
}

// Each filter must remove a different row, and their intersection must be
// nonempty. Ignoring either predicate then changes the exact expected set.
function independentFilters(items, fields) {
  const candidates = fields.flatMap(field => [...new Set(items.map(item => item[field]).filter(value => value != null))]
    .map(value => ({ field, value, keep: row => row[field] != null && row[field] !== value })));
  for (const first of candidates) {
    for (const second of candidates) {
      if (first.field === second.field) continue;
      const kept = items.filter(row => first.keep(row) && second.keep(row));
      if (kept.length && kept.length < items.filter(first.keep).length && kept.length < items.filter(second.keep).length) {
        return { filters: [first, second], ids: kept.map(row => row.id) };
      }
    }
  }
  throw new Error('Query fixtures need two independently selective filter fields');
}

module.exports = { isolatedSearchCase, independentFilters, matchingSearchIDs };
