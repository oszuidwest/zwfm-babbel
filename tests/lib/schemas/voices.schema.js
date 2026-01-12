/**
 * Voice resource schema for test generation.
 */

module.exports = {
  name: 'Voice',
  namePlural: 'voices',
  endpoint: '/voices',

  createValidData: (suffix = '') => ({
    name: `Test Voice ${suffix || Date.now()}_${process.pid}`
  }),

  updateData: {
    name: `Updated Voice ${Date.now()}`
  },

  query: {
    searchFields: ['name'],
    sortableFields: ['id', 'name', 'created_at', 'updated_at'],
    filterableFields: ['id', 'name'],
    numericFields: ['id'],
    selectableFields: ['id', 'name', 'created_at', 'updated_at']
  },

  excludeOnFieldSelect: [],

  validation: {
    fields: {
      name: {
        type: 'string',
        required: true,
        minLength: 1,
        maxLength: 255,
        unique: true,
        rejectWhitespaceOnly: true
      }
    }
  }
};
