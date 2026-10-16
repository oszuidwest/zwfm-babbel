module.exports = {
  name: 'Voice',
  namePlural: 'voices',
  endpoint: '/voices',

  createValidData: (suffix = '') => ({
    name: `Test Voice ${suffix || Date.now()}_${process.pid}`
  }),

  updateData: () => ({
    name: `Updated Voice ${Date.now()}`
  }),

  query: {
    searchFields: ['name'],
    sortableFields: ['id', 'name', 'created_at', 'updated_at'],
    filterableFields: ['id', 'name'],
    selectableFields: ['id', 'name', 'created_at', 'updated_at']
  }
};
