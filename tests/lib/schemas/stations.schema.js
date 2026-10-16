module.exports = {
  name: 'Station',
  namePlural: 'stations',
  endpoint: '/stations',

  createValidData: (suffix = '') => ({
    name: `Test Station ${suffix || Date.now()}_${process.pid}`,
    max_stories_per_block: 5,
    pause_seconds: 2.0
  }),

  updateData: () => ({
    name: `Updated Station ${Date.now()}`,
    max_stories_per_block: 7,
    pause_seconds: 3.0
  }),

  query: {
    searchFields: ['name'],
    sortableFields: ['id', 'name', 'max_stories_per_block', 'pause_seconds', 'created_at', 'updated_at'],
    filterableFields: ['id', 'name', 'max_stories_per_block', 'pause_seconds'],
    selectableFields: ['id', 'name', 'max_stories_per_block', 'pause_seconds', 'created_at', 'updated_at']
  }
};
