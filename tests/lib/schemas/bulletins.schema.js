module.exports = {
  name: 'Bulletin',
  namePlural: 'bulletins',
  endpoint: '/bulletins',

  // Bulletins are generated through a station endpoint.
  createValidData: null,

  updateData: null,

  query: {
    searchFields: [],
    sortableFields: ['id', 'station_id', 'created_at'],
    filterableFields: ['id', 'station_id'],
    numericFields: ['id', 'station_id'],
    selectableFields: ['id', 'station_id', 'created_at']
  },

  validation: null
};
