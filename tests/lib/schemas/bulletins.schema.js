module.exports = {
  name: 'Bulletin',
  namePlural: 'bulletins',
  endpoint: '/bulletins',

  // Bulletins are generated through a station endpoint.
  createValidData: null,

  updateData: null,

  query: {
    searchFields: ['filename'],
    // Bulletin filenames are bulletin_<station>_<timestamp>.wav.
    searchTerm: '.wav',
    sortableFields: ['id', 'station_id', 'created_at'],
    filterableFields: ['id', 'station_id'],
    selectableFields: ['id', 'station_id', 'created_at']
  },

  validation: null
};
