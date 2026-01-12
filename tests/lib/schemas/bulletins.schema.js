/**
 * Bulletin resource schema for test generation.
 * Note: Bulletins are generated, not created directly. This schema is for query tests.
 */

module.exports = {
  name: 'Bulletin',
  namePlural: 'bulletins',
  endpoint: '/bulletins',

  // Bulletins are generated via POST /stations/{id}/bulletins, not POST /bulletins
  // This createValidData is for reference only
  createValidData: null,

  updateData: null, // Bulletins cannot be updated

  query: {
    searchFields: [],
    sortableFields: ['id', 'station_id', 'created_at'],
    filterableFields: ['id', 'station_id'],
    numericFields: ['id', 'station_id'],
    selectableFields: ['id', 'station_id', 'audio_file', 'created_at']
  },

  excludeOnFieldSelect: ['audio_file'],

  // Bulletins don't have direct creation validation - they're generated
  validation: null,

  // Station endpoint for bulletin generation
  generateEndpoint: (stationId) => `/stations/${stationId}/bulletins`,

  // Query for latest bulletin
  latestEndpoint: (stationId) => `/stations/${stationId}/bulletins?latest=true`
};
