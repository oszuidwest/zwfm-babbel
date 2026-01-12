/**
 * Station-Voice relationship resource schema for test generation.
 * Note: This is a junction resource that requires station_id and voice_id.
 */

module.exports = {
  name: 'StationVoice',
  namePlural: 'stationVoices',
  endpoint: '/station-voices',

  // Note: Requires stationId and voiceId to be set up externally
  createValidData: (suffix = '') => ({
    mix_point: 3.0
    // station_id and voice_id must be added by test setup
  }),

  updateData: {
    mix_point: 5.0
  },

  query: {
    searchFields: [],
    sortableFields: ['id', 'station_id', 'voice_id', 'mix_point', 'created_at', 'updated_at'],
    filterableFields: ['id', 'station_id', 'voice_id', 'mix_point'],
    numericFields: ['id', 'station_id', 'voice_id', 'mix_point'],
    selectableFields: ['id', 'station_id', 'voice_id', 'mix_point', 'jingle_file', 'created_at', 'updated_at']
  },

  excludeOnFieldSelect: ['jingle_file'],

  validation: {
    fields: {
      station_id: {
        type: 'integer',
        required: true,
        min: 1
      },
      voice_id: {
        type: 'integer',
        required: true,
        min: 1
      },
      mix_point: {
        type: 'float',
        required: false,
        min: 0,
        max: 60
      }
    }
  },

  // Helper to create complete station-voice data with dependencies
  createValidDataWithDeps: (stationId, voiceId, mixPoint = 3.0) => ({
    station_id: parseInt(stationId, 10),
    voice_id: parseInt(voiceId, 10),
    mix_point: parseFloat(mixPoint)
  })
};
