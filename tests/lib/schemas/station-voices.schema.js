module.exports = {
  name: 'StationVoice',
  namePlural: 'stationVoices',
  endpoint: '/station-voices',

  // Tests supply both foreign keys through fixture setup.
  createValidData: (suffix = '') => ({
    mix_point: 3.0
  }),

  updateData: () => ({
    mix_point: 5.0
  }),

  query: {
    searchFields: [],
    sortableFields: ['id', 'station_id', 'voice_id', 'mix_point', 'created_at', 'updated_at'],
    filterableFields: ['id', 'station_id', 'voice_id', 'mix_point'],
    numericFields: ['id', 'station_id', 'voice_id', 'mix_point'],
    selectableFields: ['id', 'station_id', 'voice_id', 'mix_point', 'audio_url', 'created_at', 'updated_at']
  },

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
  }
};
