/**
 * Story resource schema for test generation.
 * Note: Stories have complex dependencies (voice_id, target_stations) that require
 * setup functions in the actual tests. This schema covers the basic structure.
 */

module.exports = {
  name: 'Story',
  namePlural: 'stories',
  endpoint: '/stories',

  // Note: This requires voiceId and stationId to be set up externally
  // Use createValidDataWithDeps in actual tests
  createValidData: (suffix = '') => ({
    title: `Test Story ${suffix || Date.now()}_${process.pid}`,
    text: 'This is test story content for automated testing.',
    status: 'active',
    weekdays: 127, // All days (binary: 1111111)
    start_date: new Date().toISOString().split('T')[0],
    end_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
    // voice_id and target_stations must be added by test setup
  }),

  updateData: {
    title: `Updated Story ${Date.now()}`,
    text: 'Updated story content.',
    status: 'active'
  },

  query: {
    searchFields: ['title', 'text'],
    sortableFields: ['id', 'title', 'status', 'start_date', 'end_date', 'created_at', 'updated_at'],
    filterableFields: ['id', 'title', 'status', 'voice_id', 'weekdays'],
    numericFields: ['id', 'voice_id', 'weekdays'],
    selectableFields: ['id', 'title', 'text', 'status', 'voice_id', 'weekdays', 'start_date', 'end_date', 'created_at', 'updated_at']
  },

  // Note: Story API doesn't properly exclude fields on field selection
  excludeOnFieldSelect: [],

  validation: {
    fields: {
      title: {
        type: 'string',
        required: true,
        minLength: 1,
        maxLength: 500,
        rejectWhitespaceOnly: true
      },
      text: {
        type: 'string',
        required: true,
        minLength: 1,
        maxLength: 65535
      },
      voice_id: {
        type: 'integer',
        required: true,
        min: 1
      },
      target_stations: {
        type: 'array',
        required: true,
        minItems: 1
      },
      status: {
        type: 'string',
        required: false,
        enum: ['active', 'inactive', 'deleted']
      },
      weekdays: {
        type: 'integer',
        required: false,
        min: 0,
        max: 127
      },
      start_date: {
        type: 'string',
        required: false
      },
      end_date: {
        type: 'string',
        required: false
      }
    }
  },

  // Helper to create complete story data with dependencies
  createValidDataWithDeps: (voiceId, stationIds, suffix = '') => ({
    title: `Test Story ${suffix || Date.now()}_${process.pid}`,
    text: 'This is test story content for automated testing.',
    voice_id: parseInt(voiceId, 10),
    target_stations: stationIds.map(id => parseInt(id, 10)),
    status: 'active',
    weekdays: 127,
    start_date: new Date().toISOString().split('T')[0],
    end_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
  })
};
