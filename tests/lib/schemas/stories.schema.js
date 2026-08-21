// Tests supply voice_id and target_stations through their fixture setup.

module.exports = {
  name: 'Story',
  namePlural: 'stories',
  endpoint: '/stories',

  createValidData: (suffix = '') => ({
    title: `Test Story ${suffix || Date.now()}_${process.pid}`,
    text: 'This is test story content for automated testing.',
    status: 'active',
    weekdays: 127, // All days (binary: 1111111)
    start_date: new Date().toISOString().split('T')[0],
    end_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
  }),

  updateData: () => ({
    title: `Updated Story ${Date.now()}`,
    text: 'Updated story content.',
    status: 'active'
  }),

  query: {
    searchFields: ['title', 'text'],
    sortableFields: ['id', 'title', 'status', 'start_date', 'end_date', 'created_at', 'updated_at'],
    filterableFields: ['id', 'title', 'status', 'voice_id', 'weekdays', 'is_breaking'],
    numericFields: ['id', 'voice_id', 'weekdays'],
    booleanFields: ['is_breaking'],
    selectableFields: ['id', 'title', 'text', 'status', 'voice_id', 'weekdays', 'is_breaking', 'start_date', 'end_date', 'created_at', 'updated_at']
  },

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
        enum: ['draft', 'active', 'expired']
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
  }
};
