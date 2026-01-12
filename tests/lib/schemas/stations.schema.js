/**
 * Station resource schema for test generation.
 */

module.exports = {
  // Resource identification
  name: 'Station',
  namePlural: 'stations',
  endpoint: '/stations',

  // Factory function for creating valid test data
  createValidData: (suffix = '') => ({
    name: `Test Station ${suffix || Date.now()}_${process.pid}`,
    max_stories_per_block: 5,
    pause_seconds: 2.0
  }),

  // Data for update tests
  updateData: {
    name: `Updated Station ${Date.now()}`,
    max_stories_per_block: 7,
    pause_seconds: 3.0
  },

  // Query parameter configuration
  query: {
    searchFields: ['name'],
    sortableFields: ['id', 'name', 'max_stories_per_block', 'pause_seconds', 'created_at', 'updated_at'],
    filterableFields: ['id', 'name', 'max_stories_per_block', 'pause_seconds'],
    numericFields: ['id', 'max_stories_per_block', 'pause_seconds'],
    selectableFields: ['id', 'name', 'max_stories_per_block', 'pause_seconds', 'created_at', 'updated_at']
  },

  // Fields to verify are excluded when not in field selection
  excludeOnFieldSelect: ['max_stories_per_block', 'pause_seconds'],

  // Validation rules
  validation: {
    fields: {
      name: {
        type: 'string',
        required: true,
        minLength: 1,
        maxLength: 255,
        unique: true,
        rejectWhitespaceOnly: true
      },
      max_stories_per_block: {
        type: 'integer',
        required: true,
        min: 1,
        max: 50
      },
      pause_seconds: {
        type: 'float',
        required: false, // Has default value in API
        min: 0,
        max: 60
      }
    }
  }
};
