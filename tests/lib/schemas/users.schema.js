/**
 * User resource schema for test generation.
 */

module.exports = {
  name: 'User',
  namePlural: 'users',
  endpoint: '/users',

  createValidData: (suffix = '') => ({
    username: `testuser${suffix || Date.now()}${process.pid}`.replace(/[^a-zA-Z0-9]/g, ''),
    full_name: `Test User ${suffix || ''}`.trim(),
    password: 'TestPassword123!',
    role: 'viewer'
  }),

  updateData: {
    full_name: 'Updated User Name',
    role: 'editor'
  },

  query: {
    searchFields: ['username', 'full_name'],
    sortableFields: ['id', 'username', 'full_name', 'role', 'created_at', 'updated_at'],
    filterableFields: ['id', 'username', 'role', 'is_suspended'],
    numericFields: ['id'],
    selectableFields: ['id', 'username', 'full_name', 'role', 'is_suspended', 'created_at', 'updated_at']
  },

  excludeOnFieldSelect: ['full_name', 'role'],

  validation: {
    fields: {
      username: {
        type: 'string',
        required: true,
        minLength: 3,
        maxLength: 100,
        unique: true,
        rejectWhitespaceOnly: true
      },
      full_name: {
        type: 'string',
        required: true,
        minLength: 1,
        maxLength: 255
      },
      password: {
        type: 'string',
        required: true,
        minLength: 8,
        maxLength: 128
      },
      role: {
        type: 'string',
        required: true,
        enum: ['admin', 'editor', 'viewer']
      }
    }
  }
};
