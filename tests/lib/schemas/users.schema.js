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

  updateData: () => ({
    full_name: 'Updated User Name',
    role: 'editor'
  }),

  query: {
    searchFields: ['username', 'full_name'],
    sortableFields: ['id', 'username', 'full_name', 'role', 'created_at', 'updated_at'],
    filterableFields: ['id', 'username', 'role'],
    selectableFields: ['id', 'username', 'full_name', 'role', 'created_at', 'updated_at']
  }
};
