const createUser = async (username, fullName, password, role) => {
  const response = await global.api.apiCall('POST', '/users', {
    username,
    full_name: fullName,
    password,
    role
  });

  if (response.status === 201 && response.data?.id) {
    global.resources.track('users', response.data.id);
    return response.data.id;
  } else if (response.status === 409) {
    // User already exists, find it
    const userResponse = await global.api.apiCall('GET', '/users');
    if (userResponse.status === 200 && userResponse.data.data) {
      const user = userResponse.data.data.find(u => u.username === username);
      if (user) return user.id;
    }
  }
  return null;
};

const switchToUser = async (username, password) => {
  const loginResponse = await global.api.apiLogin(username, password);
  return loginResponse.status === 201;
};

const restoreAdmin = async () => {
  await global.api.apiLogin('admin', 'admin');
};

module.exports = { createUser, switchToUser, restoreAdmin };
