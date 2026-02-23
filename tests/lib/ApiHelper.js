/**
 * ApiHelper - HTTP client for Babbel API tests
 * Handles cookie-based session management, file uploads, and authentication.
 * Extracted from BaseTest.js for use with Jest.
 */
const axios = require('axios');
const FormData = require('form-data');
const { CookieJar } = require('tough-cookie');
const { wrapper } = require('axios-cookiejar-support');
const fsSync = require('fs');
const path = require('path');

class ApiHelper {
  constructor() {
    this.apiBase = process.env.API_BASE || 'http://localhost:8080';
    this.apiUrl = `${this.apiBase}/api/v1`;
    this.audioDir = path.join(__dirname, '../../audio');

    // Initialize cookie jar and HTTP client
    this.cookieJar = new CookieJar();
    this.http = wrapper(axios.create({
      jar: this.cookieJar,
      validateStatus: () => true, // Don't throw on HTTP errors
      timeout: 30000
    }));

    // Default credentials
    this.defaultAdminUsername = 'admin';
    this.defaultAdminPassword = 'admin';
  }

  /**
   * Clears all cookies and reinitializes the HTTP client.
   */
  clearCookies() {
    this.cookieJar = new CookieJar();
    this.http = wrapper(axios.create({
      jar: this.cookieJar,
      validateStatus: () => true,
      timeout: 30000
    }));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HTTP Request Methods
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Makes API call with automatic cookie handling.
   * @param {string} method - HTTP method (GET, POST, etc.)
   * @param {string} endpoint - API endpoint path
   * @param {Object} data - Request data (optional)
   * @param {Object} options - Additional axios options (optional)
   * @returns {Promise<Object>} Response object with status, data, and headers
   */
  async apiCall(method, endpoint, data = null, options = {}) {
    const config = {
      method: method.toLowerCase(),
      url: `${this.apiUrl}${endpoint}`,
      ...options
    };

    if (data && !config.data) {
      if (method.toUpperCase() !== 'GET' && method.toUpperCase() !== 'DELETE') {
        config.headers = {
          'Content-Type': 'application/json',
          ...config.headers
        };
        config.data = typeof data === 'string' ? data : JSON.stringify(data);
      }
    }

    const response = await this.http(config);

    return {
      status: response.status,
      data: response.data,
      headers: response.headers
    };
  }

  /**
   * Uploads file using multipart form data.
   * @param {string} endpoint - API endpoint path
   * @param {Object} formFields - Form field data
   * @param {string} filePath - Path to file to upload (optional)
   * @param {string} fileFieldName - Name of file field (default: 'file')
   * @param {string} method - HTTP method (default: 'POST')
   * @returns {Promise<Object>} Response object with status, data, and headers
   */
  async uploadFile(endpoint, formFields, filePath = null, fileFieldName = 'file', method = 'POST') {
    const form = new FormData();

    // Add regular form fields
    for (const [key, value] of Object.entries(formFields)) {
      form.append(key, value);
    }

    // Add file if provided
    if (filePath) {
      if (!fsSync.existsSync(filePath)) {
        throw new Error(`Upload file not found: ${filePath}`);
      }
      const fileStream = fsSync.createReadStream(filePath);
      form.append(fileFieldName, fileStream);
    }

    const response = await this.http({
      method: method.toLowerCase(),
      url: `${this.apiUrl}${endpoint}`,
      data: form,
      headers: {
        ...form.getHeaders()
      }
    });

    return {
      status: response.status,
      data: response.data,
      headers: response.headers
    };
  }

  /**
   * Downloads a file from API endpoint.
   * @param {string} endpoint - API endpoint path
   * @param {string} outputPath - Local path to save file
   * @param {string} method - HTTP method (default: 'GET')
   * @param {Object} data - Request data (optional)
   * @param {Object} headers - Custom headers (optional)
   * @returns {Promise<number>} HTTP status code
   */
  async downloadFile(endpoint, outputPath, method = 'GET', data = null, headers = {}) {
    const config = {
      method: method.toLowerCase(),
      url: `${this.apiUrl}${endpoint}`,
      responseType: 'stream',
      headers: { ...headers }
    };

    if (data && method.toUpperCase() !== 'GET') {
      config.data = data;
      config.headers = {
        'Content-Type': 'application/json',
        ...config.headers
      };
    }

    const response = await this.http(config);

    if (response.status === 200) {
      const writer = fsSync.createWriteStream(outputPath);
      response.data.pipe(writer);

      return new Promise((resolve, reject) => {
        response.data.on('error', (err) => {
          writer.destroy();
          reject(err);
        });
        writer.on('finish', () => resolve(response.status));
        writer.on('error', reject);
      });
    }

    // Drain unused stream to prevent resource leaks
    if (response.data && typeof response.data.resume === 'function') {
      response.data.resume();
    }

    return response.status;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Authentication Methods
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Authenticates with the API using provided credentials.
   * @param {string} username - Username (optional, defaults to admin)
   * @param {string} password - Password (optional, defaults to admin)
   * @returns {Promise<Object>} Response object with status and data
   */
  async apiLogin(username = null, password = null) {
    username = username || this.defaultAdminUsername;
    password = password || this.defaultAdminPassword;

    this.clearCookies();

    return this.apiCall('POST', '/sessions', { username, password });
  }

  /**
   * Logs out from the API and clears session cookies.
   * @returns {Promise<Object>} Response object with status
   */
  async apiLogout() {
    const response = await this.apiCall('DELETE', '/sessions/current');
    this.clearCookies();
    return response;
  }

  /**
   * Retrieves current session information.
   * @returns {Promise<Object|null>} Session data or null if not authenticated
   */
  async getCurrentSession() {
    const response = await this.apiCall('GET', '/sessions/current');

    if (response.status === 200) {
      return response.data;
    }
    return null;
  }

  /**
   * Checks if there is an active session.
   * @returns {Promise<boolean>} True if session is active
   */
  async isSessionActive() {
    const session = await this.getCurrentSession();
    return session !== null;
  }

}

module.exports = ApiHelper;
