/**
 * ApiHelper - HTTP client for Babbel API tests
 * Handles cookie-based session management, file uploads, and authentication.
 * Extracted from BaseTest.js for use with Jest.
 */
const axios = require('axios');
const FormData = require('form-data');
const { CookieJar } = require('tough-cookie');
const { wrapper } = require('axios-cookiejar-support');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');

class ApiHelper {
  constructor() {
    this.apiBase = process.env.API_BASE || 'http://localhost:8080';
    this.apiUrl = `${this.apiBase}/api/v1`;
    this.audioDir = path.join(__dirname, '../../audio');
    this.cookieFile = path.join(__dirname, '../test_cookies.txt');

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

  // ═══════════════════════════════════════════════════════════════════════════
  // Cookie Management
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Loads cookies from file to maintain session persistence.
   */
  async loadCookies() {
    try {
      if (fsSync.existsSync(this.cookieFile)) {
        const cookieData = await fs.readFile(this.cookieFile, 'utf8');
        const lines = cookieData.split('\n');
        for (const line of lines) {
          if (line.startsWith('#') || !line.trim()) continue;
          const parts = line.split('\t');
          if (parts.length >= 7) {
            const [domain, flag, path, secure, expiration, name, value] = parts;
            await this.cookieJar.setCookie(`${name}=${value}`, this.apiBase);
          }
        }
      }
    } catch (error) {
      // Ignore cookie loading errors, start fresh
    }
  }

  /**
   * Saves cookies to file for persistence.
   */
  async saveCookies() {
    try {
      const cookies = await this.cookieJar.getCookies(this.apiBase);
      const cookieStrings = cookies.map(cookie => {
        const domain = cookie.domain || 'localhost';
        const flag = 'TRUE';
        const path = cookie.path || '/';
        const secure = cookie.secure ? 'TRUE' : 'FALSE';
        const expiration = cookie.expires ? Math.floor(cookie.expires.getTime() / 1000) : '0';
        return `${domain}\t${flag}\t${path}\t${secure}\t${expiration}\t${cookie.key}\t${cookie.value}`;
      });

      const header = '# Netscape HTTP Cookie File\n# Session cookies for Babbel API tests\n';
      await fs.writeFile(this.cookieFile, header + cookieStrings.join('\n') + '\n');
    } catch (error) {
      // Ignore cookie saving errors
    }
  }

  /**
   * Clears all cookies and reinitializes the HTTP client.
   */
  async clearCookies() {
    try {
      await fs.unlink(this.cookieFile);
    } catch (error) {
      // File doesn't exist, which is acceptable
    }
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
    await this.loadCookies();

    const config = {
      method: method.toLowerCase(),
      url: `${this.apiUrl}${endpoint}`,
      ...options
    };

    if (data && !config.data && !config.formData) {
      if (method.toUpperCase() !== 'GET' && method.toUpperCase() !== 'DELETE') {
        config.headers = {
          'Content-Type': 'application/json',
          ...config.headers
        };
        config.data = typeof data === 'string' ? data : JSON.stringify(data);
      }
    }

    const response = await this.http(config);
    await this.saveCookies();

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
    await this.loadCookies();

    const form = new FormData();

    // Add regular form fields
    for (const [key, value] of Object.entries(formFields)) {
      form.append(key, value);
    }

    // Add file if provided
    if (filePath && fsSync.existsSync(filePath)) {
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

    await this.saveCookies();

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
    await this.loadCookies();

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
        writer.on('finish', () => resolve(response.status));
        writer.on('error', reject);
      });
    }

    return response.status;
  }

  /**
   * Makes API call with FormData for file uploads.
   * @param {string} method - HTTP method
   * @param {string} endpoint - API endpoint path
   * @param {FormData} formData - FormData object
   * @param {Object} options - Additional options (optional)
   * @returns {Promise<Object>} Response object with status, data, and headers
   */
  async apiCallFormData(method, endpoint, formData, options = {}) {
    await this.loadCookies();

    const config = {
      method: method.toLowerCase(),
      url: `${this.apiUrl}${endpoint}`,
      data: formData,
      headers: {
        ...formData.getHeaders(),
        ...options.headers
      },
      ...options
    };

    const response = await this.http(config);
    await this.saveCookies();

    return {
      status: response.status,
      data: response.data,
      headers: response.headers
    };
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

    await this.clearCookies();

    const response = await this.apiCall('POST', '/sessions', {
      username,
      password
    });

    return response;
  }

  /**
   * Logs out from the API and clears session cookies.
   * @returns {Promise<Object>} Response object with status
   */
  async apiLogout() {
    if (!fsSync.existsSync(this.cookieFile)) {
      return { status: 204, data: null };
    }

    const response = await this.apiCall('DELETE', '/sessions/current');
    await this.clearCookies();

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

  // ═══════════════════════════════════════════════════════════════════════════
  // Utility Methods
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Extracts error message from RFC 9457 Problem Details response.
   * @param {Object} responseData - Response data object
   * @returns {string} Extracted error message or empty string
   */
  extractErrorMessage(responseData) {
    if (!responseData || typeof responseData !== 'object') {
      return '';
    }

    if (responseData.title) {
      const title = responseData.title;
      const detail = responseData.detail;
      if (detail) {
        return `${title}: ${detail}`;
      }
      return title;
    }

    return '';
  }

  /**
   * Parses a specific field from JSON response data.
   * @param {Object} data - JSON data object
   * @param {string} field - Field name to extract
   * @returns {string} Field value as string or empty string
   */
  parseJsonField(data, field) {
    if (!data || typeof data !== 'object') {
      return '';
    }

    const value = data[field];
    return value !== undefined && value !== null ? String(value) : '';
  }

  /**
   * Parses a nested JSON field using dot notation.
   * @param {Object} data - JSON data object
   * @param {string} fieldPath - Dot-notation path (e.g., 'data.0.id')
   * @returns {string} Field value as string or empty string
   */
  parseJsonNested(data, fieldPath) {
    if (!data || typeof data !== 'object') {
      return '';
    }

    try {
      const keys = fieldPath.split('.');
      let current = data;

      for (const key of keys) {
        if (/^\d+$/.test(key)) {
          current = current[parseInt(key)];
        } else {
          current = current[key];
        }

        if (current === undefined || current === null) {
          return '';
        }
      }

      return typeof current === 'object' ? '' : String(current);
    } catch (error) {
      return '';
    }
  }

  /**
   * Waits for a file to exist with timeout.
   * @param {string} filePath - Path to file to wait for
   * @param {number} timeout - Timeout in seconds (default: 10)
   * @returns {Promise<boolean>} True if file exists within timeout
   */
  async waitForFile(filePath, timeout = 10) {
    const startTime = Date.now();
    const timeoutMs = timeout * 1000;

    while (Date.now() - startTime < timeoutMs) {
      if (fsSync.existsSync(filePath)) {
        return true;
      }
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    return false;
  }
}

module.exports = ApiHelper;
