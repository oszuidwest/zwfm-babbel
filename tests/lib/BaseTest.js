const axios = require('axios');
const FormData = require('form-data');
const { CookieJar } = require('tough-cookie');
const { wrapper } = require('axios-cookiejar-support');
const chalk = require('chalk');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');

// Force color support for terminals that support it but aren't auto-detected by chalk.
if (!chalk.supportsColor && (process.env.TERM && process.env.TERM.includes('color'))) {
    process.env.FORCE_COLOR = '1';
    // Re-import chalk to pick up the updated environment variable.
    delete require.cache[require.resolve('chalk')];
    const chalkModule = require('chalk');
    Object.assign(chalk, chalkModule);
}

/**
 * Base test class for Babbel API tests.
 * Provides common functionality for HTTP requests, authentication,
 * cookie management, colored output, and test tracking.
 */
class BaseTest {
    constructor() {
        this.apiBase = process.env.API_BASE || 'http://localhost:8080';
        this.apiUrl = `${this.apiBase}/api/v1`;
        // Audio directory is at project root, not in tests directory
        this.audioDir = path.join(__dirname, '../../audio');
        this.cookieFile = './test_cookies.txt';
        
        // Initialize cookie jar and HTTP client instance.
        this.cookieJar = new CookieJar();
        this.http = wrapper(axios.create({
            jar: this.cookieJar,
            validateStatus: () => true, // Don't throw on HTTP errors
            timeout: 30000 // 30 second timeout
        }));
        
        // Test counters start fresh for each test run.
        this.testsPassed = 0;
        this.testsFailed = 0;
        
        // Each test file maintains its own counters instead of loading existing ones.
        
        // Default admin credentials
        this.defaultAdminUsername = 'admin';
        this.defaultAdminPassword = 'admin';
        
        // MySQL configuration
        this.mysqlUser = process.env.MYSQL_USER || 'babbel';
        this.mysqlPassword = process.env.MYSQL_PASSWORD || 'babbel';
        this.mysqlDatabase = process.env.MYSQL_DATABASE || 'babbel';
    }
    
    // Cookie Management
    
    /**
     * Loads cookies from file to maintain session persistence.
     */
    async loadCookies() {
        try {
            if (fsSync.existsSync(this.cookieFile)) {
                const cookieData = await fs.readFile(this.cookieFile, 'utf8');
                // Parse Netscape cookie format (compatible with curl -c/-b)
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
            
            const header = '# Netscape HTTP Cookie File\n# This file contains session cookies for Babbel API tests\n';
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
            // File doesn't exist, which is acceptable.
        }
        this.cookieJar = new CookieJar();
        this.http = wrapper(axios.create({
            jar: this.cookieJar,
            validateStatus: () => true,
            timeout: 30000
        }));
    }
    
    // Test Counter Management
    
    /**
     * Loads test counters from temporary file.
     */
    loadTestCounters() {
        try {
            if (fsSync.existsSync('/tmp/babbel_test_counters')) {
                const data = fsSync.readFileSync('/tmp/babbel_test_counters', 'utf8');
                const lines = data.split('\n');
                for (const line of lines) {
                    if (line.startsWith('TESTS_PASSED=')) {
                        this.testsPassed = parseInt(line.split('=')[1]) || 0;
                    } else if (line.startsWith('TESTS_FAILED=')) {
                        this.testsFailed = parseInt(line.split('=')[1]) || 0;
                    }
                }
            }
        } catch (error) {
            // Ignore loading errors, start fresh
            this.testsPassed = 0;
            this.testsFailed = 0;
        }
    }
    
    /**
     * Saves test counters to temporary file.
     */
    saveTestCounters() {
        // Disabled - each test file maintains its own counters while orchestrator counts suite results.
    }
    
    /**
     * Resets test counters to zero.
     */
    resetTestCounters() {
        this.testsPassed = 0;
        this.testsFailed = 0;
        try {
            fsSync.unlinkSync('/tmp/babbel_test_counters');
        } catch (error) {
            // File doesn't exist, which is acceptable.
        }
    }
    
    // Output Functions (styled output)
    
    printHeader(text) {
        const line = '═'.repeat(60);
        console.error(`\n${chalk.magenta.bold(line)}`);
        console.error(`${chalk.magenta.bold(`  ${text}`)}`);
        console.error(`${chalk.magenta.bold(line)}\n`);
    }
    
    printSection(text) {
        console.error(`\n${chalk.cyan(`━━━ ${text} ━━━`)}`);
    }
    
    printSuccess(text) {
        console.error(`${chalk.green(`✓ ${text}`)}`);
    }
    
    printError(text) {
        console.error(`${chalk.red(`✗ ${text}`)}`);
    }
    
    printInfo(text) {
        console.error(`${chalk.yellow(`ℹ ${text}`)}`);
    }
    
    printWarning(text) {
        console.error(`${chalk.yellow(`⚠ ${text}`)}`);
    }
    
    printSummary() {
        const total = this.testsPassed + this.testsFailed;
        console.error(`\n${chalk.bold('Test Summary:')}`);
        console.error(`${chalk.green(`✓ Passed: ${this.testsPassed}`)}`);
        console.error(`${chalk.red(`✗ Failed: ${this.testsFailed}`)}`);
        console.error(`${chalk.cyan(`Total: ${total}`)}`);
        
        if (this.testsFailed === 0) {
            console.error(`${chalk.green.bold('All tests passed!')}`);
            return true;
        } else {
            console.error(`${chalk.red.bold('Some tests failed!')}`);
            return false;
        }
    }
    
    // HTTP Request Methods
    
    /**
     * Makes API call with automatic cookie handling.
     * @param {string} method - HTTP method (GET, POST, etc.).
     * @param {string} endpoint - API endpoint path.
     * @param {Object} data - Request data (optional).
     * @param {Object} options - Additional options (optional).
     * @returns {Promise<Object>} Response object with status, data, and headers.
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
     * @param {string} endpoint - API endpoint path.
     * @param {Object} formFields - Form field data.
     * @param {string} filePath - Path to file to upload (optional).
     * @param {string} fileFieldName - Name of file field (default: 'file').
     * @param {string} method - HTTP method (default: 'POST').
     * @returns {Promise<Object>} Response object with status, data, and headers.
     */
    async uploadFile(endpoint, formFields, filePath = null, fileFieldName = 'file', method = 'POST') {
        await this.loadCookies();
        
        const form = new FormData();
        
        // Add regular form fields to multipart data.
        for (const [key, value] of Object.entries(formFields)) {
            form.append(key, value);
        }
        
        // Add file to form data if provided.
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
     * @param {string} endpoint - API endpoint path.
     * @param {string} outputPath - Local path to save file.
     * @param {string} method - HTTP method (default: 'GET').
     * @param {Object} data - Request data (optional).
     * @param {Object} headers - Custom headers (optional).
     * @returns {Promise<number>} HTTP status code.
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
    
    // Authentication Methods
    
    /**
     * Authenticates with the API using provided credentials.
     * @param {string} username - Username (optional, defaults to admin).
     * @param {string} password - Password (optional, defaults to admin).
     * @returns {Promise<boolean>} True if login succeeded.
     */
    async apiLogin(username = null, password = null) {
        username = username || this.defaultAdminUsername;
        password = password || this.defaultAdminPassword;
        
        this.printSection('API Authentication');
        
        await this.clearCookies();
        
        const response = await this.apiCall('POST', '/sessions', {
            username,
            password
        });
        
        if (response.status === 201) {
            this.printSuccess(`Logged in as ${username}`);
            return true;
        } else {
            this.printError(`Login failed for ${username} (HTTP ${response.status})`);
            const errorMsg = this.extractErrorMessage(response.data);
            if (errorMsg) {
                this.printError(`Error: ${errorMsg}`);
            }
            return false;
        }
    }
    
    /**
     * Logs out from the API and clears session cookies.
     * @returns {Promise<boolean>} True if logout succeeded.
     */
    async apiLogout() {
        this.printSection('API Logout');
        
        if (!fsSync.existsSync(this.cookieFile)) {
            this.printWarning('No cookie file found - already logged out');
            return true;
        }
        
        const response = await this.apiCall('DELETE', '/sessions/current');
        
        if (response.status === 204) {
            this.printSuccess('Logged out successfully');
            await this.clearCookies();
            return true;
        } else {
            this.printWarning(`Logout response: HTTP ${response.status} (removing cookies anyway)`);
            await this.clearCookies();
            return false;
        }
    }
    
    /**
     * Retrieves current session information.
     * @returns {Promise<Object|null>} Session data or null if not authenticated.
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
     * @returns {Promise<boolean>} True if session is active.
     */
    async isSessionActive() {
        const session = await this.getCurrentSession();
        return session !== null;
    }
    
    // Utility Methods
    
    /**
     * Extracts error message from RFC 9457 Problem Details response.
     * @param {Object} responseData - Response data object.
     * @returns {string} Extracted error message or empty string.
     */
    extractErrorMessage(responseData) {
        if (!responseData || typeof responseData !== 'object') {
            return '';
        }
        
        try {
            // RFC 9457 format includes title and optional detail fields.
            if (responseData.title) {
                const title = responseData.title;
                const detail = responseData.detail;
                if (detail) {
                    return `${title}: ${detail}`;
                }
                return title;
            }
        } catch (error) {
            // Ignore any JSON parsing errors.
        }
        
        return '';
    }
    
    /**
     * Parses a specific field from JSON response data.
     * @param {Object} data - JSON data object.
     * @param {string} field - Field name to extract.
     * @returns {string} Field value as string or empty string.
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
     * @param {Object} data - JSON data object.
     * @param {string} fieldPath - Dot-notation path (e.g., 'data.0.id').
     * @returns {string} Field value as string or empty string.
     */
    parseJsonNested(data, fieldPath) {
        if (!data || typeof data !== 'object') {
            return '';
        }
        
        try {
            const keys = fieldPath.split('.');
            let current = data;
            
            for (const key of keys) {
                if (/^\\d+$/.test(key)) {
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
     * @param {string} filePath - Path to file to wait for.
     * @param {number} timeout - Timeout in seconds (default: 10).
     * @returns {Promise<boolean>} True if file exists within timeout.
     */
    async waitForFile(filePath, timeout = 10) {
        this.printInfo(`Waiting for file: ${filePath} (timeout: ${timeout}s)`);
        
        const startTime = Date.now();
        const timeoutMs = timeout * 1000;
        
        while (Date.now() - startTime < timeoutMs) {
            if (fsSync.existsSync(filePath)) {
                this.printSuccess(`File exists: ${filePath}`);
                return true;
            }
            await new Promise(resolve => setTimeout(resolve, 500));
        }
        
        this.printError(`File not found after ${timeout}s: ${filePath}`);
        return false;
    }
    
    /**
     * Waits for audio file to exist (alias for waitForFile).
     * @param {string} filePath - Path to audio file.
     * @param {number} timeout - Timeout in seconds (default: 10).
     * @returns {Promise<boolean>} True if file exists within timeout.
     */
    async waitForAudioFile(filePath, timeout = 10) {
        return await this.waitForFile(filePath, timeout);
    }
    
    /**
     * Makes API call with FormData for file uploads.
     * @param {string} method - HTTP method.
     * @param {string} endpoint - API endpoint path.
     * @param {FormData} formData - FormData object.
     * @param {Object} options - Additional options (optional).
     * @returns {Promise<Object>} Response object with status, data, and headers.
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
    
    /**
     * Runs a test function with error handling and result tracking.
     * @param {Function} testFunction - Test function to execute.
     * @param {string} testName - Name of the test (optional).
     * @returns {Promise<boolean>} True if test passed.
     */
    async runTest(testFunction, testName = null) {
        testName = testName || testFunction.name;
        
        this.printInfo(`Running: ${testName}`);
        
        try {
            const result = await testFunction.call(this);
            if (result !== false) {
                this.printSuccess(`${testName} completed`);
                this.testsPassed++;
                this.saveTestCounters();
                return true;
            } else {
                this.printError(`${testName} failed`);
                this.testsFailed++;
                this.saveTestCounters();
                return false;
            }
        } catch (error) {
            this.printError(`${testName} failed: ${error.message}`);
            this.testsFailed++;
            this.saveTestCounters();
            return false;
        }
    }
}

module.exports = BaseTest;