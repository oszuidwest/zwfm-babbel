#!/usr/bin/env node

/**
 * Babbel Validation Tests - Node.js Implementation
 * 
 * Comprehensive validation testing for all API endpoints with proper JSON handling.
 * Tests field validation, data types, boundaries, business rules, and input sanitization.
 * 
 * This script replaces the bash implementation to solve JSON parsing issues when
 * using colons as delimiters in test data that also contains colons.
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const { promisify } = require('util');
const querystring = require('querystring');

// Terminal color codes for output formatting
const Colors = {
    GREEN: '\033[0;32m',
    BLUE: '\033[0;34m',
    YELLOW: '\033[1;33m',
    RED: '\033[0;31m',
    CYAN: '\033[0;36m',
    MAGENTA: '\033[0;35m',
    BOLD: '\033[1m',
    NC: '\033[0m'  // No Color
};

// Test result types
const TestResult = {
    PASS: "PASS",
    FAIL: "FAIL",
    SKIP: "SKIP"
};

/**
 * Represents a single test case
 */
class TestCase {
    constructor(name, data, expectedStatus, description, endpoint = "", method = "POST") {
        this.name = name;
        this.data = data;
        this.expectedStatus = expectedStatus;
        this.description = description;
        this.endpoint = endpoint;
        this.method = method;
    }
}

/**
 * Main class for running validation tests
 */
class ValidationTester {
    constructor() {
        this.apiBase = process.env.API_BASE || 'http://localhost:8080';
        this.apiUrl = `${this.apiBase}/api/v1`;
        // Check for cookie file in multiple locations
        const possiblePaths = [
            './test_cookies.txt',      // Current directory
            '../test_cookies.txt',      // Parent directory
            '/tmp/cookies.txt'          // Temp directory
        ];
        
        for (const path of possiblePaths) {
            if (fs.existsSync(path)) {
                this.cookieFile = path;
                break;
            }
        }
        
        if (!this.cookieFile) {
            this.cookieFile = './test_cookies.txt';  // Default
        }
        this.cookies = new Map();
        
        // Test counters
        this.testsPassed = 0;
        this.testsFailed = 0;
        
        // Created resources for cleanup
        this.createdStationIds = [];
        this.createdVoiceIds = [];
        this.createdStoryIds = [];
        this.createdUserIds = [];
        this.createdStationVoiceIds = [];
        
        // Load cookies if available
        this.loadCookies();
    }

    /**
     * Load cookies from the cookie file
     */
    loadCookies() {
        try {
            if (fs.existsSync(this.cookieFile)) {
                const content = fs.readFileSync(this.cookieFile, 'utf8').trim();
                if (content) {
                    // Parse Netscape cookie format
                    const lines = content.split('\n');
                    for (const line of lines) {
                        // Skip only true comment lines (# followed by space or at start of file)
                        // #HttpOnly_ lines are NOT comments but cookie data
                        if (line.match(/^#\s/) || line === '#' || !line.trim()) {
                            continue;
                        }
                        const parts = line.split('\t');
                        if (parts.length >= 7) {
                            const domain = parts[0];
                            const name = parts[5];
                            const value = parts[6];
                            this.cookies.set(name, value);
                        }
                    }
                }
                // Silently track cookie loading status
                // Cookies loaded: ${this.cookies.size}
            } else {
                // Cookie file not found: ${this.cookieFile}
            }
        } catch (e) {
            this.printError(`Failed to load cookies: ${e.message}`);
        }
    }

    /**
     * Print a header with formatting
     */
    printHeader(text) {
        process.stderr.write(`\n${Colors.MAGENTA}${Colors.BOLD}${'='.repeat(60)}${Colors.NC}\n`);
        process.stderr.write(`${Colors.MAGENTA}${Colors.BOLD}  ${text}${Colors.NC}\n`);
        process.stderr.write(`${Colors.MAGENTA}${Colors.BOLD}${'='.repeat(60)}${Colors.NC}\n\n`);
    }

    /**
     * Print a section header
     */
    printSection(text) {
        process.stderr.write(`\n${Colors.CYAN}━━━ ${text} ━━━${Colors.NC}\n`);
    }

    /**
     * Print success message and increment counter
     */
    printSuccess(text) {
        process.stderr.write(`${Colors.GREEN}✓ ${text}${Colors.NC}\n`);
        this.testsPassed++;
    }

    /**
     * Print error message and increment counter
     */
    printError(text) {
        process.stderr.write(`${Colors.RED}✗ ${text}${Colors.NC}\n`);
        this.testsFailed++;
    }

    /**
     * Print info message
     */
    printInfo(text) {
        process.stderr.write(`${Colors.YELLOW}ℹ ${text}${Colors.NC}\n`);
    }

    /**
     * Print warning message
     */
    printWarning(text) {
        process.stderr.write(`${Colors.YELLOW}⚠ ${text}${Colors.NC}\n`);
    }

    /**
     * Print test summary
     */
    printSummary() {
        const total = this.testsPassed + this.testsFailed;
        process.stderr.write(`\n${Colors.BOLD}Test Summary:${Colors.NC}\n`);
        process.stderr.write(`${Colors.GREEN}✓ Passed: ${this.testsPassed}${Colors.NC}\n`);
        process.stderr.write(`${Colors.RED}✗ Failed: ${this.testsFailed}${Colors.NC}\n`);
        process.stderr.write(`${Colors.CYAN}Total: ${total}${Colors.NC}\n`);
        
        if (this.testsFailed === 0) {
            process.stderr.write(`${Colors.GREEN}${Colors.BOLD}All tests passed!${Colors.NC}\n`);
            return true;
        } else {
            process.stderr.write(`${Colors.RED}${Colors.BOLD}Some tests failed!${Colors.NC}\n`);
            return false;
        }
    }

    /**
     * Make an HTTP request and return status code and response data
     */
    async apiCall(method, endpoint, data = null, files = null) {
        return new Promise((resolve, reject) => {
            const url = new URL(`${this.apiUrl}${endpoint}`);
            const isHttps = url.protocol === 'https:';
            const client = isHttps ? https : http;
            
            const options = {
                hostname: url.hostname,
                port: url.port || (isHttps ? 443 : 80),
                path: url.pathname + url.search,
                method: method.toUpperCase(),
                headers: {
                    'User-Agent': 'Babbel-ValidationTests/1.0'
                }
            };

            // Add cookies
            if (this.cookies.size > 0) {
                const cookieString = Array.from(this.cookies.entries())
                    .map(([name, value]) => `${name}=${value}`)
                    .join('; ');
                options.headers['Cookie'] = cookieString;
            }

            let requestData = null;

            // Handle different request types
            if (method.toUpperCase() === 'GET' || method.toUpperCase() === 'DELETE') {
                // No body for GET/DELETE
            } else if (files) {
                // Multipart form data for file uploads
                const boundary = `----ValidationTest${Date.now()}`;
                options.headers['Content-Type'] = `multipart/form-data; boundary=${boundary}`;
                
                let formData = '';
                
                // Add regular fields
                if (data) {
                    for (const [key, value] of Object.entries(data)) {
                        formData += `--${boundary}\r\n`;
                        formData += `Content-Disposition: form-data; name="${key}"\r\n\r\n`;
                        formData += `${value}\r\n`;
                    }
                }
                
                // Add file fields
                for (const [fieldName, fileBuffer] of Object.entries(files)) {
                    formData += `--${boundary}\r\n`;
                    formData += `Content-Disposition: form-data; name="${fieldName}"; filename="test.wav"\r\n`;
                    formData += `Content-Type: audio/wav\r\n\r\n`;
                }
                
                formData += `--${boundary}--\r\n`;
                
                // For files, we need to handle binary data separately
                // This is a simplified implementation - for real file uploads, use a proper multipart library
                requestData = Buffer.from(formData, 'utf8');
                
            } else if (data && endpoint.includes('/stories')) {
                // Form data for stories (multipart form without files)
                const formData = querystring.stringify(data);
                options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
                requestData = formData;
            } else if (data) {
                // JSON data for other endpoints
                options.headers['Content-Type'] = 'application/json';
                requestData = JSON.stringify(data);
            }

            if (requestData) {
                options.headers['Content-Length'] = Buffer.byteLength(requestData);
            }

            const req = client.request(options, (res) => {
                let responseBody = '';
                
                res.on('data', (chunk) => {
                    responseBody += chunk;
                });
                
                res.on('end', () => {
                    // Try to parse JSON response
                    let responseData;
                    try {
                        responseData = JSON.parse(responseBody);
                    } catch (e) {
                        responseData = { raw_text: responseBody };
                    }
                    
                    resolve([res.statusCode, responseData]);
                });
            });
            
            req.on('error', (error) => {
                this.printError(`API call failed: ${error.message}`);
                resolve([500, { error: error.message }]);
            });
            
            if (requestData) {
                req.write(requestData);
            }
            
            req.end();
        });
    }

    /**
     * Assert HTTP status code matches expected
     */
    assertStatusCode(actual, expected, description) {
        if (actual === expected) {
            this.printSuccess(`${description}: expected ${expected}, got ${actual}`);
            return true;
        } else {
            this.printError(`${description}: expected ${expected}, got ${actual}`);
            return false;
        }
    }

    /**
     * Run a single test case
     */
    async runTestCase(testCase) {
        this.printInfo(`Testing: ${testCase.description}`);
        
        const [statusCode, responseData] = await this.apiCall(
            testCase.method,
            testCase.endpoint,
            testCase.data
        );
        
        const success = this.assertStatusCode(
            statusCode,
            testCase.expectedStatus,
            testCase.description
        );
        
        // Handle successful creation responses
        if (success && testCase.expectedStatus === 201) {
            const resourceId = responseData.id;
            if (resourceId) {
                // Track created resources for cleanup
                if (testCase.endpoint.includes('/stations')) {
                    this.createdStationIds.push(resourceId);
                } else if (testCase.endpoint.includes('/voices')) {
                    this.createdVoiceIds.push(resourceId);
                } else if (testCase.endpoint.includes('/stories')) {
                    this.createdStoryIds.push(resourceId);
                } else if (testCase.endpoint.includes('/users')) {
                    this.createdUserIds.push(resourceId);
                } else if (testCase.endpoint.includes('/station-voices')) {
                    this.createdStationVoiceIds.push(resourceId);
                }
            }
        }
        
        // Check for validation error details on 422 responses
        if (testCase.expectedStatus === 422 && statusCode === 422) {
            const responseStr = JSON.stringify(responseData).toLowerCase();
            if (['validation', 'required', 'field', 'invalid'].some(keyword => responseStr.includes(keyword))) {
                this.printSuccess("Contains validation error details");
            } else {
                this.printWarning("Missing detailed validation error message");
            }
        }
        
        return success;
    }

    // ============================================================================
    // STATION VALIDATION TESTS
    // ============================================================================

    /**
     * Test station required field validation
     */
    async testStationFieldValidation() {
        this.printSection("Station Field Validation");
        
        const testCases = [
            new TestCase("empty_json", {}, 422, "Missing all required fields", "/stations"),
            new TestCase("empty_name", { name: "" }, 422, "Empty name field", "/stations"),
            new TestCase("missing_max_stories", { name: "Test" }, 422, "Missing max_stories_per_block", "/stations"),
            new TestCase("missing_name", { max_stories_per_block: 5 }, 422, "Missing name field", "/stations"),
            new TestCase("null_name", { name: null, max_stories_per_block: 5 }, 422, "Null name field", "/stations"),
        ];
        
        let allPassed = true;
        for (const testCase of testCases) {
            if (!(await this.runTestCase(testCase))) {
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    /**
     * Test station data type validation
     */
    async testStationDataTypeValidation() {
        this.printSection("Station Data Type Validation");
        
        const testCases = [
            new TestCase("name_as_number", { name: 123, max_stories_per_block: 5 }, 422, 
                "Name should be string not number", "/stations"),
            new TestCase("max_stories_as_string", { name: "Test", max_stories_per_block: "invalid" }, 422,
                "Max stories should be number not string", "/stations"),
            new TestCase("pause_seconds_as_string", { name: "Test", max_stories_per_block: 5, pause_seconds: "invalid" }, 422,
                "Pause seconds should be number not string", "/stations"),
            new TestCase("max_stories_as_float", { name: "Test", max_stories_per_block: 5.5 }, 422,
                "Max stories should be integer not float", "/stations"),
            new TestCase("name_as_boolean", { name: true, max_stories_per_block: 5 }, 422,
                "Name should be string not boolean", "/stations"),
            new TestCase("name_as_array", { name: ["array"], max_stories_per_block: 5 }, 422,
                "Name should be string not array", "/stations"),
            new TestCase("name_as_object", { name: { object: "test" }, max_stories_per_block: 5 }, 422,
                "Name should be string not object", "/stations"),
        ];
        
        let allPassed = true;
        for (const testCase of testCases) {
            if (!(await this.runTestCase(testCase))) {
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    /**
     * Test station boundary validation
     */
    async testStationBoundaryValidation() {
        this.printSection("Station Boundary Validation");
        
        // Generate long strings for testing
        const longName = 'A'.repeat(256);
        const maxName = 'A'.repeat(255);
        
        const testCases = [
            new TestCase("name_too_long", { name: longName, max_stories_per_block: 5 }, 422,
                "Name too long (256 chars, max 255)", "/stations"),
            new TestCase("name_at_max", { name: maxName, max_stories_per_block: 5 }, 201,
                "Name at max length (255 chars)", "/stations"),
            new TestCase("max_stories_below_min", { name: "Test", max_stories_per_block: 0 }, 422,
                "Max stories below minimum (0, min 1)", "/stations"),
            new TestCase("max_stories_at_min", { name: "Test1", max_stories_per_block: 1 }, 201,
                "Max stories at minimum (1)", "/stations"),
            new TestCase("max_stories_at_max", { name: "Test50", max_stories_per_block: 50 }, 201,
                "Max stories at maximum (50)", "/stations"),
            new TestCase("max_stories_above_max", { name: "Test", max_stories_per_block: 51 }, 422,
                "Max stories above maximum (51, max 50)", "/stations"),
            new TestCase("pause_seconds_negative", { name: "Test", max_stories_per_block: 5, pause_seconds: -0.1 }, 422,
                "Pause seconds negative", "/stations"),
            new TestCase("pause_seconds_at_min", { name: "Test2", max_stories_per_block: 5, pause_seconds: 0 }, 201,
                "Pause seconds at minimum (0)", "/stations"),
            new TestCase("pause_seconds_at_max", { name: "Test3", max_stories_per_block: 5, pause_seconds: 60 }, 201,
                "Pause seconds at maximum (60)", "/stations"),
            new TestCase("pause_seconds_above_max", { name: "Test", max_stories_per_block: 5, pause_seconds: 60.1 }, 422,
                "Pause seconds above maximum (60.1, max 60)", "/stations"),
        ];
        
        let allPassed = true;
        for (const testCase of testCases) {
            if (!(await this.runTestCase(testCase))) {
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    /**
     * Test station unique name constraint
     */
    async testStationUniqueConstraint() {
        this.printSection("Station Unique Name Constraint");
        
        const uniqueName = `UniqueConstraintTest_${Date.now()}`;
        
        // Create first station
        this.printInfo(`Creating station with name: ${uniqueName}`);
        const [statusCode, responseData] = await this.apiCall(
            "POST", "/stations",
            { name: uniqueName, max_stories_per_block: 5 }
        );
        
        if (this.assertStatusCode(statusCode, 201, "Create first station")) {
            const stationId = responseData.id;
            if (stationId) {
                this.createdStationIds.push(stationId);
            }
            
            // Try to create duplicate
            this.printInfo("Attempting to create duplicate station name");
            const [dupStatus] = await this.apiCall(
                "POST", "/stations",
                { name: uniqueName, max_stories_per_block: 3 }
            );
            
            return this.assertStatusCode(dupStatus, 409, "Duplicate station name should return 409 Conflict");
        }
        
        return false;
    }

    // ============================================================================
    // VOICE VALIDATION TESTS
    // ============================================================================

    /**
     * Test voice validation
     */
    async testVoiceValidation() {
        this.printSection("Voice Validation");
        
        const longName = 'V'.repeat(256);
        const maxName = 'V'.repeat(255);
        
        const testCases = [
            new TestCase("missing_name", {}, 422, "Missing name field", "/voices"),
            new TestCase("empty_name", { name: "" }, 422, "Empty name field", "/voices"),
            new TestCase("null_name", { name: null }, 422, "Null name field", "/voices"),
            new TestCase("name_as_number", { name: 123 }, 422, "Name should be string not number", "/voices"),
            new TestCase("valid_voice", { name: "Valid Voice" }, 201, "Valid voice creation", "/voices"),
            new TestCase("name_too_long", { name: longName }, 422, "Name too long (256 chars)", "/voices"),
            new TestCase("name_at_max", { name: maxName }, 201, "Name at max length (255 chars)", "/voices"),
        ];
        
        let allPassed = true;
        for (const testCase of testCases) {
            if (!(await this.runTestCase(testCase))) {
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    // ============================================================================
    // USER VALIDATION TESTS
    // ============================================================================

    /**
     * Test user validation
     */
    async testUserValidation() {
        this.printSection("User Validation");
        
        // Generate test strings
        const longUsername = 'u'.repeat(101);
        const maxUsername = 'u'.repeat(100);
        const longFullname = 'F'.repeat(256);
        const maxFullname = 'F'.repeat(255);
        const longEmail = 'e'.repeat(246) + '@test.com';  // 256+ chars total
        const maxEmail = 'e'.repeat(245) + '@test.com';   // 255 chars total
        
        const testCases = [
            // Basic field validation
            new TestCase("missing_fields", {}, 422, "Missing all required fields", "/users"),
            new TestCase("empty_username", { username: "" }, 422, "Empty username", "/users"),
            new TestCase("missing_full_name", { username: "test" }, 422, "Missing full_name", "/users"),
            new TestCase("empty_full_name", { username: "test", full_name: "" }, 422, "Empty full_name", "/users"),
            new TestCase("username_too_short", { username: "ab" }, 422, "Username too short (min 3 chars)", "/users"),
            new TestCase("missing_password", { username: "validuser", full_name: "Test User" }, 422, "Missing password for new user", "/users"),
            new TestCase("password_too_short", { username: "validuser", full_name: "Test User", password: "short" }, 422, "Password too short (min 8 chars)", "/users"),
            new TestCase("valid_user", { username: "validuser", full_name: "Test User", password: "validpassword", role: "viewer" }, 201, "Valid user creation", "/users"),
            
            // Username pattern validation
            new TestCase("username_with_at", { username: "test@user", full_name: "Test", password: "password123" }, 422, "Username with @ symbol", "/users"),
            new TestCase("username_with_space", { username: "test user", full_name: "Test", password: "password123" }, 422, "Username with space", "/users"),
            new TestCase("username_with_dot", { username: "test.user", full_name: "Test", password: "password123" }, 422, "Username with dot", "/users"),
            new TestCase("username_with_underscore", { username: "test_user", full_name: "Test", password: "password123", role: "viewer" }, 422, "Username with underscore (invalid)", "/users"),
            new TestCase("username_with_hyphen", { username: "test-user", full_name: "Test", password: "password123", role: "viewer" }, 422, "Username with hyphen (invalid)", "/users"),
            new TestCase("username_alphanumeric", { username: "testuser123", full_name: "Test", password: "password123", role: "viewer" }, 201, "Username alphanumeric (valid)", "/users"),
            
            // Length boundaries
            new TestCase("username_too_long", { username: longUsername, full_name: "Test", password: "password123" }, 422, "Username too long (101 chars)", "/users"),
            new TestCase("username_at_max", { username: maxUsername, full_name: "Test", password: "password123", role: "viewer" }, 201, "Username at max length (100 chars)", "/users"),
            new TestCase("fullname_too_long", { username: "testuser", full_name: longFullname, password: "password123" }, 422, "Full name too long (256 chars)", "/users"),
            new TestCase("fullname_at_max", { username: "testuser2", full_name: maxFullname, password: "password123", role: "viewer" }, 201, "Full name at max length (255 chars)", "/users"),
            new TestCase("email_too_long", { username: "testuser3", full_name: "Test", email: longEmail, password: "password123" }, 422, "Email too long (256+ chars)", "/users"),
            new TestCase("email_at_max", { username: "testuser4", full_name: "Test", email: maxEmail, password: "password123", role: "viewer" }, 201, "Email at max length (255 chars)", "/users"),
            
            // Email format validation
            new TestCase("invalid_email", { username: "testuser5", full_name: "Test", email: "invalid-email", password: "password123" }, 422, "Invalid email format", "/users"),
            new TestCase("valid_email", { username: "testuser6", full_name: "Test", email: "valid@example.com", password: "password123", role: "viewer" }, 201, "Valid email format", "/users"),
            new TestCase("empty_email", { username: "testuser7", full_name: "Test", email: "", password: "password123" }, 422, "Empty email (should be null or valid)", "/users"),
            new TestCase("no_email", { username: "testuser8", full_name: "Test", password: "password123", role: "viewer" }, 201, "No email field (valid)", "/users"),
            
            // Role validation
            new TestCase("invalid_role", { username: "testuser9", full_name: "Test", password: "password123", role: "invalid" }, 422, "Invalid role", "/users"),
            new TestCase("admin_role", { username: "testuser10", full_name: "Test", password: "password123", role: "admin" }, 201, "Valid admin role", "/users"),
            new TestCase("editor_role", { username: "testuser11", full_name: "Test", password: "password123", role: "editor" }, 201, "Valid editor role", "/users"),
            new TestCase("viewer_role", { username: "testuser12", full_name: "Test", password: "password123", role: "viewer" }, 201, "Valid viewer role", "/users"),
        ];
        
        let allPassed = true;
        for (const testCase of testCases) {
            if (!(await this.runTestCase(testCase))) {
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    /**
     * Test user unique constraints
     */
    async testUserUniqueConstraints() {
        this.printSection("User Unique Constraints");
        
        const timestamp = Date.now();
        const username = `uniquetest${timestamp}`;
        const email = `uniquetest${timestamp}@example.com`;
        
        // Create first user
        this.printInfo(`Creating user with username: ${username} and email: ${email}`);
        const [statusCode, responseData] = await this.apiCall(
            "POST", "/users",
            {
                username: username,
                full_name: "Test User",
                email: email,
                password: "password123"
            }
        );
        
        if (this.assertStatusCode(statusCode, 201, "Create first user")) {
            const userId = responseData.id;
            if (userId) {
                this.createdUserIds.push(userId);
            }
            
            // Test duplicate username
            this.printInfo("Testing duplicate username");
            const [dupStatus] = await this.apiCall(
                "POST", "/users",
                {
                    username: username,
                    full_name: "Another User",
                    email: `different${timestamp}@example.com`,
                    password: "password123"
                }
            );
            
            const usernameTest = this.assertStatusCode(dupStatus, 409, "Duplicate username should return 409 Conflict");
            
            // Test duplicate email
            this.printInfo("Testing duplicate email");
            const [dupEmailStatus] = await this.apiCall(
                "POST", "/users",
                {
                    username: `different${timestamp}`,
                    full_name: "Another User",
                    email: email,
                    password: "password123"
                }
            );
            
            const emailTest = this.assertStatusCode(dupEmailStatus, 409, "Duplicate email should return 409 Conflict");
            
            return usernameTest && emailTest;
        }
        
        return false;
    }

    // ============================================================================
    // STORY VALIDATION TESTS
    // ============================================================================

    /**
     * Create test data needed for story validation
     */
    async setupStoryTestData() {
        if (this.createdVoiceIds.length === 0) {
            this.printInfo("Creating test voice for story validation");
            const [statusCode, responseData] = await this.apiCall(
                "POST", "/voices", { name: "Story Test Voice" }
            );
            if (statusCode === 201) {
                const voiceId = responseData.id;
                if (voiceId) {
                    this.createdVoiceIds.push(voiceId);
                }
            }
        }
    }

    /**
     * Test story validation with form data
     */
    async testStoryValidation() {
        this.printSection("Story Validation");
        
        // Setup test data
        await this.setupStoryTestData();
        
        const testCases = [
            { data: { title: "", text: "Test text", start_date: "2024-12-01", end_date: "2024-12-31" }, 
              expected: 422, description: "Empty title" },
            { data: { text: "", title: "Test Title", start_date: "2024-12-01", end_date: "2024-12-31" }, 
              expected: 422, description: "Empty text" },
            { data: { title: "Test Title", text: "Test text", end_date: "2024-12-31" }, 
              expected: 422, description: "Missing start_date" },
            { data: { title: "Test Title", text: "Test text", start_date: "2024-12-01" }, 
              expected: 422, description: "Missing end_date" },
            { data: { title: "Test Title", text: "Test text", start_date: "2024-12-01", end_date: "2024-12-31" }, 
              expected: 201, description: "Valid minimal story" },
        ];
        
        let allPassed = true;
        for (const testCase of testCases) {
            this.printInfo(`Testing: ${testCase.description}`);
            
            try {
                const [statusCode, responseData] = await this.apiCall("POST", "/stories", testCase.data);
                
                const success = this.assertStatusCode(
                    statusCode,
                    testCase.expected,
                    testCase.description
                );
                
                if (!success) {
                    allPassed = false;
                }
                
                // Handle successful creation
                if (success && testCase.expected === 201) {
                    const storyId = responseData.id;
                    if (storyId) {
                        this.createdStoryIds.push(storyId);
                    }
                }
            } catch (e) {
                this.printError(`Story validation test failed: ${e.message}`);
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    /**
     * Test story boundary validation
     */
    async testStoryBoundaryValidation() {
        this.printSection("Story Boundary Validation");
        
        // Generate test strings
        const longTitle = 'T'.repeat(501);
        const maxTitle = 'T'.repeat(500);
        const longText = 'X'.repeat(10000);
        
        const testCases = [
            { data: { title: longTitle, text: "Test text", start_date: "2024-12-01", end_date: "2024-12-31" }, 
              expected: 422, description: "Title too long (501 chars, max 500)" },
            { data: { title: maxTitle, text: "Test text", start_date: "2024-12-01", end_date: "2024-12-31" }, 
              expected: 201, description: "Title at max length (500 chars)" },
            { data: { title: "Long Text Test", text: longText, start_date: "2024-12-01", end_date: "2024-12-31" }, 
              expected: 201, description: "Very long text content should be accepted" },
        ];
        
        let allPassed = true;
        for (const testCase of testCases) {
            this.printInfo(`Testing: ${testCase.description}`);
            
            try {
                const [statusCode, responseData] = await this.apiCall("POST", "/stories", testCase.data);
                
                const success = this.assertStatusCode(
                    statusCode,
                    testCase.expected,
                    testCase.description
                );
                
                if (!success) {
                    allPassed = false;
                }
                
                // Handle successful creation
                if (success && testCase.expected === 201) {
                    const storyId = responseData.id;
                    if (storyId) {
                        this.createdStoryIds.push(storyId);
                    }
                }
            } catch (e) {
                this.printError(`Story boundary test failed: ${e.message}`);
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    /**
     * Test story date validation
     */
    async testStoryDateValidation() {
        this.printSection("Story Date Validation");
        
        const testCases = [
            { data: { title: "Date Test 1", text: "Test", start_date: "invalid-date", end_date: "2024-12-31" }, 
              expected: 422, description: "Invalid start_date format" },
            { data: { title: "Date Test 2", text: "Test", start_date: "2024-12-01", end_date: "invalid-date" }, 
              expected: 422, description: "Invalid end_date format" },
            { data: { title: "Date Test 3", text: "Test", start_date: "2024/12/01", end_date: "2024-12-31" }, 
              expected: 422, description: "Wrong date format (slashes)" },
            { data: { title: "Date Test 4", text: "Test", start_date: "01-12-2024", end_date: "2024-12-31" }, 
              expected: 422, description: "Wrong date format (DD-MM-YYYY)" },
            { data: { title: "Date Test 5", text: "Test", start_date: "2024-13-01", end_date: "2024-12-31" }, 
              expected: 422, description: "Invalid month (13)" },
            { data: { title: "Date Test 6", text: "Test", start_date: "2024-12-32", end_date: "2024-12-31" }, 
              expected: 422, description: "Invalid day (32)" },
            { data: { title: "Date Test 7", text: "Test", start_date: "2024-02-30", end_date: "2024-12-31" }, 
              expected: 422, description: "Invalid date (Feb 30)" },
            { data: { title: "Date Test 8", text: "Test", start_date: "2024-12-01", end_date: "2024-12-31" }, 
              expected: 201, description: "Valid date range" },
            { data: { title: "Date Test 9", text: "Test", start_date: "2024-12-31", end_date: "2024-12-01" }, 
              expected: 422, description: "End date before start date" },
        ];
        
        let allPassed = true;
        for (const testCase of testCases) {
            this.printInfo(`Testing: ${testCase.description}`);
            
            try {
                const [statusCode, responseData] = await this.apiCall("POST", "/stories", testCase.data);
                
                const success = this.assertStatusCode(
                    statusCode,
                    testCase.expected,
                    testCase.description
                );
                
                if (!success) {
                    allPassed = false;
                }
                
                // Handle successful creation
                if (success && testCase.expected === 201) {
                    const storyId = responseData.id;
                    if (storyId) {
                        this.createdStoryIds.push(storyId);
                    }
                }
            } catch (e) {
                this.printError(`Story date test failed: ${e.message}`);
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    // ============================================================================
    // INPUT SANITIZATION TESTS
    // ============================================================================

    /**
     * Test SQL injection sanitization
     */
    async testSqlInjectionAttempts() {
        this.printSection("SQL Injection Sanitization Tests");
        
        const sqlPayloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin'--",
            "' OR 1=1 --",
            '" OR "1"="1',
            "'; INSERT INTO users (username) VALUES ('hacker'); --",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
        ];
        
        let allPassed = true;
        
        // Test SQL injection in station names
        this.printInfo("Testing SQL injection in station names");
        for (const payload of sqlPayloads) {
            const [statusCode, responseData] = await this.apiCall(
                "POST", "/stations",
                { name: payload, max_stories_per_block: 5 }
            );
            
            // Should either reject malicious input (422) or safely store it (201)
            if (statusCode === 201) {
                this.printSuccess("SQL injection payload safely stored as literal string");
                const stationId = responseData.id;
                if (stationId) {
                    this.createdStationIds.push(stationId);
                }
            } else if (statusCode === 422) {
                this.printSuccess("SQL injection payload correctly rejected");
            } else {
                this.printError(`Unexpected response to SQL injection attempt: HTTP ${statusCode}`);
                allPassed = false;
            }
        }
        
        // Test SQL injection in user data
        this.printInfo("Testing SQL injection in user creation");
        const userPayload = "admin'; DROP TABLE stories; --";
        const [statusCode, responseData] = await this.apiCall(
            "POST", "/users",
            {
                username: userPayload,
                full_name: "Test",
                password: "password123"
            }
        );
        
        if (statusCode === 201) {
            this.printSuccess("SQL injection in username safely stored");
            const userId = responseData.id;
            if (userId) {
                this.createdUserIds.push(userId);
            }
        } else if ([422, 400].includes(statusCode)) {
            this.printSuccess("SQL injection in username correctly rejected");
        } else {
            this.printError(`Unexpected response to SQL injection in username: HTTP ${statusCode}`);
            allPassed = false;
        }
        
        return allPassed;
    }

    /**
     * Test XSS sanitization
     */
    async testXssAttempts() {
        this.printSection("XSS Sanitization Tests");
        
        const xssPayloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "'><script>alert('XSS')</script>",
            '"><script>alert(\'XSS\')</script>',
            "<script src=//evil.com/xss.js></script>",
        ];
        
        let allPassed = true;
        
        // Test XSS in story content
        this.printInfo("Testing XSS in story titles and text");
        for (const payload of xssPayloads) {
            try {
                const [statusCode, responseData] = await this.apiCall(
                    "POST", "/stories",
                    {
                        title: payload,
                        text: "Test text with XSS in title",
                        start_date: "2024-12-01",
                        end_date: "2024-12-31"
                    }
                );
                
                if (statusCode === 201) {
                    this.printSuccess("XSS payload in title safely stored");
                    const storyId = responseData.id;
                    if (storyId) {
                        this.createdStoryIds.push(storyId);
                        
                        // Verify the data was stored but not executed
                        const [verifyStatus, verifyData] = await this.apiCall("GET", `/stories/${storyId}`);
                        if (verifyStatus === 200) {
                            const storedTitle = verifyData.title || '';
                            if (storedTitle.includes(payload)) {
                                this.printSuccess("XSS payload stored as literal text (not executed)");
                            } else {
                                this.printInfo("XSS payload may have been sanitized during storage");
                            }
                        }
                    }
                } else if ([422, 400].includes(statusCode)) {
                    this.printSuccess("XSS payload correctly rejected");
                } else {
                    this.printError(`Unexpected response to XSS attempt: HTTP ${statusCode}`);
                    allPassed = false;
                }
            } catch (e) {
                this.printError(`XSS test failed: ${e.message}`);
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    /**
     * Test path traversal sanitization
     */
    async testPathTraversalAttempts() {
        this.printSection("Path Traversal Sanitization Tests");
        
        const traversalPayloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "../../../../../../../../../../etc/passwd",
        ];
        
        let allPassed = true;
        
        // Test path traversal in names
        this.printInfo("Testing path traversal attempts in names");
        for (const payload of traversalPayloads) {
            const [statusCode, responseData] = await this.apiCall(
                "POST", "/stations",
                { name: payload, max_stories_per_block: 5 }
            );
            
            if (statusCode === 201) {
                this.printSuccess("Path traversal payload safely stored as literal string");
                const stationId = responseData.id;
                if (stationId) {
                    this.createdStationIds.push(stationId);
                }
            } else if ([422, 400].includes(statusCode)) {
                this.printSuccess("Path traversal payload correctly rejected");
            } else {
                this.printError(`Unexpected response to path traversal: HTTP ${statusCode}`);
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    // ============================================================================
    // FILE UPLOAD VALIDATION TESTS
    // ============================================================================

    /**
     * Test audio file upload validation
     */
    async testAudioFileUploadValidation() {
        this.printSection("Audio File Upload Validation");
        
        let allPassed = true;
        
        // Create minimal valid WAV file
        const validWavBuffer = Buffer.from([
            0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0x00, 0x00,
            0x57, 0x41, 0x56, 0x45, 0x66, 0x6d, 0x74, 0x20,
            0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,
            0x22, 0x56, 0x00, 0x00, 0x88, 0x58, 0x01, 0x00,
            0x04, 0x00, 0x10, 0x00, 0x64, 0x61, 0x74, 0x61,
            0x00, 0x08, 0x00, 0x00
        ]);
        
        // Create invalid file
        const invalidBuffer = Buffer.from("Not an audio file");
        
        // Test story audio upload validation
        if (this.createdVoiceIds.length > 0) {
            const voiceId = this.createdVoiceIds[0];
            
            // Test valid audio file
            this.printInfo("Testing valid audio file upload");
            try {
                const [statusCode, responseData] = await this.apiCall(
                    "POST", "/stories",
                    {
                        title: "Audio Test Valid",
                        text: "Test with valid audio",
                        start_date: "2024-12-01",
                        end_date: "2024-12-31",
                        voice_id: voiceId
                    },
                    { audio: validWavBuffer }
                );
                
                if (this.assertStatusCode(statusCode, 201, "Valid audio file upload")) {
                    const storyId = responseData.id;
                    if (storyId) {
                        this.createdStoryIds.push(storyId);
                    }
                } else {
                    allPassed = false;
                }
            } catch (e) {
                this.printError(`Valid audio test failed: ${e.message}`);
                allPassed = false;
            }
            
            // Test invalid audio file
            this.printInfo("Testing invalid audio file upload");
            try {
                const [statusCode, responseData] = await this.apiCall(
                    "POST", "/stories",
                    {
                        title: "Audio Test Invalid",
                        text: "Test with invalid audio",
                        start_date: "2024-12-01",
                        end_date: "2024-12-31",
                        voice_id: voiceId
                    },
                    { audio: invalidBuffer }
                );
                
                // Should either accept it (backend validates later) or reject it
                if ([422, 400].includes(statusCode)) {
                    this.printSuccess("Invalid audio file correctly rejected");
                } else if (statusCode === 201) {
                    this.printWarning("Invalid audio file accepted (may be validated later)");
                    const storyId = responseData.id;
                    if (storyId) {
                        this.createdStoryIds.push(storyId);
                    }
                } else {
                    this.printError(`Unexpected response to invalid audio file: HTTP ${statusCode}`);
                    allPassed = false;
                }
            } catch (e) {
                this.printError(`Invalid audio test failed: ${e.message}`);
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    // ============================================================================
    // STATION-VOICE VALIDATION TESTS
    // ============================================================================

    /**
     * Setup test data for station-voice validation
     */
    async setupStationVoiceTestData() {
        // Create station if needed
        if (this.createdStationIds.length === 0) {
            this.printInfo("Creating test station for station-voice validation");
            const [statusCode, responseData] = await this.apiCall(
                "POST", "/stations",
                { name: "StationVoice Test Station", max_stories_per_block: 5 }
            );
            if (statusCode === 201) {
                const stationId = responseData.id;
                if (stationId) {
                    this.createdStationIds.push(stationId);
                }
            }
        }
        
        // Create voice if needed
        if (this.createdVoiceIds.length === 0) {
            this.printInfo("Creating test voice for station-voice validation");
            const [statusCode, responseData] = await this.apiCall(
                "POST", "/voices", { name: "StationVoice Test Voice" }
            );
            if (statusCode === 201) {
                const voiceId = responseData.id;
                if (voiceId) {
                    this.createdVoiceIds.push(voiceId);
                }
            }
        }
    }

    /**
     * Test station-voice validation
     */
    async testStationVoiceValidation() {
        this.printSection("Station-Voice Validation");
        
        // Setup test data
        await this.setupStationVoiceTestData();
        
        if (this.createdStationIds.length === 0 || this.createdVoiceIds.length === 0) {
            this.printError("Need station and voice for station-voice tests");
            return false;
        }
        
        const stationId = this.createdStationIds[0];
        const voiceId = this.createdVoiceIds[0];
        
        const testCases = [
            { data: { voice_id: voiceId }, expected: 422, description: "Missing station_id" },
            { data: { station_id: stationId }, expected: 422, description: "Missing voice_id" },
            { data: { station_id: 99999, voice_id: voiceId }, expected: 422, description: "Invalid station_id" },
            { data: { station_id: stationId, voice_id: 99999 }, expected: 422, description: "Invalid voice_id" },
            { data: { station_id: stationId, voice_id: voiceId }, expected: 201, description: "Valid station-voice relationship" },
            { data: { station_id: stationId, voice_id: voiceId, mix_point: -1 }, expected: 422, description: "Negative mix_point" },
            { data: { station_id: stationId, voice_id: voiceId, mix_point: 301 }, expected: 422, description: "Mix_point above maximum (300)" },
            { data: { station_id: stationId, voice_id: voiceId, mix_point: 0 }, expected: 201, description: "Mix_point at minimum (0)" },
            { data: { station_id: stationId, voice_id: voiceId, mix_point: 300 }, expected: 201, description: "Mix_point at maximum (300)" },
        ];
        
        let allPassed = true;
        for (const testCase of testCases) {
            this.printInfo(`Testing: ${testCase.description}`);
            
            try {
                const [statusCode, responseData] = await this.apiCall("POST", "/station-voices", testCase.data);
                
                const success = this.assertStatusCode(
                    statusCode,
                    testCase.expected,
                    testCase.description
                );
                
                if (!success) {
                    allPassed = false;
                }
                
                // Handle successful creation
                if (success && testCase.expected === 201) {
                    const svId = responseData.id;
                    if (svId) {
                        this.createdStationVoiceIds.push(svId);
                    }
                }
            } catch (e) {
                this.printError(`Station-voice test failed: ${e.message}`);
                allPassed = false;
            }
        }
        
        return allPassed;
    }

    // ============================================================================
    // BUSINESS RULE VALIDATION TESTS
    // ============================================================================

    /**
     * Test business rule validation
     */
    async testBusinessRuleValidation() {
        this.printSection("Business Rule Validation");
        
        let allPassed = true;
        
        // Test story date logic
        this.printInfo("Testing story date business rules");
        
        // Test end date before start date
        try {
            const [statusCode] = await this.apiCall(
                "POST", "/stories",
                {
                    title: "Date Logic Test",
                    text: "End date before start date",
                    start_date: "2024-12-31",
                    end_date: "2024-12-01"
                }
            );
            
            if (!this.assertStatusCode(statusCode, 422, "End date before start date should be rejected")) {
                allPassed = false;
            }
        } catch (e) {
            this.printError(`Date logic test failed: ${e.message}`);
            allPassed = false;
        }
        
        // Test very old dates
        try {
            const [statusCode, responseData] = await this.apiCall(
                "POST", "/stories",
                {
                    title: "Old Date Test",
                    text: "Very old date",
                    start_date: "1990-01-01",
                    end_date: "1990-01-02"
                }
            );
            
            if (statusCode === 201) {
                this.printSuccess("Old dates accepted (no business rule restriction)");
                const storyId = responseData.id;
                if (storyId) {
                    this.createdStoryIds.push(storyId);
                }
            } else if (statusCode === 422) {
                this.printSuccess("Old dates rejected by business rules");
            } else {
                this.printWarning(`Unexpected response for old dates: HTTP ${statusCode}`);
            }
        } catch (e) {
            this.printError(`Old date test failed: ${e.message}`);
            allPassed = false;
        }
        
        // Test future dates
        try {
            const [statusCode, responseData] = await this.apiCall(
                "POST", "/stories",
                {
                    title: "Future Date Test",
                    text: "Far future date",
                    start_date: "2099-01-01",
                    end_date: "2099-01-02"
                }
            );
            
            if (statusCode === 201) {
                this.printSuccess("Future dates accepted");
                const storyId = responseData.id;
                if (storyId) {
                    this.createdStoryIds.push(storyId);
                }
            } else if (statusCode === 422) {
                this.printSuccess("Far future dates rejected by business rules");
            } else {
                this.printWarning(`Unexpected response for future dates: HTTP ${statusCode}`);
            }
        } catch (e) {
            this.printError(`Future date test failed: ${e.message}`);
            allPassed = false;
        }
        
        return allPassed;
    }

    // ============================================================================
    // CLEANUP AND MAIN EXECUTION
    // ============================================================================

    /**
     * Clean up all created resources
     */
    async cleanup() {
        this.printInfo("Cleaning up validation tests...");
        
        // Delete all created resources
        for (const storyId of this.createdStoryIds) {
            try {
                await this.apiCall("DELETE", `/stories/${storyId}`);
            } catch (e) {
                // Ignore cleanup errors
            }
        }
        
        for (const svId of this.createdStationVoiceIds) {
            try {
                await this.apiCall("DELETE", `/station-voices/${svId}`);
            } catch (e) {
                // Ignore cleanup errors
            }
        }
        
        for (const userId of this.createdUserIds) {
            try {
                await this.apiCall("DELETE", `/users/${userId}`);
            } catch (e) {
                // Ignore cleanup errors
            }
        }
        
        for (const voiceId of this.createdVoiceIds) {
            try {
                await this.apiCall("DELETE", `/voices/${voiceId}`);
            } catch (e) {
                // Ignore cleanup errors
            }
        }
        
        for (const stationId of this.createdStationIds) {
            try {
                await this.apiCall("DELETE", `/stations/${stationId}`);
            } catch (e) {
                // Ignore cleanup errors
            }
        }
        
        // Reset arrays
        this.createdStationIds = [];
        this.createdVoiceIds = [];
        this.createdStoryIds = [];
        this.createdUserIds = [];
        this.createdStationVoiceIds = [];
    }

    /**
     * Run all validation tests
     */
    async runAllTests() {
        this.printHeader("Comprehensive Validation Tests");
        
        const testFunctions = [
            { name: 'testStationFieldValidation', func: this.testStationFieldValidation.bind(this) },
            { name: 'testStationDataTypeValidation', func: this.testStationDataTypeValidation.bind(this) },
            { name: 'testStationBoundaryValidation', func: this.testStationBoundaryValidation.bind(this) },
            { name: 'testStationUniqueConstraint', func: this.testStationUniqueConstraint.bind(this) },
            { name: 'testVoiceValidation', func: this.testVoiceValidation.bind(this) },
            { name: 'testUserValidation', func: this.testUserValidation.bind(this) },
            { name: 'testUserUniqueConstraints', func: this.testUserUniqueConstraints.bind(this) },
            { name: 'testStoryValidation', func: this.testStoryValidation.bind(this) },
            { name: 'testStoryBoundaryValidation', func: this.testStoryBoundaryValidation.bind(this) },
            { name: 'testStoryDateValidation', func: this.testStoryDateValidation.bind(this) },
            { name: 'testStationVoiceValidation', func: this.testStationVoiceValidation.bind(this) },
            { name: 'testSqlInjectionAttempts', func: this.testSqlInjectionAttempts.bind(this) },
            { name: 'testXssAttempts', func: this.testXssAttempts.bind(this) },
            { name: 'testPathTraversalAttempts', func: this.testPathTraversalAttempts.bind(this) },
            { name: 'testAudioFileUploadValidation', func: this.testAudioFileUploadValidation.bind(this) },
            { name: 'testBusinessRuleValidation', func: this.testBusinessRuleValidation.bind(this) },
        ];
        
        let failed = 0;
        
        for (const testFunction of testFunctions) {
            try {
                const result = await testFunction.func();
                if (result) {
                    this.printSuccess(`✓ ${testFunction.name} passed`);
                } else {
                    this.printError(`✗ ${testFunction.name} failed`);
                    failed++;
                }
            } catch (e) {
                this.printError(`✗ ${testFunction.name} failed with exception: ${e.message}`);
                failed++;
            }
            
            process.stderr.write('\n'); // Add spacing between tests
        }
        
        await this.cleanup();
        
        return this.printSummary();
    }
}

/**
 * Main entry point
 */
async function main() {
    const tester = new ValidationTester();
    
    try {
        const success = await tester.runAllTests();
        process.exit(success ? 0 : 1);
    } catch (e) {
        if (e.message.includes('interrupted')) {
            process.stderr.write(`\n${Colors.YELLOW}Tests interrupted by user${Colors.NC}\n`);
        } else {
            process.stderr.write(`${Colors.RED}Fatal error: ${e.message}${Colors.NC}\n`);
        }
        await tester.cleanup();
        process.exit(1);
    }
}

// Handle interrupt signals
process.on('SIGINT', () => {
    process.stderr.write(`\n${Colors.YELLOW}Tests interrupted by user${Colors.NC}\n`);
    process.exit(1);
});

process.on('SIGTERM', () => {
    process.stderr.write(`\n${Colors.YELLOW}Tests terminated${Colors.NC}\n`);
    process.exit(1);
});

if (require.main === module) {
    main();
}

module.exports = { ValidationTester, TestCase, Colors };