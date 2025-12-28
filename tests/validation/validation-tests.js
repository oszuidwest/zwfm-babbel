#!/usr/bin/env node

// Babbel validation tests - Node.js implementation.
// 
// Comprehensive validation testing for all API endpoints with proper JSON handling.
// Tests field validation, data types, boundaries, business rules, and input sanitization.
// 
// This script replaces the bash implementation to solve JSON parsing issues when
// using colons as delimiters in test data that also contains colons.

const fs = require('fs');
const path = require('path');
const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

// Enum for test result types.
const TestResult = {
    PASS: "PASS",
    FAIL: "FAIL",
    SKIP: "SKIP"
};

/**
 * Represents a single test case.
 * @class
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
 * Main class for running validation tests.
 * @class
 */
class ValidationTester extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);
        
        // Created resources for cleanup
        this.createdStationIds = [];
        this.createdVoiceIds = [];
        this.createdStoryIds = [];
        this.createdUserIds = [];
        this.createdStationVoiceIds = [];
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
        
        const response = await this.apiCall(
            testCase.method,
            testCase.endpoint,
            testCase.data
        );
        
        const success = this.assertStatusCode(
            response.status,
            testCase.expectedStatus,
            testCase.description
        );
        
        // Handle successful creation responses
        if (success && testCase.expectedStatus === 201) {
            const resourceId = this.parseJsonField(response.data, 'id');
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
        
        return success;
    }

    /**
     * Test station field validation
     */
    async testStationFieldValidation() {
        this.printSection("Station Field Validation Tests");
        
        const testCases = [
            new TestCase("empty_name", {}, 422, "Empty station name should be rejected", "/stations"),
            new TestCase("missing_name", { max_stories_per_block: 5, pause_seconds: 2.0 }, 422, "Missing name field", "/stations"),
            new TestCase("null_name", { name: null, max_stories_per_block: 5, pause_seconds: 2.0 }, 422, "Null name field", "/stations"),
            new TestCase("empty_string_name", { name: "", max_stories_per_block: 5, pause_seconds: 2.0 }, 422, "Empty string name", "/stations"),
            new TestCase("whitespace_name", { name: "   ", max_stories_per_block: 5, pause_seconds: 2.0 }, 422, "Whitespace-only name", "/stations"),
        ];
        
        let passed = 0;
        for (const testCase of testCases) {
            if (await this.runTestCase(testCase)) {
                passed++;
            }
        }
        
        return passed === testCases.length;
    }

    /**
     * Test station data type validation
     */
    async testStationDataTypeValidation() {
        this.printSection("Station Data Type Validation Tests");
        
        const testCases = [
            new TestCase("string_max_stories", { name: "Test Station", max_stories_per_block: "invalid", pause_seconds: 2.0 }, 422, "String max_stories_per_block", "/stations"),
            new TestCase("negative_max_stories", { name: "Test Station", max_stories_per_block: -1, pause_seconds: 2.0 }, 422, "Negative max_stories_per_block", "/stations"),
            new TestCase("zero_max_stories", { name: "Test Station", max_stories_per_block: 0, pause_seconds: 2.0 }, 422, "Zero max_stories_per_block", "/stations"),
            new TestCase("float_max_stories", { name: "Test Station", max_stories_per_block: 5.5, pause_seconds: 2.0 }, 422, "Float max_stories_per_block", "/stations"),
            new TestCase("string_pause_seconds", { name: "Test Station", max_stories_per_block: 5, pause_seconds: "invalid" }, 422, "String pause_seconds", "/stations"),
            new TestCase("negative_pause_seconds", { name: "Test Station", max_stories_per_block: 5, pause_seconds: -1.0 }, 422, "Negative pause_seconds", "/stations"),
        ];
        
        let passed = 0;
        for (const testCase of testCases) {
            if (await this.runTestCase(testCase)) {
                passed++;
            }
        }
        
        return passed === testCases.length;
    }

    /**
     * Test station boundary validation
     */
    async testStationBoundaryValidation() {
        this.printSection("Station Boundary Validation Tests");
        
        const testCases = [
            new TestCase("large_max_stories", { name: "Test Station", max_stories_per_block: 1000000, pause_seconds: 2.0 }, 422, "Very large max_stories_per_block", "/stations"),
            new TestCase("large_pause_seconds", { name: "Test Station", max_stories_per_block: 5, pause_seconds: 999999.99 }, 422, "Very large pause_seconds", "/stations"),
            new TestCase("long_station_name", { name: "A".repeat(300), max_stories_per_block: 5, pause_seconds: 2.0 }, 422, "Very long station name", "/stations"),
        ];
        
        let passed = 0;
        for (const testCase of testCases) {
            if (await this.runTestCase(testCase)) {
                passed++;
            }
        }
        
        return passed === testCases.length;
    }

    /**
     * Test station unique constraint
     */
    async testStationUniqueConstraint() {
        this.printSection("Station Unique Constraint Tests");
        
        // First create a station
        const uniqueName = `UniqueTest_${Date.now()}`;
        const createResponse = await this.apiCall('POST', '/stations', {
            name: uniqueName,
            max_stories_per_block: 5,
            pause_seconds: 2.0
        });
        
        if (createResponse.status !== 201) {
            this.printError("Failed to create initial station for unique constraint test");
            return false;
        }
        
        const stationId = this.parseJsonField(createResponse.data, 'id');
        if (stationId) {
            this.createdStationIds.push(stationId);
        }
        
        // Try to create another station with the same name
        const duplicateResponse = await this.apiCall('POST', '/stations', {
            name: uniqueName,
            max_stories_per_block: 3,
            pause_seconds: 1.5
        });
        
        return this.assertStatusCode(duplicateResponse.status, 409, "Duplicate station name should be rejected");
    }

    /**
     * Test voice validation
     */
    async testVoiceValidation() {
        this.printSection("Voice Validation Tests");
        
        const testCases = [
            new TestCase("empty_voice_data", {}, 422, "Empty voice data", "/voices"),
            new TestCase("missing_voice_name", { description: "Test voice" }, 422, "Missing voice name", "/voices"),
            new TestCase("null_voice_name", { name: null }, 422, "Null voice name", "/voices"),
            new TestCase("empty_voice_name", { name: "" }, 422, "Empty voice name", "/voices"),
            new TestCase("whitespace_voice_name", { name: "   " }, 422, "Whitespace voice name", "/voices"),
            new TestCase("long_voice_name", { name: "A".repeat(300) }, 422, "Very long voice name", "/voices"),
        ];
        
        let passed = 0;
        for (const testCase of testCases) {
            if (await this.runTestCase(testCase)) {
                passed++;
            }
        }
        
        return passed === testCases.length;
    }

    /**
     * Test user validation
     */
    async testUserValidation() {
        this.printSection("User Validation Tests");
        
        const testCases = [
            new TestCase("empty_user_data", {}, 422, "Empty user data", "/users"),
            new TestCase("missing_username", { full_name: "Test User", password: "test1234", role: "viewer" }, 422, "Missing username", "/users"),
            new TestCase("empty_username", { username: "", full_name: "Test User", password: "test1234", role: "viewer" }, 422, "Empty username", "/users"),
            new TestCase("missing_password", { username: "testuser", full_name: "Test User", role: "viewer" }, 422, "Missing password", "/users"),
            new TestCase("empty_password", { username: "testuser", full_name: "Test User", password: "", role: "viewer" }, 422, "Empty password", "/users"),
            new TestCase("invalid_role", { username: "testuser", full_name: "Test User", password: "test1234", role: "invalid" }, 422, "Invalid role", "/users"),
            new TestCase("missing_role", { username: "testuser", full_name: "Test User", password: "test1234" }, 422, "Missing role", "/users"),
        ];
        
        let passed = 0;
        for (const testCase of testCases) {
            if (await this.runTestCase(testCase)) {
                passed++;
            }
        }
        
        return passed === testCases.length;
    }

    /**
     * Test user unique constraints
     */
    async testUserUniqueConstraints() {
        this.printSection("User Unique Constraint Tests");
        
        // Create a user (no underscores - only alphanumeric allowed)
        const uniqueUsername = `uniquetest${Date.now()}`;
        const createResponse = await this.apiCall('POST', '/users', {
            username: uniqueUsername,
            full_name: "Unique Test User",
            password: "test1234",  // Minimum 8 characters
            role: "viewer"
        });
        
        if (createResponse.status !== 201) {
            this.printError(`Failed to create initial user for unique constraint test: ${createResponse.status}`);
            if (createResponse.data) {
                this.printError(`Response: ${JSON.stringify(createResponse.data)}`);
            }
            return false;
        }
        
        const userId = this.parseJsonField(createResponse.data, 'id');
        if (userId) {
            this.createdUserIds.push(userId);
        }
        
        // Try to create another user with the same username
        const duplicateResponse = await this.apiCall('POST', '/users', {
            username: uniqueUsername,
            full_name: "Another User",
            password: "test4567",  // Minimum 8 characters
            role: "editor"
        });
        
        return this.assertStatusCode(duplicateResponse.status, 409, "Duplicate username should be rejected");
    }

    /**
     * Test story validation
     */
    async testStoryValidation() {
        this.printSection("Story Validation Tests");
        
        // First create a voice for the story tests
        const voiceResponse = await this.apiCall('POST', '/voices', { name: `TestVoice_${Date.now()}` });
        if (voiceResponse.status !== 201) {
            this.printError("Failed to create voice for story validation tests");
            return false;
        }
        const voiceId = this.parseJsonField(voiceResponse.data, 'id');
        if (voiceId) {
            this.createdVoiceIds.push(voiceId);
        }
        
        const testCases = [
            new TestCase("empty_story_data", {}, 422, "Empty story data", "/stories"),
            new TestCase("missing_title", { text: "Test content", voice_id: voiceId }, 422, "Missing title", "/stories"),
            new TestCase("empty_title", { title: "", text: "Test content", voice_id: voiceId }, 422, "Empty title", "/stories"),
            new TestCase("missing_text", { title: "Test Story", voice_id: voiceId }, 422, "Missing text", "/stories"),
            new TestCase("empty_text", { title: "Test Story", text: "", voice_id: voiceId }, 422, "Empty text", "/stories"),
            // Note: voice_id is optional in the API, so missing voice_id creates a story successfully
            new TestCase("missing_voice_id", { title: "Test Story", text: "Test content" }, 201, "Missing voice_id (optional field)", "/stories"),
            // Invalid voice_id returns 404 (not found) rather than 422 (validation error)
            new TestCase("invalid_voice_id", { title: "Test Story", text: "Test content", voice_id: 99999 }, 404, "Invalid voice_id", "/stories"),
        ];
        
        let passed = 0;
        for (const testCase of testCases) {
            // Create JSON body for story tests (pure JSON API)
            const jsonBody = Object.assign({}, testCase.data);
            if (!jsonBody.status) jsonBody.status = 'active';
            if (!jsonBody.start_date) jsonBody.start_date = '2024-01-01';
            if (!jsonBody.end_date) jsonBody.end_date = '2024-12-31';
            if (jsonBody.monday === undefined) jsonBody.monday = true;
            if (jsonBody.tuesday === undefined) jsonBody.tuesday = true;
            if (jsonBody.wednesday === undefined) jsonBody.wednesday = true;
            if (jsonBody.thursday === undefined) jsonBody.thursday = true;
            if (jsonBody.friday === undefined) jsonBody.friday = true;
            if (jsonBody.saturday === undefined) jsonBody.saturday = false;
            if (jsonBody.sunday === undefined) jsonBody.sunday = false;

            const response = await this.apiCall('POST', '/stories', jsonBody);
            
            // If a story was successfully created (201), track it for cleanup
            if (response.status === 201) {
                const storyId = this.parseJsonField(response.data, 'id');
                if (storyId) {
                    this.createdStoryIds.push(storyId);
                }
            }
            
            const success = this.assertStatusCode(
                response.status,
                testCase.expectedStatus,
                testCase.description
            );
            
            if (success) passed++;
        }
        
        return passed === testCases.length;
    }

    /**
     * Test story boundary validation
     */
    async testStoryBoundaryValidation() {
        this.printSection("Story Boundary Validation Tests");
        
        // Create a voice
        const voiceResponse = await this.apiCall('POST', '/voices', { name: `BoundaryTestVoice_${Date.now()}` });
        const voiceId = this.parseJsonField(voiceResponse.data, 'id');
        if (voiceId) {
            this.createdVoiceIds.push(voiceId);
        }
        
        // Test actual database limits
        const tooLongTitle = "A".repeat(501);  // Title is VARCHAR(500)
        const acceptableText = "B".repeat(10000);  // TEXT field can handle this
        const tooLongText = "C".repeat(70000);  // Exceeds typical TEXT field limit (65535)
        
        const testCases = [
            { data: { title: tooLongTitle, text: "Test", voice_id: voiceId }, expected: 422, description: "Title exceeding 500 chars" },
            { data: { title: "Test", text: tooLongText, voice_id: voiceId }, expected: 422, description: "Text exceeding limit" },
        ];
        
        let passed = 0;
        for (const testCase of testCases) {
            const jsonBody = Object.assign({}, testCase.data, {
                status: 'active',
                start_date: '2024-01-01',
                end_date: '2024-12-31',
                monday: true,
                tuesday: true,
                wednesday: true,
                thursday: true,
                friday: true,
                saturday: false,
                sunday: false
            });

            const response = await this.apiCall('POST', '/stories', jsonBody);
            
            // Track successfully created stories for cleanup
            if (response.status === 201) {
                const storyId = this.parseJsonField(response.data, 'id');
                if (storyId) {
                    this.createdStoryIds.push(storyId);
                }
            }
            
            if (response.status !== testCase.expected) {
                this.printError(`${testCase.description}: expected ${testCase.expected}, got ${response.status}`);
                if (response.data) {
                    this.printError(`Response: ${JSON.stringify(response.data)}`);
                }
            } else {
                this.printSuccess(`${testCase.description}: expected ${testCase.expected}, got ${response.status}`);
                passed++;
            }
        }
        
        return passed === testCases.length;
    }

    /**
     * Test story date validation
     */
    async testStoryDateValidation() {
        this.printSection("Story Date Validation Tests");
        
        // Create a voice
        const voiceResponse = await this.apiCall('POST', '/voices', { name: `DateTestVoice_${Date.now()}` });
        const voiceId = this.parseJsonField(voiceResponse.data, 'id');
        if (voiceId) {
            this.createdVoiceIds.push(voiceId);
        }
        
        const testCases = [
            { data: { title: "Test", text: "Test", voice_id: voiceId, start_date: "invalid-date" }, expected: 422, description: "Invalid start date" },
            { data: { title: "Test", text: "Test", voice_id: voiceId, end_date: "invalid-date" }, expected: 422, description: "Invalid end date" },
            { data: { title: "Test", text: "Test", voice_id: voiceId, start_date: "2024-12-31", end_date: "2024-01-01" }, expected: 422, description: "End date before start date" },
        ];
        
        let passed = 0;
        for (const testCase of testCases) {
            const jsonBody = Object.assign({
                status: 'active',
                start_date: '2024-01-01',
                end_date: '2024-12-31',
                monday: true,
                tuesday: true,
                wednesday: true,
                thursday: true,
                friday: true,
                saturday: false,
                sunday: false
            }, testCase.data);

            const response = await this.apiCall('POST', '/stories', jsonBody);

            if (this.assertStatusCode(response.status, testCase.expected, testCase.description)) {
                passed++;
            }
        }

        return passed === testCases.length;
    }

    /**
     * Test station-voice validation
     */
    async testStationVoiceValidation() {
        this.printSection("Station-Voice Validation Tests");
        
        const testCases = [
            new TestCase("empty_sv_data", {}, 422, "Empty station-voice data", "/station-voices"),
            new TestCase("missing_station_id", { voice_id: 1, mix_point: 3.0 }, 422, "Missing station_id", "/station-voices"),
            new TestCase("missing_voice_id", { station_id: 1, mix_point: 3.0 }, 422, "Missing voice_id", "/station-voices"),
            new TestCase("invalid_station_id", { station_id: 99999, voice_id: 1, mix_point: 3.0 }, 404, "Invalid station_id (not found)", "/station-voices"),
            new TestCase("invalid_voice_id", { station_id: 1, voice_id: 99999, mix_point: 3.0 }, 404, "Invalid voice_id (not found)", "/station-voices"),
            new TestCase("negative_mix_point", { station_id: 1, voice_id: 1, mix_point: -1.0 }, 422, "Negative mix_point", "/station-voices"),
        ];
        
        let passed = 0;
        for (const testCase of testCases) {
            // Pure JSON API - no form-data
            const response = await this.apiCall('POST', '/station-voices', testCase.data);

            if (this.assertStatusCode(response.status, testCase.expectedStatus, testCase.description)) {
                passed++;
            }
        }

        return passed === testCases.length;
    }

    /**
     * Test SQL injection attempts
     */
    async testSqlInjectionAttempts() {
        this.printSection("SQL Injection Attempts");
        
        const sqlPayloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; SELECT * FROM users; --",
            "' UNION SELECT password FROM users --",
            "admin'--",
            "admin' OR '1'='1' --"
        ];
        
        let passed = 0;
        for (const payload of sqlPayloads) {
            this.printInfo(`Testing SQL injection with payload: ${payload}`);
            
            const response = await this.apiCall('POST', '/stations', {
                name: payload,
                max_stories_per_block: 5,
                pause_seconds: 2.0
            });
            
            // Should be rejected (422) or safely handled (201/409)
            if (response.status === 422 || response.status === 409 || response.status === 201) {
                this.printSuccess(`SQL injection payload safely handled: ${response.status}`);
                passed++;
                
                // Clean up if created
                if (response.status === 201) {
                    const stationId = this.parseJsonField(response.data, 'id');
                    if (stationId) {
                        this.createdStationIds.push(stationId);
                    }
                }
            } else {
                this.printError(`SQL injection payload caused unexpected response: ${response.status}`);
            }
        }
        
        return passed === sqlPayloads.length;
    }

    /**
     * Test XSS attempts
     */
    async testXssAttempts() {
        this.printSection("XSS Attempts");
        
        const xssPayloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg/onload=alert('xss')>",
            "'><script>alert('xss')</script>",
        ];
        
        let passed = 0;
        for (const payload of xssPayloads) {
            this.printInfo(`Testing XSS with payload: ${payload}`);
            
            const response = await this.apiCall('POST', '/stations', {
                name: payload,
                max_stories_per_block: 5,
                pause_seconds: 2.0
            });
            
            // Should be safely handled
            if (response.status === 422 || response.status === 409 || response.status === 201) {
                this.printSuccess(`XSS payload safely handled: ${response.status}`);
                passed++;
                
                // Clean up if created
                if (response.status === 201) {
                    const stationId = this.parseJsonField(response.data, 'id');
                    if (stationId) {
                        this.createdStationIds.push(stationId);
                    }
                }
            } else {
                this.printError(`XSS payload caused unexpected response: ${response.status}`);
            }
        }
        
        return passed === xssPayloads.length;
    }

    /**
     * Test path traversal attempts
     */
    async testPathTraversalAttempts() {
        this.printSection("Path Traversal Attempts");
        
        const pathPayloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ];
        
        let passed = 0;
        for (const payload of pathPayloads) {
            this.printInfo(`Testing path traversal with payload: ${payload}`);
            
            const response = await this.apiCall('POST', '/stations', {
                name: payload,
                max_stories_per_block: 5,
                pause_seconds: 2.0
            });
            
            // Should be safely handled
            if (response.status === 422 || response.status === 409 || response.status === 201) {
                this.printSuccess(`Path traversal payload safely handled: ${response.status}`);
                passed++;
                
                // Clean up if created
                if (response.status === 201) {
                    const stationId = this.parseJsonField(response.data, 'id');
                    if (stationId) {
                        this.createdStationIds.push(stationId);
                    }
                }
            } else {
                this.printError(`Path traversal payload caused unexpected response: ${response.status}`);
            }
        }
        
        return passed === pathPayloads.length;
    }

    /**
     * Test audio file upload validation
     */
    async testAudioFileUploadValidation() {
        this.printSection("Audio File Upload Validation");

        // Create a voice first
        const voiceResponse = await this.apiCall('POST', '/voices', { name: `AudioTestVoice_${Date.now()}` });
        const voiceId = this.parseJsonField(voiceResponse.data, 'id');
        if (voiceId) {
            this.createdVoiceIds.push(voiceId);
        }

        // Test story creation without audio (pure JSON API - audio is separate endpoint)
        const noFileResponse = await this.apiCall('POST', '/stories', {
            title: "No File Test",
            text: "Test content",
            voice_id: voiceId,
            status: 'active',
            start_date: '2024-01-01',
            end_date: '2024-12-31',
            monday: true,
            tuesday: false,
            wednesday: false,
            thursday: false,
            friday: false,
            saturday: false,
            sunday: false
        });

        let passed = 0;
        if (noFileResponse.status === 201) {
            this.printSuccess("Story creation without audio file allowed (pure JSON API)");
            passed++;

            const storyId = this.parseJsonField(noFileResponse.data, 'id');
            if (storyId) {
                this.createdStoryIds.push(storyId);
            }
        } else {
            this.printError(`Story creation rejected: ${noFileResponse.status}`);
        }

        return passed >= 1;
    }

    /**
     * Test business rule validation
     */
    async testBusinessRuleValidation() {
        this.printSection("Business Rule Validation");
        
        // Test minimum reasonable values
        const minValueTests = [
            { data: { name: "Min Test", max_stories_per_block: 1, pause_seconds: 0.1 }, expected: 201, description: "Minimum reasonable values" },
        ];
        
        let passed = 0;
        for (const testCase of minValueTests) {
            const response = await this.apiCall('POST', '/stations', testCase.data);
            
            if (this.assertStatusCode(response.status, testCase.expected, testCase.description)) {
                passed++;
                
                if (response.status === 201) {
                    const stationId = this.parseJsonField(response.data, 'id');
                    if (stationId) {
                        this.createdStationIds.push(stationId);
                    }
                }
            }
        }
        
        return passed === minValueTests.length;
    }

    /**
     * Cleanup created resources
     */
    async cleanup() {
        this.printInfo("Cleaning up validation test resources...");
        
        // Clean up stories
        for (const storyId of this.createdStoryIds) {
            try {
                await this.apiCall('DELETE', `/stories/${storyId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Clean up station-voices
        for (const svId of this.createdStationVoiceIds) {
            try {
                await this.apiCall('DELETE', `/station-voices/${svId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Clean up stations
        for (const stationId of this.createdStationIds) {
            try {
                await this.apiCall('DELETE', `/stations/${stationId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Clean up voices
        for (const voiceId of this.createdVoiceIds) {
            try {
                await this.apiCall('DELETE', `/voices/${voiceId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Clean up users
        for (const userId of this.createdUserIds) {
            try {
                await this.apiCall('DELETE', `/users/${userId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        this.printSuccess("Cleanup completed");
    }

    /**
     * Restore admin session
     */
    async restoreAdminSession() {
        if (!(await this.isSessionActive())) {
            this.printInfo('Restoring admin session');
            return await this.apiLogin();
        } else {
            // Check if we have admin privileges
            const response = await this.apiCall('GET', '/users');
            if (response.status === 200) {
                this.printInfo('Admin session already active');
                return true;
            } else {
                this.printInfo('Non-admin session active, re-logging as admin');
                await this.apiLogout();
                return await this.apiLogin();
            }
        }
    }

    /**
     * Run all validation tests
     */
    async runAllTests() {
        this.printHeader("Comprehensive Validation Tests");
        
        // Ensure we're logged in as admin
        if (!(await this.restoreAdminSession())) {
            this.printError('Could not establish admin session');
            return false;
        }
        
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
            
            console.error(''); // Add spacing between tests
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
            console.error('Tests interrupted by user');
        } else {
            console.error(`Fatal error: ${e.message}`);
        }
        await tester.cleanup();
        process.exit(1);
    }
}

// Handle interrupt signals
process.on('SIGINT', () => {
    console.error('Tests interrupted by user');
    process.exit(1);
});

process.on('SIGTERM', () => {
    console.error('Tests terminated');
    process.exit(1);
});

if (require.main === module) {
    main();
}

module.exports = { ValidationTester, TestCase };