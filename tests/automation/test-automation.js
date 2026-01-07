// Babbel automation endpoint tests.
// Tests the public automation endpoint for radio automation systems.

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');
const fsSync = require('fs');

class AutomationTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);

        // The automation key configured in docker-compose.yml for testing
        this.automationKey = 'test-automation-key-for-integration-tests';

        // Public endpoint base (not /api/v1)
        this.publicBase = process.env.API_BASE || 'http://localhost:8080';

        // Track created resources for cleanup
        this.createdStationIds = [];
        this.createdVoiceIds = [];
        this.createdStoryIds = [];
        this.createdStationVoiceIds = [];
    }

    /**
     * Makes a request to the public automation endpoint.
     * @param {number} stationId - Station ID
     * @param {Object} queryParams - Query parameters (key, max_age)
     * @returns {Promise<Object>} Response object
     */
    async publicBulletinRequest(stationId, queryParams = {}) {
        const params = new URLSearchParams(queryParams);
        const url = `${this.publicBase}/public/stations/${stationId}/bulletin.wav?${params.toString()}`;

        const response = await this.http({
            method: 'get',
            url: url,
            responseType: 'arraybuffer',
            validateStatus: () => true
        });

        return {
            status: response.status,
            data: response.data,
            headers: response.headers,
            contentType: response.headers['content-type']
        };
    }

    /**
     * Helper function to create a test station
     */
    async createTestStation(name, maxStories = 4, pauseSeconds = 2.0) {
        const uniqueName = `${name}_${Date.now()}_${process.pid}`;

        const response = await this.apiCall('POST', '/stations', {
            name: uniqueName,
            max_stories_per_block: maxStories,
            pause_seconds: pauseSeconds
        });

        if (response.status === 201) {
            const stationId = this.parseJsonField(response.data, 'id');
            if (stationId) {
                this.createdStationIds.push(stationId);
                return stationId;
            }
        }

        return null;
    }

    /**
     * Helper function to create a test voice
     */
    async createTestVoice(name) {
        const uniqueName = `${name}_${Date.now()}_${process.pid}`;

        const response = await this.apiCall('POST', '/voices', { name: uniqueName });

        if (response.status === 201) {
            const voiceId = this.parseJsonField(response.data, 'id');
            if (voiceId) {
                this.createdVoiceIds.push(voiceId);
                return voiceId;
            }
        }

        return null;
    }

    /**
     * Helper function to create station-voice relationship with jingle
     */
    async createStationVoiceWithJingle(stationId, voiceId, mixPoint = 3.0) {
        const jingleFile = `/tmp/test_jingle_automation_${stationId}_${voiceId}.wav`;

        try {
            const { execSync } = require('child_process');
            execSync(`ffmpeg -f lavfi -i "sine=frequency=440:duration=5" -ar 44100 -ac 2 -f wav "${jingleFile}" -y 2>/dev/null`, { stdio: 'ignore' });
            if (!fsSync.existsSync(jingleFile)) {
                this.printWarning('Could not create test jingle file');
                return null;
            }
        } catch (error) {
            this.printWarning('ffmpeg not available, cannot create jingle');
            return null;
        }

        const jsonBody = {
            station_id: parseInt(stationId, 10),
            voice_id: parseInt(voiceId, 10),
            mix_point: parseFloat(mixPoint)
        };

        const createResponse = await this.apiCall('POST', '/station-voices', jsonBody);

        if (createResponse.status !== 201) {
            fsSync.unlinkSync(jingleFile);
            return null;
        }

        const svId = this.parseJsonField(createResponse.data, 'id');
        if (!svId) {
            fsSync.unlinkSync(jingleFile);
            return null;
        }

        this.createdStationVoiceIds.push(svId);

        // Upload jingle file using the correct endpoint and method
        const uploadResponse = await this.uploadFile(`/station-voices/${svId}/audio`, {}, jingleFile, 'jingle');

        fsSync.unlinkSync(jingleFile);

        if (uploadResponse.status === 201) {
            return svId;
        }

        return null;
    }

    /**
     * Helper function to create a test story with audio
     */
    async createTestStoryWithAudio(title, body, voiceId) {
        const audioFile = `/tmp/test_story_automation_${Date.now()}.wav`;

        try {
            const { execSync } = require('child_process');
            execSync(`ffmpeg -f lavfi -i "sine=frequency=220:duration=3" -ar 44100 -ac 2 -f wav "${audioFile}" -y 2>/dev/null`, { stdio: 'ignore' });
            if (!fsSync.existsSync(audioFile)) {
                this.printWarning('Could not create test audio file');
                return null;
            }
        } catch (error) {
            this.printWarning('ffmpeg not available, cannot create audio');
            return null;
        }

        // Use date range that includes today - match bulletin test pattern
        const today = new Date();
        const year = today.getFullYear();
        const startDate = `${year}-01-01`;
        const endDate = `${year + 1}-01-31`;

        // Step 1: Create story with JSON (no audio)
        const jsonBody = {
            title: `${title}_${Date.now()}`,
            text: body,
            voice_id: parseInt(voiceId, 10),
            status: 'active',
            start_date: startDate,
            end_date: endDate,
            weekdays: 127
        };

        const createResponse = await this.apiCall('POST', '/stories', jsonBody);

        if (createResponse.status !== 201) {
            fsSync.unlinkSync(audioFile);
            return null;
        }

        const storyId = this.parseJsonField(createResponse.data, 'id');
        if (!storyId) {
            fsSync.unlinkSync(audioFile);
            return null;
        }

        this.createdStoryIds.push(storyId);

        // Step 2: Upload audio separately
        const uploadResponse = await this.uploadFile(`/stories/${storyId}/audio`, {}, audioFile, 'audio');

        fsSync.unlinkSync(audioFile);

        if (uploadResponse.status !== 201) {
            return null;
        }

        return storyId;
    }

    /**
     * Test missing API key returns 401
     */
    async testMissingApiKey() {
        this.printSection('Testing Missing API Key');

        const response = await this.publicBulletinRequest(1, { max_age: '3600' });

        if (response.status === 401) {
            this.printSuccess('Missing API key correctly returns 401');
            return true;
        } else {
            this.printError(`Expected 401, got ${response.status}`);
            return false;
        }
    }

    /**
     * Test invalid API key returns 401
     */
    async testInvalidApiKey() {
        this.printSection('Testing Invalid API Key');

        const response = await this.publicBulletinRequest(1, {
            key: 'wrong-key',
            max_age: '3600'
        });

        if (response.status === 401) {
            this.printSuccess('Invalid API key correctly returns 401');
            return true;
        } else {
            this.printError(`Expected 401, got ${response.status}`);
            return false;
        }
    }

    /**
     * Test missing max_age parameter returns 422
     */
    async testMissingMaxAge() {
        this.printSection('Testing Missing max_age Parameter');

        const response = await this.publicBulletinRequest(1, {
            key: this.automationKey
        });

        if (response.status === 422) {
            this.printSuccess('Missing max_age correctly returns 422');
            return true;
        } else {
            this.printError(`Expected 422, got ${response.status}`);
            return false;
        }
    }

    /**
     * Test invalid max_age parameter returns 422
     */
    async testInvalidMaxAge() {
        this.printSection('Testing Invalid max_age Parameter');

        const response = await this.publicBulletinRequest(1, {
            key: this.automationKey,
            max_age: 'invalid'
        });

        if (response.status === 422) {
            this.printSuccess('Invalid max_age correctly returns 422');
            return true;
        } else {
            this.printError(`Expected 422, got ${response.status}`);
            return false;
        }
    }

    /**
     * Test invalid station ID returns 422
     */
    async testInvalidStationId() {
        this.printSection('Testing Invalid Station ID');

        // Use a string that's not a valid integer
        const url = `${this.publicBase}/public/stations/invalid/bulletin.wav?key=${this.automationKey}&max_age=3600`;

        const response = await this.http({
            method: 'get',
            url: url,
            validateStatus: () => true
        });

        if (response.status === 422) {
            this.printSuccess('Invalid station ID correctly returns 422');
            return true;
        } else {
            this.printError(`Expected 422, got ${response.status}`);
            return false;
        }
    }

    /**
     * Test non-existent station returns 404
     */
    async testNonExistentStation() {
        this.printSection('Testing Non-Existent Station');

        const response = await this.publicBulletinRequest(999999, {
            key: this.automationKey,
            max_age: '3600'
        });

        if (response.status === 404) {
            this.printSuccess('Non-existent station correctly returns 404');
            return true;
        } else {
            this.printError(`Expected 404, got ${response.status}`);
            return false;
        }
    }

    /**
     * Test station with no stories returns 422
     */
    async testStationNoStories() {
        this.printSection('Testing Station With No Stories');

        // Create a station with no stories
        const stationId = await this.createTestStation('Empty Automation Station');
        if (!stationId) {
            this.printError('Failed to create test station');
            return false;
        }

        const response = await this.publicBulletinRequest(stationId, {
            key: this.automationKey,
            max_age: '0' // Force new generation
        });

        // Should return 422 because no stories are available for bulletin generation
        if (response.status === 422) {
            this.printSuccess('Station with no stories correctly returns 422');
            return true;
        } else {
            this.printError(`Expected 422, got ${response.status}`);
            return false;
        }
    }

    /**
     * Test successful bulletin generation returns audio
     */
    async testSuccessfulBulletinGeneration() {
        this.printSection('Testing Successful Bulletin Generation');

        // Create complete test setup
        this.printInfo('Setting up test data...');

        const stationId = await this.createTestStation('Automation Test Station', 3, 2.0);
        if (!stationId) {
            this.printError('Failed to create test station');
            return false;
        }
        this.printSuccess(`Created station (ID: ${stationId})`);

        const voiceId = await this.createTestVoice('Automation Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }
        this.printSuccess(`Created voice (ID: ${voiceId})`);

        const svId = await this.createStationVoiceWithJingle(stationId, voiceId);
        if (!svId) {
            this.printError('Failed to create station-voice with jingle');
            return false;
        }
        this.printSuccess('Created station-voice with jingle');

        const storyId = await this.createTestStoryWithAudio(
            'Automation Test Story',
            'This is a test story for automation endpoint testing.',
            voiceId
        );
        if (!storyId) {
            this.printError('Failed to create test story');
            return false;
        }
        this.printSuccess(`Created story (ID: ${storyId})`);

        // Wait for processing
        this.printInfo('Waiting for audio processing...');
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Request bulletin via public endpoint
        this.printInfo('Requesting bulletin via public automation endpoint...');
        const response = await this.publicBulletinRequest(stationId, {
            key: this.automationKey,
            max_age: '0' // Force new generation
        });

        if (response.status === 200) {
            this.printSuccess('Bulletin generation returned 200');

            // Check content type
            if (response.contentType && response.contentType.includes('audio/wav')) {
                this.printSuccess('Response has correct content-type: audio/wav');
            } else {
                this.printError(`Unexpected content-type: ${response.contentType}`);
                return false;
            }

            // Check that we got actual audio data
            if (response.data && response.data.length > 1000) {
                this.printSuccess(`Received audio data (${response.data.length} bytes)`);
            } else {
                this.printError('Response data too small to be valid audio');
                return false;
            }

            return true;
        } else {
            // Try to parse error response
            let errorMsg = '';
            try {
                const errorData = JSON.parse(response.data.toString());
                errorMsg = errorData.title || errorData.detail || '';
            } catch (e) {
                errorMsg = response.data.toString().substring(0, 200);
            }
            this.printError(`Expected 200, got ${response.status}: ${errorMsg}`);
            return false;
        }
    }

    /**
     * Test bulletin caching with max_age
     */
    async testBulletinCaching() {
        this.printSection('Testing Bulletin Caching');

        // Create complete test setup
        this.printInfo('Setting up test data...');

        const stationId = await this.createTestStation('Caching Test Station', 3, 2.0);
        if (!stationId) {
            this.printError('Failed to create test station');
            return false;
        }

        const voiceId = await this.createTestVoice('Caching Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }

        const svId = await this.createStationVoiceWithJingle(stationId, voiceId);
        if (!svId) {
            this.printError('Failed to create station-voice');
            return false;
        }

        const storyId = await this.createTestStoryWithAudio(
            'Caching Test Story',
            'Story for testing caching behavior.',
            voiceId
        );
        if (!storyId) {
            this.printError('Failed to create test story');
            return false;
        }

        await new Promise(resolve => setTimeout(resolve, 2000));

        // First request - should generate new bulletin
        this.printInfo('First request (max_age=0, force new)...');
        const response1 = await this.publicBulletinRequest(stationId, {
            key: this.automationKey,
            max_age: '0'
        });

        if (response1.status !== 200) {
            this.printError(`First request failed: ${response1.status}`);
            return false;
        }
        this.printSuccess('First request succeeded');

        // Verify X-Bulletin-Cached header indicates fresh bulletin
        const cached1 = response1.headers['x-bulletin-cached'];
        if (cached1 !== 'false') {
            this.printError(`Expected X-Bulletin-Cached: false, got: ${cached1}`);
            return false;
        }
        this.printSuccess('X-Bulletin-Cached: false (new bulletin)');

        // Get bulletin ID from header
        const bulletinId1 = response1.headers['x-bulletin-id'];
        if (!bulletinId1) {
            this.printError('Missing X-Bulletin-Id header');
            return false;
        }
        this.printSuccess(`X-Bulletin-Id: ${bulletinId1}`);

        // Second request with high max_age - should return cached bulletin
        this.printInfo('Second request (max_age=3600, should use cache)...');
        const response2 = await this.publicBulletinRequest(stationId, {
            key: this.automationKey,
            max_age: '3600'
        });

        if (response2.status !== 200) {
            this.printError(`Second request failed: ${response2.status}`);
            return false;
        }
        this.printSuccess('Second request succeeded');

        // Verify X-Bulletin-Cached header indicates cached bulletin
        const cached2 = response2.headers['x-bulletin-cached'];
        if (cached2 !== 'true') {
            this.printError(`Expected X-Bulletin-Cached: true, got: ${cached2}`);
            return false;
        }
        this.printSuccess('X-Bulletin-Cached: true (cached bulletin)');

        // Verify same bulletin ID was returned
        const bulletinId2 = response2.headers['x-bulletin-id'];
        if (bulletinId1 !== bulletinId2) {
            this.printError(`Bulletin ID mismatch: ${bulletinId1} vs ${bulletinId2}`);
            return false;
        }
        this.printSuccess(`Same bulletin returned (ID: ${bulletinId1}) - caching verified`);

        return true;
    }

    /**
     * Test single-day story scheduling (timezone regression test).
     * This test verifies the DATE comparison fix by creating a story that is
     * only valid today. Before the fix, stories would incorrectly appear
     * "expired" shortly after midnight due to timezone conversion issues.
     */
    async testSingleDayStoryScheduling() {
        this.printSection('Testing Single-Day Story Scheduling (Timezone Regression)');

        // Create complete test setup
        this.printInfo('Setting up test data with single-day date range...');

        const stationId = await this.createTestStation('Timezone Test Station', 3, 2.0);
        if (!stationId) {
            this.printError('Failed to create test station');
            return false;
        }

        const voiceId = await this.createTestVoice('Timezone Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }

        const svId = await this.createStationVoiceWithJingle(stationId, voiceId);
        if (!svId) {
            this.printError('Failed to create station-voice');
            return false;
        }

        // Create story valid ONLY today - this would fail with the old DATE comparison bug
        const storyId = await this.createSingleDayStoryWithAudio(
            'Timezone Test Story',
            'Story for testing single-day DATE comparison fix.',
            voiceId
        );
        if (!storyId) {
            this.printError('Failed to create single-day test story');
            return false;
        }
        this.printSuccess('Created story with single-day date range (today only)');

        await new Promise(resolve => setTimeout(resolve, 2000));

        // Request bulletin - should succeed if DATE comparison is working correctly
        this.printInfo('Requesting bulletin with single-day story...');
        const response = await this.publicBulletinRequest(stationId, {
            key: this.automationKey,
            max_age: '0'
        });

        if (response.status === 200) {
            this.printSuccess('Bulletin generated successfully with single-day story');
            this.printSuccess('DATE comparison fix verified - story was not incorrectly expired');
            return true;
        } else if (response.status === 422) {
            // This would indicate the story was incorrectly marked as expired
            this.printError('Story appears expired - DATE comparison bug may have regressed');
            return false;
        } else {
            let errorMsg = '';
            try {
                const errorData = JSON.parse(response.data.toString());
                errorMsg = errorData.title || errorData.detail || '';
            } catch (e) {
                errorMsg = response.data.toString().substring(0, 200);
            }
            this.printError(`Unexpected status ${response.status}: ${errorMsg}`);
            return false;
        }
    }

    /**
     * Helper function to create a test story with audio valid only for today.
     * This tests the DATE column comparison fix for timezone issues.
     */
    async createSingleDayStoryWithAudio(title, body, voiceId) {
        const audioFile = `/tmp/test_story_timezone_${Date.now()}.wav`;

        try {
            const { execSync } = require('child_process');
            execSync(`ffmpeg -f lavfi -i "sine=frequency=330:duration=3" -ar 44100 -ac 2 -f wav "${audioFile}" -y 2>/dev/null`, { stdio: 'ignore' });
            if (!fsSync.existsSync(audioFile)) {
                this.printWarning('Could not create test audio file');
                return null;
            }
        } catch (error) {
            this.printWarning('ffmpeg not available, cannot create audio');
            return null;
        }

        // Use TODAY only - this is the critical test case for the timezone fix
        // Format as YYYY-MM-DD in local timezone
        const today = new Date();
        const year = today.getFullYear();
        const month = String(today.getMonth() + 1).padStart(2, '0');
        const day = String(today.getDate()).padStart(2, '0');
        const todayStr = `${year}-${month}-${day}`;

        this.printInfo(`Story date range: ${todayStr} to ${todayStr} (single day)`);

        // Step 1: Create story with JSON (no audio)
        const jsonBody = {
            title: `${title}_${Date.now()}`,
            text: body,
            voice_id: parseInt(voiceId, 10),
            status: 'active',
            start_date: todayStr,
            end_date: todayStr,  // Same as start_date - valid only today
            weekdays: 127
        };

        const createResponse = await this.apiCall('POST', '/stories', jsonBody);

        if (createResponse.status !== 201) {
            fsSync.unlinkSync(audioFile);
            return null;
        }

        const storyId = this.parseJsonField(createResponse.data, 'id');
        if (!storyId) {
            fsSync.unlinkSync(audioFile);
            return null;
        }

        this.createdStoryIds.push(storyId);

        // Step 2: Upload audio separately
        const uploadResponse = await this.uploadFile(`/stories/${storyId}/audio`, {}, audioFile, 'audio');

        fsSync.unlinkSync(audioFile);

        if (uploadResponse.status !== 201) {
            return null;
        }

        return storyId;
    }

    /**
     * Test negative max_age returns 422
     */
    async testNegativeMaxAge() {
        this.printSection('Testing Negative max_age Parameter');

        const response = await this.publicBulletinRequest(1, {
            key: this.automationKey,
            max_age: '-100'
        });

        if (response.status === 422) {
            this.printSuccess('Negative max_age correctly returns 422');
            return true;
        } else {
            this.printError(`Expected 422, got ${response.status}`);
            return false;
        }
    }

    async setup() {
        this.printInfo('Setting up automation tests...');

        // Login as admin
        if (!await this.apiLogin()) {
            return false;
        }

        return true;
    }

    async cleanup() {
        this.printSection('Cleaning Up Test Data');

        // Delete stories
        for (const id of this.createdStoryIds) {
            try {
                await this.apiCall('DELETE', `/stories/${id}`);
            } catch (e) { /* ignore */ }
        }

        // Delete station-voices
        for (const id of this.createdStationVoiceIds) {
            try {
                await this.apiCall('DELETE', `/station-voices/${id}`);
            } catch (e) { /* ignore */ }
        }

        // Delete voices
        for (const id of this.createdVoiceIds) {
            try {
                await this.apiCall('DELETE', `/voices/${id}`);
            } catch (e) { /* ignore */ }
        }

        // Delete stations
        for (const id of this.createdStationIds) {
            try {
                await this.apiCall('DELETE', `/stations/${id}`);
            } catch (e) { /* ignore */ }
        }

        this.printSuccess('Cleanup complete');
    }

    async run() {
        this.printHeader('Automation Endpoint Tests');

        if (!await this.setup()) {
            this.printError('Setup failed');
            return false;
        }

        const tests = [
            'testMissingApiKey',
            'testInvalidApiKey',
            'testMissingMaxAge',
            'testInvalidMaxAge',
            'testNegativeMaxAge',
            'testInvalidStationId',
            'testNonExistentStation',
            'testStationNoStories',
            'testSuccessfulBulletinGeneration',
            'testBulletinCaching',
            'testSingleDayStoryScheduling'
        ];

        for (const test of tests) {
            if (await this.runTest(this[test], test)) {
                // Test passed
            }
        }

        await this.cleanup();

        return this.printSummary();
    }
}

// Run tests if called directly
if (require.main === module) {
    const tests = new AutomationTests();
    tests.run().then(success => {
        process.exit(success ? 0 : 1);
    }).catch(error => {
        console.error('Test execution error:', error);
        process.exit(1);
    });
}

module.exports = AutomationTests;
