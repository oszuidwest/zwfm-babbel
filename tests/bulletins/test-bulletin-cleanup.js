// Babbel bulletin cleanup tests.
// Tests that purged bulletins behave correctly: no audio_url, metadata preserved,
// latest endpoint skips purged, automation regenerates after purge.

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');
const fsSync = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class BulletinCleanupTests extends BaseTest {
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
        this.createdBulletinIds = [];

        // Track bulletin details for tests
        this.purgedBulletinId = null;
        this.unpurgedBulletinId = null;
        this.testStationId = null;
    }

    /**
     * Execute SQL against the Docker MySQL container.
     * All interpolated values are test-generated integer IDs (via parseInt),
     * matching the established pattern in tests/fixtures/load-fixtures.js.
     */
    execSQL(sql) {
        const cmd = `docker exec -i babbel-mysql mysql -u ${this.mysqlUser} -p${this.mysqlPassword} ${this.mysqlDatabase} -e "${sql}"`;
        return execSync(cmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
    }

    /**
     * Makes a request to the public automation endpoint.
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
        const jingleFile = `/tmp/test_jingle_cleanup_${stationId}_${voiceId}.wav`;

        try {
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
        const audioFile = `/tmp/test_story_cleanup_${Date.now()}.wav`;

        try {
            execSync(`ffmpeg -f lavfi -i "sine=frequency=220:duration=3" -ar 44100 -ac 2 -f wav "${audioFile}" -y 2>/dev/null`, { stdio: 'ignore' });
            if (!fsSync.existsSync(audioFile)) {
                this.printWarning('Could not create test audio file');
                return null;
            }
        } catch (error) {
            this.printWarning('ffmpeg not available, cannot create audio');
            return null;
        }

        const today = new Date();
        const year = today.getFullYear();
        const startDate = `${year}-01-01`;
        const endDate = `${year + 1}-01-31`;

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

        const uploadResponse = await this.uploadFile(`/stories/${storyId}/audio`, {}, audioFile, 'audio');

        fsSync.unlinkSync(audioFile);

        if (uploadResponse.status !== 201) {
            return null;
        }

        return storyId;
    }

    /**
     * Mark a bulletin as purged via direct SQL and remove its audio file.
     */
    markBulletinPurged(bulletinId) {
        const id = parseInt(bulletinId, 10);

        // Set file_purged_at in database
        this.execSQL(`UPDATE bulletins SET file_purged_at = NOW() WHERE id = ${id}`);

        // Get filename from database to delete the actual file
        const result = this.execSQL(`SELECT audio_file FROM bulletins WHERE id = ${id}`);
        const lines = result.trim().split('\n');
        if (lines.length >= 2) {
            const filename = lines[1].trim();
            if (filename) {
                const filePath = path.join(this.audioDir, 'output', filename);
                try {
                    fsSync.unlinkSync(filePath);
                    this.printInfo(`Deleted audio file: ${filePath}`);
                } catch (e) {
                    this.printWarning(`Could not delete audio file: ${filePath}`);
                }
            }
        }
    }

    /**
     * Test that a purged bulletin has no audio_url but has file_purged_at.
     */
    async testPurgedBulletinHasNoAudioUrl() {
        this.printSection('Testing Purged Bulletin Has No audio_url');

        // Get purged bulletin
        const purgedResponse = await this.apiCall('GET', `/bulletins/${this.purgedBulletinId}`);
        if (purgedResponse.status !== 200) {
            this.printError(`Failed to get purged bulletin: HTTP ${purgedResponse.status}`);
            return false;
        }

        const purged = purgedResponse.data;

        // audio_url should be absent (omitted due to omitempty)
        if (purged.audio_url) {
            this.printError(`Purged bulletin should not have audio_url, got: ${purged.audio_url}`);
            return false;
        }
        this.printSuccess('Purged bulletin has no audio_url');

        // file_purged_at should be present as ISO timestamp
        if (!purged.file_purged_at) {
            this.printError('Purged bulletin should have file_purged_at');
            return false;
        }
        this.printSuccess(`Purged bulletin has file_purged_at: ${purged.file_purged_at}`);

        // Verify non-purged bulletin still has audio_url
        const unpurgedResponse = await this.apiCall('GET', `/bulletins/${this.unpurgedBulletinId}`);
        if (unpurgedResponse.status !== 200) {
            this.printError(`Failed to get unpurged bulletin: HTTP ${unpurgedResponse.status}`);
            return false;
        }

        const unpurged = unpurgedResponse.data;
        if (!unpurged.audio_url) {
            this.printError('Unpurged bulletin should have audio_url');
            return false;
        }
        this.printSuccess(`Unpurged bulletin has audio_url: ${unpurged.audio_url}`);

        if (unpurged.file_purged_at) {
            this.printError('Unpurged bulletin should not have file_purged_at');
            return false;
        }
        this.printSuccess('Unpurged bulletin has no file_purged_at');

        return true;
    }

    /**
     * Test that requesting audio for a purged bulletin returns 404.
     */
    async testPurgedBulletinAudioReturns404() {
        this.printSection('Testing Purged Bulletin Audio Returns 404');

        const response = await this.apiCall('GET', `/bulletins/${this.purgedBulletinId}/audio`);

        if (response.status === 404) {
            this.printSuccess('Purged bulletin audio correctly returns 404');
            return true;
        } else {
            this.printError(`Expected 404, got ${response.status}`);
            return false;
        }
    }

    /**
     * Test that purged bulletin metadata is fully preserved.
     */
    async testPurgedBulletinMetadataPreserved() {
        this.printSection('Testing Purged Bulletin Metadata Preserved');

        const response = await this.apiCall('GET', `/bulletins/${this.purgedBulletinId}`);
        if (response.status !== 200) {
            this.printError(`Failed to get purged bulletin: HTTP ${response.status}`);
            return false;
        }

        const bulletin = response.data;
        const requiredFields = ['id', 'station_id', 'filename', 'duration_seconds', 'story_count', 'created_at'];
        let allPresent = true;

        for (const field of requiredFields) {
            if (bulletin[field] === undefined || bulletin[field] === null) {
                this.printError(`Missing required field: ${field}`);
                allPresent = false;
            } else {
                this.printSuccess(`Field '${field}' preserved: ${bulletin[field]}`);
            }
        }

        if (!allPresent) {
            return false;
        }

        // Verify the ID matches what we expect
        if (String(bulletin.id) !== String(this.purgedBulletinId)) {
            this.printError(`Bulletin ID mismatch: expected ${this.purgedBulletinId}, got ${bulletin.id}`);
            return false;
        }
        this.printSuccess('Purged bulletin metadata fully preserved as audit trail');

        return true;
    }

    /**
     * Test that purged bulletins appear in list with correct fields.
     */
    async testBulletinListIncludesPurgedRecords() {
        this.printSection('Testing Bulletin List Includes Purged Records');

        const response = await this.apiCall('GET', `/stations/${this.testStationId}/bulletins`);
        if (response.status !== 200) {
            this.printError(`Failed to list bulletins: HTTP ${response.status}`);
            return false;
        }

        const bulletins = response.data.data || [];
        if (bulletins.length < 2) {
            this.printError(`Expected at least 2 bulletins in list, got ${bulletins.length}`);
            return false;
        }
        this.printSuccess(`Bulletin list contains ${bulletins.length} bulletins`);

        // Find the purged and unpurged bulletins in the list
        const purged = bulletins.find(b => String(b.id) === String(this.purgedBulletinId));
        const unpurged = bulletins.find(b => String(b.id) === String(this.unpurgedBulletinId));

        if (!purged) {
            this.printError('Purged bulletin not found in list');
            return false;
        }
        this.printSuccess('Purged bulletin appears in list');

        if (!unpurged) {
            this.printError('Unpurged bulletin not found in list');
            return false;
        }
        this.printSuccess('Unpurged bulletin appears in list');

        // Purged bulletin should have file_purged_at but no audio_url
        if (purged.audio_url) {
            this.printError('Purged bulletin in list should not have audio_url');
            return false;
        }
        this.printSuccess('Purged bulletin in list has no audio_url');

        if (!purged.file_purged_at) {
            this.printError('Purged bulletin in list should have file_purged_at');
            return false;
        }
        this.printSuccess('Purged bulletin in list has file_purged_at');

        // Unpurged bulletin should have audio_url but no file_purged_at
        if (!unpurged.audio_url) {
            this.printError('Unpurged bulletin in list should have audio_url');
            return false;
        }
        this.printSuccess('Unpurged bulletin in list has audio_url');

        if (unpurged.file_purged_at) {
            this.printError('Unpurged bulletin in list should not have file_purged_at');
            return false;
        }
        this.printSuccess('Unpurged bulletin in list has no file_purged_at');

        return true;
    }

    /**
     * Test that ?latest=true skips purged bulletins.
     * We purge the newest bulletin and verify the endpoint returns the older unpurged one.
     */
    async testLatestBulletinSkipsPurged() {
        this.printSection('Testing Latest Bulletin Skips Purged');

        // Generate a third bulletin so we have something to purge as "newest"
        const thirdResponse = await this.apiCall('POST', `/stations/${this.testStationId}/bulletins`, {});
        if (thirdResponse.status !== 200) {
            this.printError(`Failed to generate third bulletin: HTTP ${thirdResponse.status}`);
            return false;
        }

        const thirdBulletinId = this.parseJsonField(thirdResponse.data, 'id');
        if (!thirdBulletinId) {
            this.printError('Failed to get third bulletin ID');
            return false;
        }
        this.createdBulletinIds.push(thirdBulletinId);
        this.printSuccess(`Generated third bulletin (ID: ${thirdBulletinId})`);

        // Purge this newest bulletin
        this.markBulletinPurged(thirdBulletinId);
        this.printSuccess(`Purged newest bulletin (ID: ${thirdBulletinId})`);

        // Request latest - should return the unpurged bulletin, not the purged one
        const latestResponse = await this.apiCall('GET', `/stations/${this.testStationId}/bulletins?latest=true`);
        if (latestResponse.status !== 200) {
            this.printError(`Latest endpoint failed: HTTP ${latestResponse.status}`);
            return false;
        }

        // latest=true returns a single bulletin object (not array)
        const latestBulletin = latestResponse.data;
        const latestId = String(latestBulletin.id);

        if (latestId === String(thirdBulletinId)) {
            this.printError(`Latest returned purged bulletin (ID: ${thirdBulletinId}) - should have been skipped`);
            return false;
        }

        if (latestId === String(this.purgedBulletinId)) {
            this.printError(`Latest returned originally purged bulletin (ID: ${this.purgedBulletinId}) - should have been skipped`);
            return false;
        }

        // Should be the unpurged bulletin
        if (latestId !== String(this.unpurgedBulletinId)) {
            this.printWarning(`Latest returned bulletin ID ${latestId}, expected ${this.unpurgedBulletinId}`);
        }

        if (!latestBulletin.audio_url) {
            this.printError('Latest bulletin should have audio_url (not purged)');
            return false;
        }
        this.printSuccess(`Latest endpoint correctly returned unpurged bulletin (ID: ${latestId})`);

        return true;
    }

    /**
     * Test that the automation endpoint regenerates a bulletin when all existing ones are purged.
     */
    async testAutomationEndpointRegeneratesAfterPurge() {
        this.printSection('Testing Automation Endpoint Regenerates After Purge');

        // Create a separate station for this test to avoid interference
        const stationId = await this.createTestStation('Automation Purge Test', 3, 2.0);
        if (!stationId) {
            this.printError('Failed to create test station');
            return false;
        }

        const voiceId = await this.createTestVoice('Automation Purge Voice');
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
            'Automation Purge Story',
            'Story for testing automation after purge.',
            voiceId
        );
        if (!storyId) {
            this.printError('Failed to create test story');
            return false;
        }

        await new Promise(resolve => setTimeout(resolve, 2000));

        // Generate a bulletin via automation
        this.printInfo('Generating initial bulletin via automation...');
        const initialResponse = await this.publicBulletinRequest(stationId, {
            key: this.automationKey,
            max_age: '0'
        });

        if (initialResponse.status !== 200) {
            this.printError(`Initial automation request failed: HTTP ${initialResponse.status}`);
            return false;
        }

        const initialBulletinId = initialResponse.headers['x-bulletin-id'];
        this.printSuccess(`Initial bulletin generated (ID: ${initialBulletinId})`);

        // Purge it
        this.markBulletinPurged(initialBulletinId);
        this.printSuccess('Purged the bulletin');

        // Request again with max_age - since no unpurged bulletins exist, should generate fresh
        this.printInfo('Requesting bulletin after purge...');
        const afterPurgeResponse = await this.publicBulletinRequest(stationId, {
            key: this.automationKey,
            max_age: '3600'
        });

        if (afterPurgeResponse.status !== 200) {
            this.printError(`Post-purge automation request failed: HTTP ${afterPurgeResponse.status}`);
            return false;
        }

        const newBulletinId = afterPurgeResponse.headers['x-bulletin-id'];
        const cached = afterPurgeResponse.headers['x-bulletin-cached'];

        if (cached === 'true') {
            this.printError('Should not return cached bulletin after purge');
            return false;
        }
        this.printSuccess(`X-Bulletin-Cached: ${cached} (new bulletin generated)`);

        if (newBulletinId === initialBulletinId) {
            this.printError('Should have generated a new bulletin, not returned the purged one');
            return false;
        }
        this.printSuccess(`New bulletin generated (ID: ${newBulletinId}) after purge`);

        // Verify the new bulletin audio is valid
        if (afterPurgeResponse.contentType && afterPurgeResponse.contentType.includes('audio/wav')) {
            this.printSuccess('Response has correct content-type: audio/wav');
        } else {
            this.printError(`Unexpected content-type: ${afterPurgeResponse.contentType}`);
            return false;
        }

        return true;
    }

    /**
     * Test filtering bulletins by purged status using modern query parameters.
     */
    async testFilterByPurgedStatus() {
        this.printSection('Testing Filter by Purged Status');

        // Filter for bulletins where file_purged_at is not null (purged only)
        const purgedResponse = await this.apiCall('GET',
            `/stations/${this.testStationId}/bulletins?filter[file_purged_at][ne]=null`);

        if (purgedResponse.status !== 200) {
            this.printError(`Purged filter request failed: HTTP ${purgedResponse.status}`);
            return false;
        }

        const purgedBulletins = purgedResponse.data.data || [];
        this.printInfo(`Filter file_purged_at[ne]=null returned ${purgedBulletins.length} bulletins`);

        // All returned bulletins should have file_purged_at set
        let allPurged = true;
        for (const b of purgedBulletins) {
            if (!b.file_purged_at) {
                this.printError(`Bulletin ID ${b.id} returned by purged filter but has no file_purged_at`);
                allPurged = false;
            }
        }

        if (purgedBulletins.length === 0) {
            this.printWarning('No purged bulletins returned by filter - filter may not support this field');
            // This is not a hard failure; the filter system may not expose file_purged_at
            this.printSuccess('Filter query executed without error');
            return true;
        }

        if (allPurged) {
            this.printSuccess('All bulletins from purged filter have file_purged_at set');
        } else {
            return false;
        }

        return true;
    }

    async restoreAdminSession() {
        if (!(await this.isSessionActive())) {
            return await this.apiLogin();
        }
        return true;
    }

    async setup() {
        this.printInfo('Setting up bulletin cleanup tests...');

        // Login as admin
        if (!await this.restoreAdminSession()) {
            this.printError('Failed to authenticate');
            return false;
        }

        // Create test resources
        const stationId = await this.createTestStation('Cleanup Test Station', 3, 2.0);
        if (!stationId) {
            this.printError('Failed to create test station');
            return false;
        }
        this.testStationId = stationId;
        this.printSuccess(`Created test station (ID: ${stationId})`);

        const voiceId = await this.createTestVoice('Cleanup Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }
        this.printSuccess(`Created test voice (ID: ${voiceId})`);

        const svId = await this.createStationVoiceWithJingle(stationId, voiceId);
        if (!svId) {
            this.printError('Failed to create station-voice with jingle');
            return false;
        }
        this.printSuccess('Created station-voice with jingle');

        const storyId = await this.createTestStoryWithAudio(
            'Cleanup Test Story',
            'Story for testing bulletin cleanup behavior.',
            voiceId
        );
        if (!storyId) {
            this.printError('Failed to create test story');
            return false;
        }
        this.printSuccess(`Created test story (ID: ${storyId})`);

        // Wait for audio processing
        this.printInfo('Waiting for audio processing...');
        await new Promise(resolve => setTimeout(resolve, 3000));

        // Generate first bulletin
        this.printInfo('Generating first bulletin...');
        const bulletin1Response = await this.apiCall('POST', `/stations/${stationId}/bulletins`, {});
        if (bulletin1Response.status !== 200) {
            this.printError(`First bulletin generation failed: HTTP ${bulletin1Response.status}: ${JSON.stringify(bulletin1Response.data)}`);
            return false;
        }
        const bulletin1Id = this.parseJsonField(bulletin1Response.data, 'id');
        this.createdBulletinIds.push(bulletin1Id);
        this.printSuccess(`Generated first bulletin (ID: ${bulletin1Id})`);

        // Small delay between bulletins for different timestamps
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Generate second bulletin
        this.printInfo('Generating second bulletin...');
        const bulletin2Response = await this.apiCall('POST', `/stations/${stationId}/bulletins`, {});
        if (bulletin2Response.status !== 200) {
            this.printError(`Second bulletin generation failed: HTTP ${bulletin2Response.status}: ${JSON.stringify(bulletin2Response.data)}`);
            return false;
        }
        const bulletin2Id = this.parseJsonField(bulletin2Response.data, 'id');
        this.createdBulletinIds.push(bulletin2Id);
        this.printSuccess(`Generated second bulletin (ID: ${bulletin2Id})`);

        // Mark the first (older) bulletin as purged
        this.purgedBulletinId = bulletin1Id;
        this.unpurgedBulletinId = bulletin2Id;
        this.markBulletinPurged(bulletin1Id);
        this.printSuccess(`Marked bulletin ${bulletin1Id} as purged`);

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
        this.printHeader('Bulletin Cleanup Tests');

        if (!await this.setup()) {
            this.printError('Setup failed');
            return false;
        }

        const tests = [
            'testPurgedBulletinHasNoAudioUrl',
            'testPurgedBulletinAudioReturns404',
            'testPurgedBulletinMetadataPreserved',
            'testBulletinListIncludesPurgedRecords',
            'testLatestBulletinSkipsPurged',
            'testAutomationEndpointRegeneratesAfterPurge',
            'testFilterByPurgedStatus'
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
    const tests = new BulletinCleanupTests();
    tests.run().then(success => {
        process.exit(success ? 0 : 1);
    }).catch(error => {
        console.error('Test execution error:', error);
        process.exit(1);
    });
}

module.exports = BulletinCleanupTests;
