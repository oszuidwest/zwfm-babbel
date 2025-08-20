/**
 * Babbel Bulletins Tests - Node.js
 * Test bulletin generation and audio handling functionality
 */

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

class BulletinsTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);
        
        // Global variables for tracking created resources
        this.createdStationIds = [];
        this.createdVoiceIds = [];
        this.createdStoryIds = [];
        this.createdBulletinIds = [];
        this.createdStationVoiceIds = [];
    }
    
    /**
     * Helper function to create a test station
     */
    async createTestStation(name, maxStories = 4, pauseSeconds = 2.0) {
        // Add timestamp to ensure uniqueness
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
        // Add timestamp to ensure uniqueness
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
        // Create a simple test jingle audio file
        const jingleFile = `/tmp/test_jingle_${stationId}_${voiceId}.wav`;
        const fs = require('fs');
        
        try {
            const { execSync } = require('child_process');
            execSync(`ffmpeg -f lavfi -i "sine=frequency=440:duration=5" -ar 44100 -ac 2 -f wav "${jingleFile}" -y 2>/dev/null`, { stdio: 'ignore' });
            if (!fs.existsSync(jingleFile)) {
                this.printWarning('Could not create test jingle file');
                return null;
            }
        } catch (error) {
            this.printWarning('ffmpeg not available, cannot create jingle');
            return null;
        }
        
        // Upload the station-voice relationship with jingle
        const formFields = {
            station_id: stationId.toString(),
            voice_id: voiceId.toString(),
            mix_point: mixPoint.toString()
        };
        
        const response = await this.uploadFile('/station-voices', formFields, jingleFile, 'jingle');
        
        // Clean up temp file
        fs.unlinkSync(jingleFile);
        
        if (response.status === 201) {
            const svId = this.parseJsonField(response.data, 'id');
            if (svId) {
                this.createdStationVoiceIds.push(svId);
                return svId;
            }
        }
        
        return null;
    }
    
    /**
     * Helper function to create a test story with audio
     */
    async createTestStoryWithAudio(title, text, voiceId, weekdays = 'monday,tuesday,wednesday,thursday,friday') {
        // Create a simple test audio file
        const audioFile = `/tmp/test_story_audio_${Date.now()}.wav`;
        const fs = require('fs');
        
        try {
            const { execSync } = require('child_process');
            execSync(`ffmpeg -f lavfi -i "sine=frequency=220:duration=3" -ar 44100 -ac 2 -f wav "${audioFile}" -y 2>/dev/null`, { stdio: 'ignore' });
            if (!fs.existsSync(audioFile)) {
                this.printWarning('Could not create test audio file');
                return null;
            }
        } catch (error) {
            this.printWarning('ffmpeg not available, cannot create test audio');
            return null;
        }
        
        // Set weekday flags
        const weekdayFlags = {
            monday: 'false',
            tuesday: 'false',
            wednesday: 'false',
            thursday: 'false',
            friday: 'false',
            saturday: 'false',
            sunday: 'false'
        };
        
        const days = weekdays.split(',');
        days.forEach(day => {
            if (weekdayFlags.hasOwnProperty(day.trim())) {
                weekdayFlags[day.trim()] = 'true';
            }
        });
        
        const formFields = {
            title,
            text,
            voice_id: voiceId.toString(),
            status: 'active',
            start_date: '2025-01-01',
            end_date: '2025-12-31',
            ...weekdayFlags
        };
        
        const response = await this.uploadFile('/stories', formFields, audioFile, 'audio');
        
        // Clean up temp file
        fs.unlinkSync(audioFile);
        
        if (response.status === 201) {
            const storyId = this.parseJsonField(response.data, 'id');
            if (storyId) {
                this.createdStoryIds.push(storyId);
                return storyId;
            }
        }
        
        return null;
    }
    
    /**
     * Test bulletin generation
     */
    async testBulletinGeneration() {
        this.printSection('Testing Bulletin Generation');
        
        // Setup test data
        this.printInfo('Setting up test data for bulletin generation...');
        
        // Create a test station
        const stationId = await this.createTestStation('Bulletin Test Station', 3, 2.0);
        if (!stationId) {
            this.printError('Failed to create test station');
            return false;
        }
        this.printSuccess(`Created test station (ID: ${stationId})`);
        
        // Create test voices
        const voice1Id = await this.createTestVoice('Bulletin Voice 1');
        const voice2Id = await this.createTestVoice('Bulletin Voice 2');
        if (!voice1Id || !voice2Id) {
            this.printError('Failed to create test voices');
            return false;
        }
        this.printSuccess(`Created test voices (IDs: ${voice1Id}, ${voice2Id})`);
        
        // Create station-voice relationships with jingles
        const sv1Id = await this.createStationVoiceWithJingle(stationId, voice1Id, 3.0);
        const sv2Id = await this.createStationVoiceWithJingle(stationId, voice2Id, 2.5);
        if (!sv1Id || !sv2Id) {
            this.printError('Failed to create station-voice relationships');
            return false;
        }
        this.printSuccess('Created station-voice relationships with jingles');
        
        // Create test stories with audio
        const story1Id = await this.createTestStoryWithAudio('Breaking News Bulletin Test', 'This is a test breaking news story for bulletin generation.', voice1Id, 'monday,tuesday,wednesday,thursday,friday');
        const story2Id = await this.createTestStoryWithAudio('Weather Update Bulletin Test', 'Test weather forecast for bulletin generation.', voice2Id, 'monday,tuesday,wednesday,thursday,friday');
        const story3Id = await this.createTestStoryWithAudio('Traffic Report Bulletin Test', 'Traffic update for bulletin generation testing.', voice1Id, 'monday,wednesday,friday');
        
        if (!story1Id || !story2Id || !story3Id) {
            this.printError('Failed to create test stories');
            return false;
        }
        this.printSuccess('Created test stories with audio files');
        
        // Wait for audio files to be processed
        this.printInfo('Waiting for audio files to be processed...');
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Test basic bulletin generation
        this.printInfo('Testing basic bulletin generation...');
        const response = await this.apiCall('POST', `/stations/${stationId}/bulletins`, {});
        
        if (response.status === 200) {
            this.printSuccess('Bulletin generated successfully');
            
            // Extract bulletin details
            const bulletinId = this.parseJsonField(response.data, 'id');
            const audioUrl = this.parseJsonField(response.data, 'audio_url');
            const duration = this.parseJsonField(response.data, 'duration');
            const storyCount = this.parseJsonField(response.data, 'story_count');
            const filename = this.parseJsonField(response.data, 'filename');
            const cached = this.parseJsonField(response.data, 'cached');
            
            if (bulletinId) {
                this.createdBulletinIds.push(bulletinId);
            }
            
            this.printInfo(`Bulletin details: ID=${bulletinId}, Duration=${duration}s, Stories=${storyCount}, Cached=${cached}`);
            this.printInfo(`Audio URL: ${audioUrl}`);
            this.printInfo(`Filename: ${filename}`);
            
            // Verify required fields are present
            if (audioUrl && duration && storyCount && filename) {
                this.printSuccess('Bulletin response contains all required fields');
            } else {
                this.printError('Bulletin response missing required fields');
                return false;
            }
            
            // Verify the bulletin cached flag is false for new generation
            if (cached === 'false') {
                this.printSuccess('New bulletin correctly marked as not cached');
            } else {
                this.printWarning(`New bulletin marked as cached: ${cached}`);
            }
        } else {
            this.printError(`Bulletin generation failed - HTTP ${response.status}: ${JSON.stringify(response.data)}`);
            return false;
        }
        
        // Test bulletin generation with specific date
        this.printInfo('Testing bulletin generation with specific date...');
        const today = new Date().toISOString().split('T')[0];
        const dateResponse = await this.apiCall('POST', `/stations/${stationId}/bulletins`, { date: today });
        
        if (dateResponse.status === 200) {
            this.printSuccess('Bulletin generation with date works');
        } else {
            this.printError(`Bulletin generation with date failed - HTTP ${dateResponse.status}`);
            return false;
        }
        
        // Test bulletin generation with story list inclusion
        this.printInfo('Testing bulletin generation with story list inclusion...');
        const storyListResponse = await this.apiCall('POST', `/stations/${stationId}/bulletins?include_story_list=true`, {});
        
        if (storyListResponse.status === 200) {
            // Check if stories are included in response
            const hasStories = storyListResponse.data.stories && Array.isArray(storyListResponse.data.stories) && storyListResponse.data.stories.length > 0;
            
            if (hasStories) {
                this.printSuccess('Bulletin generation with story list inclusion works');
            } else {
                this.printWarning('Story list not included in bulletin response');
            }
        } else {
            this.printError(`Bulletin generation with story list failed - HTTP ${storyListResponse.status}`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test bulletin retrieval and details
     */
    async testBulletinRetrieval() {
        this.printSection('Testing Bulletin Retrieval');
        
        // Test listing all bulletins
        this.printInfo('Testing bulletin listing...');
        const response = await this.apiCall('GET', '/bulletins');
        
        if (this.assertions.checkResponse(response, 200, 'List bulletins')) {
            // Check for data array and pagination
            if (response.data.data && Array.isArray(response.data.data)) {
                const count = response.data.data.length;
                this.printSuccess(`Bulletin listing returned ${count} bulletins`);
                
                // Check pagination info
                if (response.data.pagination) {
                    const pagination = response.data.pagination;
                    this.printInfo(`Pagination: total=${pagination.total}, limit=${pagination.limit}, offset=${pagination.offset}`);
                }
            } else {
                this.printError('Bulletin listing response missing data array');
                return false;
            }
        } else {
            return false;
        }
        
        // Test pagination
        this.printInfo('Testing bulletin pagination...');
        const paginationResponse = await this.apiCall('GET', '/bulletins?limit=2&offset=0');
        
        if (this.assertions.checkResponse(paginationResponse, 200, 'Paginated bulletin listing')) {
            const count = paginationResponse.data.data ? paginationResponse.data.data.length : 0;
            if (count <= 2) {
                this.printSuccess(`Pagination limit respected (returned ${count} bulletins)`);
            } else {
                this.printError(`Pagination limit not respected (returned ${count} bulletins)`);
                return false;
            }
        } else {
            return false;
        }
        
        // Test filtering by station if we have created stations
        if (this.createdStationIds.length > 0) {
            this.printInfo('Testing bulletin filtering by station...');
            const stationId = this.createdStationIds[0];
            const filterResponse = await this.apiCall('GET', `/bulletins?station_id=${stationId}`);
            
            if (this.assertions.checkResponse(filterResponse, 200, 'Filter bulletins by station')) {
                this.printSuccess('Filtering bulletins by station works');
            } else {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Test bulletin audio download
     */
    async testBulletinAudioDownload() {
        this.printSection('Testing Bulletin Audio Download');
        
        // Get a bulletin to test audio download
        const response = await this.apiCall('GET', '/bulletins?limit=1');
        
        if (this.assertions.checkResponse(response, 200, 'Get bulletins for audio test')) {
            if (response.data.data && response.data.data.length > 0) {
                const bulletinId = response.data.data[0].id;
                this.printInfo(`Testing bulletin audio download for ID: ${bulletinId}`);
                
                // Test audio download
                const downloadPath = '/tmp/test_bulletin_download.wav';
                const downloadResponse = await this.downloadFile(`/bulletins/${bulletinId}/audio`, downloadPath);
                
                if (downloadResponse === 200) {
                    const fs = require('fs');
                    if (fs.existsSync(downloadPath)) {
                        const stats = fs.statSync(downloadPath);
                        if (stats.size > 1000) {
                            this.printSuccess(`Bulletin audio downloaded successfully (${stats.size} bytes)`);
                        } else {
                            this.printWarning(`Downloaded file seems too small: ${stats.size} bytes`);
                        }
                        fs.unlinkSync(downloadPath);
                    } else {
                        this.printError('Download failed - file not created or empty');
                        return false;
                    }
                } else {
                    this.printError(`Audio download failed (HTTP: ${downloadResponse})`);
                    return false;
                }
                
                // Test audio download with direct download flag
                this.printInfo('Testing bulletin generation with direct download...');
                if (this.createdStationIds.length > 0) {
                    const stationId = this.createdStationIds[0];
                    const directDownloadResponse = await this.downloadFile(`/stations/${stationId}/bulletins?download=true`, downloadPath, 'POST', {});
                    
                    if (directDownloadResponse === 200) {
                        const fs = require('fs');
                        if (fs.existsSync(downloadPath) && fs.statSync(downloadPath).size > 0) {
                            this.printSuccess('Direct bulletin download works');
                            fs.unlinkSync(downloadPath);
                        } else {
                            this.printError('Direct download failed - no file created');
                            return false;
                        }
                    } else {
                        this.printError(`Direct bulletin download failed (HTTP: ${directDownloadResponse})`);
                        return false;
                    }
                }
            } else {
                this.printWarning('No bulletin ID found for audio download test');
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test station bulletin endpoints
     */
    async testStationBulletinEndpoints() {
        this.printSection('Testing Station Bulletin Endpoints');
        
        if (this.createdStationIds.length === 0) {
            this.printWarning('No stations created for station bulletin endpoint tests');
            return true;
        }
        
        const stationId = this.createdStationIds[0];
        
        // Test station-specific bulletin generation
        this.printInfo(`Testing station-specific bulletin generation for station ${stationId}...`);
        const genResponse = await this.apiCall('POST', `/stations/${stationId}/bulletins`, {});
        
        if (this.assertions.checkResponse(genResponse, 200, 'Generate station bulletin')) {
            this.printSuccess('Station-specific bulletin generation works');
        } else {
            return false;
        }
        
        // Test station bulletin listing
        this.printInfo('Testing station bulletin listing...');
        const listResponse = await this.apiCall('GET', `/stations/${stationId}/bulletins`);
        
        if (this.assertions.checkResponse(listResponse, 200, 'List station bulletins')) {
            const count = listResponse.data.data ? listResponse.data.data.length : 0;
            this.printSuccess(`Listed ${count} bulletins for station ${stationId}`);
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test bulletin history
     */
    async testBulletinHistory() {
        this.printSection('Testing Bulletin History');
        
        // Test bulletin history listing
        this.printInfo('Testing bulletin history...');
        const response = await this.apiCall('GET', '/bulletins?sort=-created_at');
        
        if (this.assertions.checkResponse(response, 200, 'List bulletin history')) {
            const bulletins = response.data.data || [];
            if (bulletins.length > 0) {
                this.printSuccess(`Retrieved ${bulletins.length} bulletins in history`);
                
                // Check if bulletins are sorted by creation date (descending)
                if (bulletins.length > 1) {
                    const first = new Date(bulletins[0].created_at);
                    const second = new Date(bulletins[1].created_at);
                    if (first >= second) {
                        this.printSuccess('Bulletins correctly sorted by creation date (descending)');
                    } else {
                        this.printWarning('Bulletin sorting may not be working correctly');
                    }
                }
            } else {
                this.printInfo('No bulletins found in history');
            }
        } else {
            return false;
        }
        
        // Test date range filtering for bulletins
        this.printInfo('Testing bulletin date range filtering...');
        const today = new Date().toISOString().split('T')[0];
        const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        
        const dateFilterResponse = await this.apiCall('GET', `/bulletins?filter%5Bcreated_at%5D%5Bgte%5D=${yesterday}&filter%5Bcreated_at%5D%5Blte%5D=${today}`);
        
        if (this.assertions.checkResponse(dateFilterResponse, 200, 'Filter bulletins by date range')) {
            this.printSuccess('Bulletin date range filtering works');
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test bulletin caching
     */
    async testBulletinCaching() {
        this.printSection('Testing Bulletin Caching');
        
        if (this.createdStationIds.length === 0) {
            this.printWarning('No stations created for caching tests');
            return true;
        }
        
        const stationId = this.createdStationIds[0];
        
        // Generate a bulletin
        this.printInfo('Generating first bulletin...');
        const firstResponse = await this.apiCall('POST', `/stations/${stationId}/bulletins`, {});
        
        if (!this.assertions.checkResponse(firstResponse, 200, 'Generate first bulletin')) {
            return false;
        }
        
        const firstCached = this.parseJsonField(firstResponse.data, 'cached');
        const firstFilename = this.parseJsonField(firstResponse.data, 'filename');
        
        // Generate another bulletin immediately (should be cached)
        this.printInfo('Generating second bulletin (should be cached)...');
        const secondResponse = await this.apiCall('POST', `/stations/${stationId}/bulletins`, {});
        
        if (this.assertions.checkResponse(secondResponse, 200, 'Generate second bulletin')) {
            const secondCached = this.parseJsonField(secondResponse.data, 'cached');
            const secondFilename = this.parseJsonField(secondResponse.data, 'filename');
            
            if (secondCached === 'true') {
                this.printSuccess('Second bulletin correctly marked as cached');
            } else {
                this.printWarning(`Second bulletin not marked as cached: ${secondCached}`);
            }
            
            if (firstFilename === secondFilename) {
                this.printSuccess('Cached bulletin uses same filename');
            } else {
                this.printWarning('Cached bulletin has different filename');
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test bulletin error cases
     */
    async testBulletinErrorCases() {
        this.printSection('Testing Bulletin Error Cases');
        
        // Test bulletin generation for non-existent station
        this.printInfo('Testing bulletin generation for non-existent station...');
        const nonExistentResponse = await this.apiCall('POST', '/stations/99999/bulletins', {});
        
        if (nonExistentResponse.status === 404) {
            this.printSuccess('Non-existent station correctly returns 404');
        } else {
            this.printError(`Non-existent station returned unexpected status: ${nonExistentResponse.status}`);
            return false;
        }
        
        // Test audio download for non-existent bulletin
        this.printInfo('Testing audio download for non-existent bulletin...');
        const nonExistentAudioResponse = await this.apiCall('GET', '/bulletins/99999/audio');
        
        if (nonExistentAudioResponse.status === 404) {
            this.printSuccess('Non-existent bulletin audio correctly returns 404');
        } else {
            this.printError(`Non-existent bulletin audio returned unexpected status: ${nonExistentAudioResponse.status}`);
            return false;
        }
        
        // Test bulletin generation with invalid date format
        if (this.createdStationIds.length > 0) {
            this.printInfo('Testing bulletin generation with invalid date...');
            const stationId = this.createdStationIds[0];
            const invalidDateResponse = await this.apiCall('POST', `/stations/${stationId}/bulletins`, { date: 'invalid-date' });
            
            if (invalidDateResponse.status === 400 || invalidDateResponse.status === 422) {
                this.printSuccess('Invalid date correctly rejected');
            } else {
                this.printWarning(`Invalid date returned unexpected status: ${invalidDateResponse.status}`);
            }
        }
        
        return true;
    }
    
    /**
     * Test bulletin metadata
     */
    async testBulletinMetadata() {
        this.printSection('Testing Bulletin Metadata');
        
        // Test getting bulletin details
        this.printInfo('Testing bulletin metadata retrieval...');
        const listResponse = await this.apiCall('GET', '/bulletins?limit=1');
        
        if (this.assertions.checkResponse(listResponse, 200, 'Get bulletins for metadata test')) {
            if (listResponse.data.data && listResponse.data.data.length > 0) {
                const bulletin = listResponse.data.data[0];
                const bulletinId = bulletin.id;
                
                // Check required metadata fields
                const requiredFields = ['id', 'station_id', 'filename', 'duration', 'story_count', 'created_at'];
                const missingFields = [];
                
                requiredFields.forEach(field => {
                    if (!bulletin.hasOwnProperty(field) || bulletin[field] === null || bulletin[field] === undefined) {
                        missingFields.push(field);
                    }
                });
                
                if (missingFields.length === 0) {
                    this.printSuccess('All required metadata fields present');
                } else {
                    this.printError(`Missing metadata fields: ${missingFields.join(', ')}`);
                    return false;
                }
                
                // Test individual bulletin retrieval
                this.printInfo(`Testing individual bulletin retrieval for ID: ${bulletinId}...`);
                const detailResponse = await this.apiCall('GET', `/bulletins/${bulletinId}`);
                
                if (this.assertions.checkResponse(detailResponse, 200, 'Get bulletin details')) {
                    this.printSuccess('Individual bulletin retrieval works');
                    
                    // Verify metadata consistency
                    const detailBulletin = detailResponse.data;
                    if (detailBulletin.id === bulletin.id && detailBulletin.filename === bulletin.filename) {
                        this.printSuccess('Bulletin metadata consistent between list and detail views');
                    } else {
                        this.printError('Bulletin metadata inconsistent between views');
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                this.printInfo('No bulletins found for metadata test');
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Setup function
     */
    async setup() {
        this.printInfo('Setting up bulletin tests...');
        await this.restoreAdminSession();
        return true;
    }
    
    /**
     * Cleanup function
     */
    async cleanup() {
        this.printInfo('Cleaning up bulletin tests...');
        
        // Delete station-voice relationships
        for (const svId of this.createdStationVoiceIds) {
            try {
                await this.apiCall('DELETE', `/station-voices/${svId}`);
                this.printInfo(`Cleaned up station-voice: ${svId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Delete bulletins
        for (const bulletinId of this.createdBulletinIds) {
            try {
                await this.apiCall('DELETE', `/bulletins/${bulletinId}`);
                this.printInfo(`Cleaned up bulletin: ${bulletinId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Delete stories
        for (const storyId of this.createdStoryIds) {
            try {
                await this.apiCall('DELETE', `/stories/${storyId}`);
                this.printInfo(`Cleaned up story: ${storyId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Delete voices
        for (const voiceId of this.createdVoiceIds) {
            try {
                await this.apiCall('DELETE', `/voices/${voiceId}`);
                this.printInfo(`Cleaned up voice: ${voiceId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Delete stations
        for (const stationId of this.createdStationIds) {
            try {
                await this.apiCall('DELETE', `/stations/${stationId}`);
                this.printInfo(`Cleaned up station: ${stationId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        return true;
    }
    
    /**
     * Restore admin session (compatibility helper)
     */
    async restoreAdminSession() {
        if (!(await this.isSessionActive())) {
            return await this.apiLogin();
        }
        return true;
    }
    
    /**
     * Main test runner
     */
    async run() {
        this.printHeader('Bulletin Tests');
        
        await this.setup();
        
        const tests = [
            'testBulletinGeneration',
            'testBulletinRetrieval',
            'testBulletinAudioDownload',
            'testStationBulletinEndpoints',
            'testBulletinHistory',
            'testBulletinCaching',
            'testBulletinErrorCases',
            'testBulletinMetadata'
        ];
        
        let failed = 0;
        
        for (const test of tests) {
            if (await this.runTest(this[test], test)) {
                this.printSuccess(`✓ ${test} passed`);
            } else {
                this.printError(`✗ ${test} failed`);
                failed++;
            }
            console.error('');
        }
        
        await this.cleanup();
        
        this.printSummary();
        
        if (failed === 0) {
            this.printSuccess('All bulletin tests passed!');
            return true;
        } else {
            this.printError(`${failed} bulletin tests failed`);
            return false;
        }
    }
}

module.exports = BulletinsTests;
// Run tests if executed directly
if (require.main === module) {
    const TestClass = module.exports;
    const test = new TestClass();
    test.run().then(success => {
        process.exit(success ? 0 : 1);
    }).catch(error => {
        console.error('Test execution failed:', error);
        process.exit(1);
    });
}
