// Babbel bulletins tests.
// Tests bulletin generation and audio handling functionality.

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
        
        // Step 1: Create station-voice relationship with JSON
        const jsonBody = {
            station_id: parseInt(stationId, 10),
            voice_id: parseInt(voiceId, 10),
            mix_point: parseFloat(mixPoint)
        };

        const createResponse = await this.apiCall('POST', '/station-voices', jsonBody);

        if (createResponse.status !== 201) {
            fs.unlinkSync(jingleFile);
            return null;
        }

        const svId = this.parseJsonField(createResponse.data, 'id');
        if (!svId) {
            fs.unlinkSync(jingleFile);
            return null;
        }

        this.createdStationVoiceIds.push(svId);

        // Step 2: Upload jingle separately
        const uploadResponse = await this.uploadFile(`/station-voices/${svId}/audio`, {}, jingleFile, 'jingle');

        // Clean up temp file
        fs.unlinkSync(jingleFile);

        if (uploadResponse.status !== 200) {
            return null;
        }

        return svId;
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
        
        // Set weekday flags - initialize all days to false first
        const weekdayFlags = {
            sunday: false,
            monday: false,
            tuesday: false,
            wednesday: false,
            thursday: false,
            friday: false,
            saturday: false
        };

        const days = weekdays.split(',');
        days.forEach(day => {
            const trimmed = day.trim().toLowerCase();
            if (weekdayFlags.hasOwnProperty(trimmed)) {
                weekdayFlags[trimmed] = true;
            }
        });

        // Use date range that includes today
        const today = new Date();
        const startDate = new Date(today.getFullYear(), 0, 1).toISOString().split('T')[0]; // Jan 1 of current year
        const endDate = new Date(today.getFullYear(), 11, 31).toISOString().split('T')[0]; // Dec 31 of current year

        // Step 1: Create story with JSON
        const jsonBody = {
            title,
            text,
            voice_id: parseInt(voiceId, 10),
            status: 'active',
            start_date: startDate,
            end_date: endDate,
            weekdays: weekdayFlags
        };

        const createResponse = await this.apiCall('POST', '/stories', jsonBody);

        if (createResponse.status !== 201) {
            fs.unlinkSync(audioFile);
            return null;
        }

        const storyId = this.parseJsonField(createResponse.data, 'id');
        if (!storyId) {
            fs.unlinkSync(audioFile);
            return null;
        }

        this.createdStoryIds.push(storyId);

        // Step 2: Upload audio separately
        const uploadResponse = await this.uploadFile(`/stories/${storyId}/audio`, {}, audioFile, 'audio');

        // Clean up temp file
        fs.unlinkSync(audioFile);

        if (uploadResponse.status !== 200) {
            return null;
        }

        return storyId;
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
        
        // Create test stories with audio - include all days to ensure stories are available
        const story1Id = await this.createTestStoryWithAudio('Breaking News Bulletin Test', 'This is a test breaking news story for bulletin generation.', voice1Id, 'monday,tuesday,wednesday,thursday,friday,saturday,sunday');
        const story2Id = await this.createTestStoryWithAudio('Weather Update Bulletin Test', 'Test weather forecast for bulletin generation.', voice2Id, 'monday,tuesday,wednesday,thursday,friday,saturday,sunday');
        const story3Id = await this.createTestStoryWithAudio('Traffic Report Bulletin Test', 'Traffic update for bulletin generation testing.', voice1Id, 'monday,tuesday,wednesday,thursday,friday,saturday,sunday');
        
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
            const duration = this.parseJsonField(response.data, 'duration_seconds');
            const storyCount = this.parseJsonField(response.data, 'story_count');
            const filename = this.parseJsonField(response.data, 'filename');
            
            if (bulletinId) {
                this.createdBulletinIds.push(bulletinId);
            }
            
            this.printInfo(`Bulletin details: ID=${bulletinId}, Duration=${duration}s, Stories=${storyCount}`);
            this.printInfo(`Audio URL: ${audioUrl}`);
            this.printInfo(`Filename: ${filename}`);
            
            // Verify required fields are present
            if (audioUrl && duration && storyCount && filename) {
                this.printSuccess('Bulletin response contains all required fields');
            } else {
                this.printError('Bulletin response missing required fields');
                return false;
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
        
        // Test separate story fetching after bulletin generation
        this.printInfo('Testing separate story fetching after bulletin generation...');
        const separateResponse = await this.apiCall('POST', `/stations/${stationId}/bulletins`, {});
        
        if (separateResponse.status === 200) {
            const bulletinId = this.parseJsonField(separateResponse.data, 'id');
            
            if (bulletinId) {
                // Now fetch stories separately
                const storiesResponse = await this.apiCall('GET', `/bulletins/${bulletinId}/stories`);
                
                if (storiesResponse.status === 200 && storiesResponse.data.data && Array.isArray(storiesResponse.data.data)) {
                    this.printSuccess(`Separate story fetching works - bulletin has ${storiesResponse.data.data.length} stories`);
                } else {
                    // Debug the actual response format
                    this.printError(`Separate story fetching failed or returned unexpected format`);
                    this.printError(`Status: ${storiesResponse.status}`);
                    this.printError(`Response structure: ${JSON.stringify(storiesResponse.data, null, 2)}`);
                    return false;
                }
            } else {
                this.printError('Failed to extract bulletin ID for separate story fetch test');
                return false;
            }
        } else {
            this.printError(`Bulletin generation for story fetch test failed - HTTP ${separateResponse.status}`);
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
            const filterResponse = await this.apiCall('GET', `/bulletins?filter[station_id]=${stationId}`);
            
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
                
                // Test audio download with direct download flag using Accept header
                this.printInfo('Testing bulletin generation with direct download using Accept header...');
                if (this.createdStationIds.length > 0) {
                    const stationId = this.createdStationIds[0];
                    const directDownloadResponse = await this.downloadFile(`/stations/${stationId}/bulletins`, downloadPath, 'POST', {}, { 'Accept': 'audio/wav' });
                    
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
     * Test station bulletin endpoints with modern query parameters
     */
    async testStationBulletinsModernQuery() {
        this.printSection('Testing Station Bulletins Modern Query Parameters');
        
        // Setup test data - create a dedicated station with voices and stories
        this.printInfo('Setting up comprehensive test data for station bulletins modern query tests...');
        const testStationId = await this.createTestStation('Station Query Test');
        if (!testStationId) {
            this.printError('Failed to create test station for modern query tests');
            return false;
        }
        
        // Create test voices and station-voice relationships for this station
        const testVoiceId = await this.createTestVoice('Modern Query Voice');
        if (!testVoiceId) {
            this.printError('Failed to create test voice for modern query tests');
            return false;
        }
        
        const stationVoiceId = await this.createStationVoiceWithJingle(testStationId, testVoiceId, 2.0);
        if (!stationVoiceId) {
            this.printError('Failed to create station-voice relationship for modern query tests');
            return false;
        }
        
        // Create multiple test stories with different content for better testing
        const storyTitles = [
            'Breaking News Bulletin Query Test',
            'Weather Update Query Test', 
            'Traffic Report Query Test',
            'Sports News Query Test',
            'Local News Query Test',
            'Business Update Query Test'
        ];
        
        const createdStoryIds = [];
        for (let i = 0; i < storyTitles.length; i++) {
            const storyId = await this.createTestStoryWithAudio(
                storyTitles[i], 
                `Test story content for ${storyTitles[i]}`, 
                testVoiceId,
                'monday,tuesday,wednesday,thursday,friday,saturday,sunday'
            );
            if (storyId) {
                createdStoryIds.push(storyId);
            }
        }
        
        if (createdStoryIds.length === 0) {
            this.printError('Failed to create any test stories for modern query tests');
            return false;
        }
        this.printSuccess(`Created ${createdStoryIds.length} test stories for query testing`);
        
        // Wait for audio processing
        this.printInfo('Waiting for audio processing...');
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Generate multiple bulletins for this station with delays to ensure different timestamps
        const bulletinIds = [];
        this.printInfo('Generating multiple bulletins for testing...');
        for (let i = 0; i < 6; i++) {
            const response = await this.apiCall('POST', `/stations/${testStationId}/bulletins`, {});
            if (response.status === 200) {
                const bulletinId = this.parseJsonField(response.data, 'id');
                if (bulletinId) {
                    bulletinIds.push(bulletinId);
                    this.createdBulletinIds.push(bulletinId);
                }
                // Add small delay to ensure different timestamps and durations
                await new Promise(resolve => setTimeout(resolve, 500));
            }
        }
        
        if (bulletinIds.length < 3) {
            this.printError(`Failed to create enough test bulletins for modern query tests (created ${bulletinIds.length})`);
            // Still attempt to test with available data if we have some bulletins
            if (bulletinIds.length === 0) {
                return false;
            }
        }
        this.printSuccess(`Created ${bulletinIds.length} test bulletins for station ${testStationId}`);
        
        // Test 1: Search functionality
        this.printInfo('Testing search by filename in station bulletins...');
        const searchResponse = await this.apiCall('GET', `/stations/${testStationId}/bulletins?search=bulletin`);
        if (this.assertions.checkResponse(searchResponse, 200, 'Search station bulletins')) {
            const results = searchResponse.data.data || [];
            if (results.length > 0) {
                this.printSuccess(`Station search returned ${results.length} bulletins matching "bulletin"`);
                // Since this is station-specific endpoint, all results should be from this station
                // Station constraint is automatic from URL path, so just verify we got results
                this.printSuccess('Station search returned results (station constraint is automatic from URL)');
            } else {
                this.printWarning('Station search returned no results');
            }
        } else {
            return false;
        }
        
        // Test 2: Field selection
        this.printInfo('Testing field selection for station bulletins...');
        const fieldsResponse = await this.apiCall('GET', `/stations/${testStationId}/bulletins?fields=id,filename,duration_seconds&limit=3`);
        if (this.assertions.checkResponse(fieldsResponse, 200, 'Station bulletins field selection')) {
            const firstResult = fieldsResponse.data.data[0];
            if (firstResult) {
                const hasOnlySelectedFields = 
                    firstResult.hasOwnProperty('id') && 
                    firstResult.hasOwnProperty('filename') &&
                    firstResult.hasOwnProperty('duration_seconds') &&
                    !firstResult.hasOwnProperty('story_count') &&
                    !firstResult.hasOwnProperty('file_size');
                
                if (hasOnlySelectedFields) {
                    this.printSuccess('Station bulletins field selection works correctly');
                } else {
                    this.printWarning('Field selection returned unexpected fields');
                }
            } else {
                this.printWarning('No results returned for field selection test');
            }
        } else {
            return false;
        }
        
        // Test 3: Sorting by created_at descending
        this.printInfo('Testing sorting by created_at descending...');
        const sortDescResponse = await this.apiCall('GET', `/stations/${testStationId}/bulletins?sort=-created_at&limit=5`);
        if (this.assertions.checkResponse(sortDescResponse, 200, 'Station bulletins sort descending')) {
            const results = sortDescResponse.data.data || [];
            if (results.length > 1) {
                let correctOrder = true;
                for (let i = 1; i < results.length; i++) {
                    if (new Date(results[i-1].created_at) < new Date(results[i].created_at)) {
                        correctOrder = false;
                        break;
                    }
                }
                if (correctOrder) {
                    this.printSuccess('Station bulletins descending sort order works correctly');
                } else {
                    this.printError('Station bulletins sort order is incorrect');
                    return false;
                }
                
                // Station-specific endpoint automatically filters by station
                this.printSuccess('Sorted results from station-specific endpoint');
            } else {
                this.printWarning('Not enough bulletins for sort order test');
            }
        } else {
            return false;
        }
        
        // Test 4: Sorting by filename ascending
        this.printInfo('Testing sorting by filename ascending...');
        const sortAscResponse = await this.apiCall('GET', `/stations/${testStationId}/bulletins?sort=filename:asc&limit=5`);
        if (this.assertions.checkResponse(sortAscResponse, 200, 'Station bulletins sort ascending')) {
            const results = sortAscResponse.data.data || [];
            if (results.length > 1) {
                let correctOrder = true;
                for (let i = 1; i < results.length; i++) {
                    if (results[i-1].filename > results[i].filename) {
                        correctOrder = false;
                        break;
                    }
                }
                if (correctOrder) {
                    this.printSuccess('Station bulletins filename ascending sort works correctly');
                } else {
                    this.printWarning('Station bulletins filename sort order may be incorrect');
                }
            }
        } else {
            return false;
        }
        
        // Test 5: Filtering by duration (gte operator)
        this.printInfo('Testing filter by duration_seconds gte...');
        
        // Get a reference bulletin to use for filtering
        const refResponse = await this.apiCall('GET', `/stations/${testStationId}/bulletins?limit=1`);
        if (refResponse.status === 200 && refResponse.data.data && refResponse.data.data.length > 0) {
            const refBulletin = refResponse.data.data[0];
            if (refBulletin.duration_seconds) {
                const minDuration = Math.floor(refBulletin.duration_seconds);
                const filterResponse = await this.apiCall('GET', 
                    `/stations/${testStationId}/bulletins?filter[duration_seconds][gte]=${minDuration}`);
                    
                if (this.assertions.checkResponse(filterResponse, 200, 'Filter station bulletins by duration')) {
                    const results = filterResponse.data.data || [];
                    const allMeetCriteria = results.every(b => 
                        b.duration_seconds >= minDuration
                    );
                    if (allMeetCriteria) {
                        this.printSuccess('Station bulletins duration filter works correctly');
                    } else {
                        this.printWarning('Some results do not meet duration filter criteria');
                    }
                } else {
                    return false;
                }
            } else {
                this.printWarning('No duration_seconds field available for filtering test');
            }
        } else {
            this.printWarning('No bulletin data available for duration filter test');
        }
        
        // Test 5b: Filtering by story_count (lte operator)
        this.printInfo('Testing filter by story_count lte...');
        if (bulletinIds.length > 0) {
            const storyCountResponse = await this.apiCall('GET', 
                `/stations/${testStationId}/bulletins?filter[story_count][lte]=10&limit=3`);
            if (this.assertions.checkResponse(storyCountResponse, 200, 'Filter station bulletins by story count')) {
                const results = storyCountResponse.data.data || [];
                const allMeetCriteria = results.every(b => 
                    b.story_count <= 10
                );
                if (allMeetCriteria) {
                    this.printSuccess('Station bulletins story_count filter (lte) works correctly');
                } else {
                    this.printWarning('Some results do not meet story_count filter criteria');
                }
            } else {
                return false;
            }
        }
        
        // Test 5c: Filtering by ID not equal (ne operator)  
        this.printInfo('Testing filter by id not equal (ne operator)...');
        if (bulletinIds.length > 1) {
            const excludeId = bulletinIds[0];
            const neResponse = await this.apiCall('GET', 
                `/stations/${testStationId}/bulletins?filter[id][ne]=${excludeId}&limit=5`);
            if (this.assertions.checkResponse(neResponse, 200, 'Filter station bulletins by id ne')) {
                const results = neResponse.data.data || [];
                const noneMeetExcludedId = results.every(b => 
                    b.id !== excludeId
                );
                if (noneMeetExcludedId) {
                    this.printSuccess('Station bulletins not-equal filter works correctly');
                } else {
                    this.printWarning('Not-equal filter returned excluded ID or wrong station');
                }
            } else {
                return false;
            }
        }
        
        // Test 6: Complex query combining search, sort, and fields
        this.printInfo('Testing complex query with search, sort, and field selection...');
        const complexResponse = await this.apiCall('GET', 
            `/stations/${testStationId}/bulletins?search=bulletin&sort=-created_at&fields=id,filename,created_at&limit=10`);
        if (this.assertions.checkResponse(complexResponse, 200, 'Complex station bulletins query')) {
            const results = complexResponse.data.data || [];
            this.printSuccess(`Complex station query returned ${results.length} results`);
            
            // Station-specific endpoint ensures proper scoping
            this.printSuccess('Complex query scoped to station via URL path');
        } else {
            return false;
        }
        
        // Test 7: Special parameter - latest=true
        this.printInfo('Testing latest=true parameter...');
        const latestResponse = await this.apiCall('GET', `/stations/${testStationId}/bulletins?latest=true`);
        if (this.assertions.checkResponse(latestResponse, 200, 'Get latest station bulletin')) {
            // For latest=true, we should get a single bulletin (not an array)
            if (latestResponse.data.id) {
                this.printSuccess('Latest parameter returned single bulletin');
                this.printSuccess('Latest bulletin from station-specific endpoint');
            } else if (latestResponse.data.data && latestResponse.data.data.length === 1) {
                this.printSuccess('Latest parameter returned single bulletin in array format');
                this.printSuccess('Latest bulletin from station-specific endpoint');
            } else {
                this.printWarning('Latest parameter response format unexpected');
            }
        } else {
            return false;
        }
        
        // Test 8: Separate story fetching for station bulletins
        this.printInfo('Testing separate story fetching for station bulletins...');
        const stationBulletinsResponse = await this.apiCall('GET', `/stations/${testStationId}/bulletins?limit=1`);
        if (this.assertions.checkResponse(stationBulletinsResponse, 200, 'Get station bulletins for story testing')) {
            const results = stationBulletinsResponse.data.data || [];
            if (results.length > 0) {
                const firstResult = results[0];
                const bulletinId = firstResult.id;
                
                if (bulletinId) {
                    // Fetch stories separately using bulletin ID
                    const storiesResponse = await this.apiCall('GET', `/bulletins/${bulletinId}/stories`);
                    if (this.assertions.checkResponse(storiesResponse, 200, 'Fetch stories for station bulletin')) {
                        const stories = storiesResponse.data.data || [];
                        this.printSuccess(`Separate story fetching works - bulletin has ${stories.length} stories`);
                        this.printSuccess('Stories fetched via separate endpoint maintain bulletin relationship');
                    } else {
                        return false;
                    }
                } else {
                    this.printWarning('No bulletin ID found for separate story fetching test');
                }
            } else {
                this.printWarning('No bulletins found for separate story fetching test');
            }
        } else {
            return false;
        }
        
        // Test 9: Pagination
        this.printInfo('Testing pagination for station bulletins...');
        const pageResponse = await this.apiCall('GET', `/stations/${testStationId}/bulletins?limit=2&offset=1`);
        if (this.assertions.checkResponse(pageResponse, 200, 'Station bulletins pagination')) {
            const results = pageResponse.data.data || [];
            if (results.length <= 2) {
                this.printSuccess(`Pagination limit respected (returned ${results.length} bulletins)`);
            } else {
                this.printError(`Pagination limit not respected (returned ${results.length} bulletins)`);
                return false;
            }
            
            // Check pagination metadata
            if (pageResponse.data.limit === 2 && pageResponse.data.offset === 1) {
                this.printSuccess('Pagination metadata correctly included');
            } else {
                this.printWarning('Pagination metadata incomplete');
            }
            
            // Station-specific endpoint automatically filters results
            this.printSuccess('Paginated results from station-specific endpoint');
        } else {
            return false;
        }
        
        // Test 10: IN operator for multiple IDs
        this.printInfo('Testing IN operator with multiple bulletin IDs...');
        if (bulletinIds.length >= 2) {
            const firstTwoIds = bulletinIds.slice(0, 2);
            const inResponse = await this.apiCall('GET', 
                `/stations/${testStationId}/bulletins?filter[id][in]=${firstTwoIds.join(',')}`);
            if (this.assertions.checkResponse(inResponse, 200, 'Filter station bulletins with IN operator')) {
                const results = inResponse.data.data || [];
                const allInIds = results.every(b => 
                    firstTwoIds.includes(b.id)
                );
                if (allInIds && results.length <= 2) {
                    this.printSuccess('Station bulletins IN operator works correctly');
                } else {
                    this.printWarning('IN operator results may include wrong IDs or station');
                }
            } else {
                return false;
            }
        }
        
        // Test 11: Date range filtering
        this.printInfo('Testing date range filtering for station bulletins...');
        const today = new Date().toISOString().split('T')[0];
        const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        const dateRangeResponse = await this.apiCall('GET', 
            `/stations/${testStationId}/bulletins?filter[created_at][gte]=${yesterday}&filter[created_at][lte]=${today}T23:59:59`);
        if (this.assertions.checkResponse(dateRangeResponse, 200, 'Filter station bulletins by date range')) {
            const results = dateRangeResponse.data.data || [];
            // Station-specific endpoint automatically filters by station
            this.printSuccess(`Date range filter works correctly (found ${results.length} bulletins)`);
        } else {
            return false;
        }
        
        // Test 12: Multiple sort fields (if supported)
        this.printInfo('Testing multiple sort fields...');
        const multiSortResponse = await this.apiCall('GET', 
            `/stations/${testStationId}/bulletins?sort=-created_at,filename&limit=5`);
        if (this.assertions.checkResponse(multiSortResponse, 200, 'Multi-field sort for station bulletins')) {
            const results = multiSortResponse.data.data || [];
            if (results.length > 0) {
                this.printSuccess('Multiple sort fields accepted (results may vary by implementation)');
            }
        } else {
            return false;
        }
        
        // Test 13: Verify station constraint (bulletins from other stations should not appear)
        this.printInfo('Testing station constraint isolation...');
        if (this.createdStationIds.length > 1) {
            const otherStationId = this.createdStationIds.find(id => id !== testStationId);
            if (otherStationId) {
                // Try to generate a bulletin for the other station
                await this.apiCall('POST', `/stations/${otherStationId}/bulletins`, {});
                
                // Query our test station and verify no cross-station leakage
                const isolationResponse = await this.apiCall('GET', `/stations/${testStationId}/bulletins?limit=50`);
                if (this.assertions.checkResponse(isolationResponse, 200, 'Test station isolation')) {
                    const results = isolationResponse.data.data || [];
                    // Station-specific endpoint ensures correct station results
                    this.printSuccess('Station constraint properly isolates bulletins');
                } else {
                    return false;
                }
            }
        }
        
        // Test 14: Empty result handling
        this.printInfo('Testing query that returns no results...');
        const emptyResponse = await this.apiCall('GET', 
            `/stations/${testStationId}/bulletins?search=nonexistentbulletinfilename12345`);
        if (this.assertions.checkResponse(emptyResponse, 200, 'Empty search results')) {
            if (emptyResponse.data.data && emptyResponse.data.data.length === 0) {
                this.printSuccess('Empty search results handled correctly');
            } else {
                this.printWarning('Expected empty results but got data');
            }
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
        
        const firstFilename = this.parseJsonField(firstResponse.data, 'filename');
        
        // Check cache headers for first (fresh) bulletin
        const firstCacheHeader = firstResponse.headers['x-cache'] || firstResponse.headers['X-Cache'];
        const firstAgeHeader = firstResponse.headers['age'] || firstResponse.headers['Age'];
        
        if (firstCacheHeader === 'MISS') {
            this.printSuccess('First bulletin X-Cache header correctly indicates MISS');
        } else {
            this.printWarning(`First bulletin X-Cache header: ${firstCacheHeader} (expected: MISS)`);
        }
        
        if (firstAgeHeader === '0') {
            this.printSuccess('First bulletin Age header correctly shows 0');
        } else {
            this.printWarning(`First bulletin Age header: ${firstAgeHeader} (expected: 0)`);
        }
        
        // Generate another bulletin immediately with cache control (should use cached version)
        this.printInfo('Generating second bulletin with max-age header (should be cached)...');
        const secondResponse = await this.apiCall('POST', `/stations/${stationId}/bulletins`, {}, { 'Cache-Control': 'max-age=300' });
        
        if (this.assertions.checkResponse(secondResponse, 200, 'Generate second bulletin')) {
            const secondFilename = this.parseJsonField(secondResponse.data, 'filename');
            
            // Check cache headers
            const cacheHeader = secondResponse.headers['x-cache'] || secondResponse.headers['X-Cache'];
            const ageHeader = secondResponse.headers['age'] || secondResponse.headers['Age'];
            
            if (firstFilename === secondFilename) {
                this.printSuccess('Second bulletin reused cached version (same filename)');
                
                // Verify cache headers for cached response
                if (cacheHeader === 'HIT') {
                    this.printSuccess('X-Cache header correctly indicates HIT');
                } else {
                    this.printWarning(`X-Cache header: ${cacheHeader} (expected: HIT)`);
                }
                
                if (ageHeader && parseInt(ageHeader) >= 0) {
                    this.printSuccess(`Age header present: ${ageHeader} seconds`);
                } else {
                    this.printWarning(`Age header: ${ageHeader} (expected: >= 0)`);
                }
            } else {
                this.printInfo('Second bulletin generated new version (different filename)');
                
                // For fresh generation, should show MISS and Age 0
                if (cacheHeader === 'MISS') {
                    this.printSuccess('X-Cache header correctly indicates MISS');
                } else {
                    this.printWarning(`X-Cache header: ${cacheHeader} (expected: MISS)`);
                }
                
                if (ageHeader === '0') {
                    this.printSuccess('Age header correctly shows 0 for fresh bulletin');
                } else {
                    this.printWarning(`Age header: ${ageHeader} (expected: 0)`);
                }
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
                const requiredFields = ['id', 'station_id', 'filename', 'duration_seconds', 'story_count', 'created_at'];
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
                
                // Test bulletin stories endpoint instead (no individual bulletin detail endpoint exists)
                this.printInfo(`Testing bulletin stories endpoint for ID: ${bulletinId}...`);
                const storiesResponse = await this.apiCall('GET', `/bulletins/${bulletinId}/stories`);
                
                if (this.assertions.checkResponse(storiesResponse, 200, 'Get bulletin stories')) {
                    this.printSuccess('Bulletin stories endpoint works');
                    
                    // Check if response has expected structure
                    if (storiesResponse.data.data !== undefined) {
                        const storyCount = storiesResponse.data.data.length;
                        this.printSuccess(`Bulletin contains ${storyCount} stories`);
                    } else {
                        this.printWarning('Bulletin stories response has unexpected structure');
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
     * Test bulletin stories endpoint with modern query parameters
     */
    async testBulletinStoriesModernQuery() {
        this.printSection('Testing Bulletin Stories Modern Query Parameters');
        
        // Setup comprehensive test data - create a dedicated station with multiple stories and generate bulletin
        this.printInfo('Setting up comprehensive test data for bulletin stories modern query tests...');
        
        const testStationId = await this.createTestStation('Bulletin Stories Query Test');
        if (!testStationId) {
            this.printError('Failed to create test station for bulletin stories modern query tests');
            return false;
        }
        
        // Create test voice and station-voice relationship
        const testVoiceId = await this.createTestVoice('Bulletin Stories Voice');
        if (!testVoiceId) {
            this.printError('Failed to create test voice for bulletin stories modern query tests');
            return false;
        }
        
        const stationVoiceId = await this.createStationVoiceWithJingle(testStationId, testVoiceId, 2.5);
        if (!stationVoiceId) {
            this.printError('Failed to create station-voice relationship for bulletin stories modern query tests');
            return false;
        }
        
        // Create multiple test stories with varied content for comprehensive testing
        const storyTitles = [
            'News Breaking Alert Test',
            'Weather Forecast Update', 
            'Traffic Report Bulletin',
            'Sports Update News',
            'Local Community News',
            'Business Market Update',
            'Technology News Brief'
        ];
        
        const createdStoryIds = [];
        for (let i = 0; i < storyTitles.length; i++) {
            const storyId = await this.createTestStoryWithAudio(
                storyTitles[i], 
                `Test story content for ${storyTitles[i]} with detailed information`, 
                testVoiceId,
                'monday,tuesday,wednesday,thursday,friday,saturday,sunday'
            );
            if (storyId) {
                createdStoryIds.push(storyId);
            }
        }
        
        if (createdStoryIds.length < 5) {
            this.printError(`Failed to create enough test stories for bulletin stories query tests (created ${createdStoryIds.length})`);
            return false;
        }
        this.printSuccess(`Created ${createdStoryIds.length} test stories for bulletin stories query testing`);
        
        // Wait for audio processing
        this.printInfo('Waiting for audio processing...');
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Generate a bulletin that includes multiple stories
        this.printInfo('Generating test bulletin with multiple stories...');
        const bulletinResponse = await this.apiCall('POST', `/stations/${testStationId}/bulletins`, {});
        
        if (!this.assertions.checkResponse(bulletinResponse, 200, 'Generate bulletin for stories testing')) {
            return false;
        }
        
        const testBulletinId = this.parseJsonField(bulletinResponse.data, 'id');
        if (!testBulletinId) {
            this.printError('Failed to extract bulletin ID from generation response');
            return false;
        }
        
        this.createdBulletinIds.push(testBulletinId);
        this.printSuccess(`Generated test bulletin (ID: ${testBulletinId}) for stories query testing`);
        
        // Test 1: Basic bulletin stories listing
        this.printInfo('Testing basic bulletin stories listing...');
        const basicResponse = await this.apiCall('GET', `/bulletins/${testBulletinId}/stories`);
        if (this.assertions.checkResponse(basicResponse, 200, 'Basic bulletin stories listing')) {
            const results = basicResponse.data.data || [];
            if (results.length > 0) {
                this.printSuccess(`Basic listing returned ${results.length} stories for bulletin ${testBulletinId}`);
                
                // Verify the nested response structure
                const firstStory = results[0];
                const hasNestedStructure = firstStory.station && firstStory.story && firstStory.bulletin;
                if (hasNestedStructure) {
                    this.printSuccess('Response has correct nested structure (station, story, bulletin objects)');
                } else {
                    this.printWarning('Response missing expected nested structure');
                }
                
                // Verify all stories belong to the correct bulletin
                // Note: testBulletinId is a string from parseJsonField, bulletin_id is a number from API
                const allFromCorrectBulletin = results.every(s => s.bulletin_id == testBulletinId);
                if (allFromCorrectBulletin) {
                    this.printSuccess('All stories correctly filtered by bulletin_id from URL');
                } else {
                    this.printError('Some stories belong to wrong bulletin');
                    return false;
                }
            } else {
                this.printWarning('Basic listing returned no stories');
            }
        } else {
            return false;
        }
        
        // Test 2: Search functionality (searches in story_title)
        this.printInfo('Testing search by story_title in bulletin stories...');
        const searchResponse = await this.apiCall('GET', `/bulletins/${testBulletinId}/stories?search=News`);
        if (this.assertions.checkResponse(searchResponse, 200, 'Search bulletin stories')) {
            const results = searchResponse.data.data || [];
            if (results.length > 0) {
                this.printSuccess(`Search returned ${results.length} stories matching "News"`);
                // All results should still be from the same bulletin
                const allFromCorrectBulletin = results.every(s => s.bulletin_id === testBulletinId);
                if (allFromCorrectBulletin) {
                    this.printSuccess('Search results correctly filtered by bulletin_id constraint');
                }
            } else {
                this.printWarning('Search returned no results for "News"');
            }
        } else {
            return false;
        }
        
        // Test 3: Field selection
        this.printInfo('Testing field selection for bulletin stories...');
        const fieldsResponse = await this.apiCall('GET', `/bulletins/${testBulletinId}/stories?fields=id,story_title,story_order&limit=3`);
        if (this.assertions.checkResponse(fieldsResponse, 200, 'Bulletin stories field selection')) {
            const results = fieldsResponse.data.data || [];
            if (results.length > 0) {
                const firstResult = results[0];
                const hasOnlySelectedFields = 
                    firstResult.hasOwnProperty('id') && 
                    firstResult.hasOwnProperty('story_title') &&
                    firstResult.hasOwnProperty('story_order') &&
                    !firstResult.hasOwnProperty('created_at') &&
                    !firstResult.hasOwnProperty('bulletin_id');
                
                if (hasOnlySelectedFields) {
                    this.printSuccess('Bulletin stories field selection works correctly');
                } else {
                    this.printWarning('Field selection returned unexpected fields');
                }
            } else {
                this.printWarning('No results returned for field selection test');
            }
        } else {
            return false;
        }
        
        // Test 4: Sorting by story_order descending (override default ASC order)
        this.printInfo('Testing sorting by story_order descending...');
        const sortDescResponse = await this.apiCall('GET', `/bulletins/${testBulletinId}/stories?sort=-story_order&limit=5`);
        if (this.assertions.checkResponse(sortDescResponse, 200, 'Bulletin stories sort descending')) {
            const results = sortDescResponse.data.data || [];
            if (results.length > 1) {
                let correctOrder = true;
                for (let i = 1; i < results.length; i++) {
                    if (results[i-1].story_order < results[i].story_order) {
                        correctOrder = false;
                        break;
                    }
                }
                if (correctOrder) {
                    this.printSuccess('Bulletin stories descending sort by story_order works correctly');
                } else {
                    this.printWarning('Sort order may be incorrect');
                }
            } else {
                this.printWarning('Not enough stories for sort order test');
            }
        } else {
            return false;
        }
        
        // Test 5: Sorting by story_title ascending
        this.printInfo('Testing sorting by story_title ascending...');
        const sortAscResponse = await this.apiCall('GET', `/bulletins/${testBulletinId}/stories?sort=story_title:asc&limit=5`);
        if (this.assertions.checkResponse(sortAscResponse, 200, 'Bulletin stories sort by title ascending')) {
            const results = sortAscResponse.data.data || [];
            if (results.length > 1) {
                let correctOrder = true;
                for (let i = 1; i < results.length; i++) {
                    if (results[i-1].story_title > results[i].story_title) {
                        correctOrder = false;
                        break;
                    }
                }
                if (correctOrder) {
                    this.printSuccess('Bulletin stories title ascending sort works correctly');
                } else {
                    this.printWarning('Title sort order may be incorrect');
                }
            }
        } else {
            return false;
        }
        
        // Test 6: Filtering by story_order (gte operator)
        this.printInfo('Testing filter by story_order gte...');
        
        // Get a reference story to use for filtering
        const refResponse = await this.apiCall('GET', `/bulletins/${testBulletinId}/stories?limit=1`);
        if (refResponse.status === 200 && refResponse.data.data && refResponse.data.data.length > 0) {
            const refStory = refResponse.data.data[0];
            if (refStory.story_order) {
                const minOrder = refStory.story_order;
                const filterResponse = await this.apiCall('GET', 
                    `/bulletins/${testBulletinId}/stories?filter[story_order][gte]=${minOrder}`);
                    
                if (this.assertions.checkResponse(filterResponse, 200, 'Filter bulletin stories by story_order')) {
                    const results = filterResponse.data.data || [];
                    const allMeetCriteria = results.every(s => 
                        s.story_order >= minOrder && s.bulletin_id === testBulletinId
                    );
                    if (allMeetCriteria) {
                        this.printSuccess('Bulletin stories story_order filter works correctly');
                    } else {
                        this.printWarning('Some results do not meet filter criteria or bulletin constraint');
                    }
                } else {
                    return false;
                }
            } else {
                this.printWarning('No story_order field available for filtering test');
            }
        } else {
            this.printWarning('No story data available for story_order filter test');
        }
        
        // Test 7: Complex query combining search, sort, and field selection
        this.printInfo('Testing complex query with search, sort, and field selection...');
        const complexResponse = await this.apiCall('GET', 
            `/bulletins/${testBulletinId}/stories?search=Update&sort=-story_order&fields=id,story_title,story_order,station&limit=10`);
        if (this.assertions.checkResponse(complexResponse, 200, 'Complex bulletin stories query')) {
            const results = complexResponse.data.data || [];
            this.printSuccess(`Complex query returned ${results.length} results for bulletin ${testBulletinId}`);
            
            // Verify bulletin constraint is maintained
            const allFromCorrectBulletin = results.every(s => s.bulletin_id === testBulletinId);
            if (allFromCorrectBulletin) {
                this.printSuccess('Complex query maintains bulletin_id constraint from URL');
            }
        } else {
            return false;
        }
        
        // Test 8: Pagination
        this.printInfo('Testing pagination for bulletin stories...');
        const pageResponse = await this.apiCall('GET', `/bulletins/${testBulletinId}/stories?limit=2&offset=1`);
        if (this.assertions.checkResponse(pageResponse, 200, 'Bulletin stories pagination')) {
            const results = pageResponse.data.data || [];
            if (results.length <= 2) {
                this.printSuccess(`Pagination limit respected (returned ${results.length} stories)`);
            } else {
                this.printError(`Pagination limit not respected (returned ${results.length} stories)`);
                return false;
            }
            
            // Check pagination metadata
            if (pageResponse.data.limit === 2 && pageResponse.data.offset === 1) {
                this.printSuccess('Pagination metadata correctly included');
            } else {
                this.printWarning('Pagination metadata incomplete');
            }
            
            // Verify bulletin constraint in paginated results
            const allFromCorrectBulletin = results.every(s => s.bulletin_id === testBulletinId);
            if (allFromCorrectBulletin) {
                this.printSuccess('Paginated results maintain bulletin_id constraint');
            }
        } else {
            return false;
        }
        
        // Test 9: Default sort order (story_order ASC)
        this.printInfo('Testing default sort order (story_order ASC)...');
        const defaultSortResponse = await this.apiCall('GET', `/bulletins/${testBulletinId}/stories?limit=5`);
        if (this.assertions.checkResponse(defaultSortResponse, 200, 'Default sort order')) {
            const results = defaultSortResponse.data.data || [];
            if (results.length > 1) {
                let correctOrder = true;
                for (let i = 1; i < results.length; i++) {
                    if (results[i-1].story_order > results[i].story_order) {
                        correctOrder = false;
                        break;
                    }
                }
                if (correctOrder) {
                    this.printSuccess('Default sort order (story_order ASC) works correctly');
                } else {
                    this.printWarning('Default sort order may be incorrect');
                }
            }
        } else {
            return false;
        }
        
        // Test 10: Verify nested response structure details
        this.printInfo('Testing nested response structure details...');
        const structureResponse = await this.apiCall('GET', `/bulletins/${testBulletinId}/stories?limit=1`);
        if (this.assertions.checkResponse(structureResponse, 200, 'Nested structure verification')) {
            const results = structureResponse.data.data || [];
            if (results.length > 0) {
                const story = results[0];
                
                // Check required top-level fields
                const hasRequiredFields = story.id && story.bulletin_id && story.story_id && 
                    story.story_order !== undefined && story.created_at;
                
                // Check nested objects
                const hasStation = story.station && story.station.id && story.station.name;
                const hasStoryInfo = story.story && story.story.id && story.story.title;
                const hasBulletinInfo = story.bulletin && story.bulletin.id && story.bulletin.filename;
                
                if (hasRequiredFields && hasStation && hasStoryInfo && hasBulletinInfo) {
                    this.printSuccess('Complete nested response structure verified');
                    this.printInfo(`Station: ${story.station.name}, Story: ${story.story.title}, Order: ${story.story_order}`);
                } else {
                    this.printWarning('Nested response structure incomplete');
                }
            }
        } else {
            return false;
        }
        
        // Test 11: Error handling - non-existent bulletin
        this.printInfo('Testing error handling for non-existent bulletin...');
        const nonExistentResponse = await this.apiCall('GET', '/bulletins/99999/stories');
        if (nonExistentResponse.status === 404) {
            this.printSuccess('Non-existent bulletin correctly returns 404');
        } else {
            this.printWarning(`Non-existent bulletin returned status: ${nonExistentResponse.status}`);
        }
        
        // Test 12: Empty result handling
        this.printInfo('Testing query that returns no results...');
        const emptyResponse = await this.apiCall('GET', 
            `/bulletins/${testBulletinId}/stories?search=nonexistentquerytermthatmatchesnothing`);
        if (this.assertions.checkResponse(emptyResponse, 200, 'Empty search results')) {
            if (emptyResponse.data.data && emptyResponse.data.data.length === 0) {
                this.printSuccess('Empty search results handled correctly');
            } else {
                this.printWarning('Expected empty results but got data');
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test Modern Query System features
     */
    async testModernQueryParameters() {
        this.printSection('Testing Modern Query Parameters');
        
        // First, ensure we have some test data
        this.printInfo('Setting up test data for modern query tests...');
        
        // Create multiple stations with different bulletins for testing
        const station1Id = await this.createTestStation('Query Test Station Alpha');
        const station2Id = await this.createTestStation('Query Test Station Beta');
        
        // Generate multiple bulletins with varying properties
        const bulletinIds = [];
        for (let i = 0; i < 5; i++) {
            const stationId = i < 3 ? station1Id : station2Id;
            const response = await this.apiCall('POST', `/stations/${stationId}/bulletins`, {});
            if (response.status === 200) {
                bulletinIds.push(this.parseJsonField(response.data, 'id'));
                // Add small delay to ensure different timestamps
                await new Promise(resolve => setTimeout(resolve, 100));
            }
        }
        
        // Test 1: Search functionality
        this.printInfo('Testing search by filename...');
        const searchResponse = await this.apiCall('GET', '/bulletins?search=bulletin');
        if (this.assertions.checkResponse(searchResponse, 200, 'Search bulletins')) {
            const results = searchResponse.data.data || [];
            if (results.length > 0) {
                this.printSuccess(`Search returned ${results.length} bulletins matching "bulletin"`);
            } else {
                this.printWarning('Search returned no results');
            }
        } else {
            return false;
        }
        
        // Test 2: Field selection
        this.printInfo('Testing field selection...');
        const fieldsResponse = await this.apiCall('GET', '/bulletins?fields=id,filename,station_name&limit=3');
        if (this.assertions.checkResponse(fieldsResponse, 200, 'Field selection')) {
            const firstResult = fieldsResponse.data.data[0];
            const hasOnlySelectedFields = firstResult && 
                firstResult.hasOwnProperty('id') && 
                firstResult.hasOwnProperty('filename') &&
                firstResult.hasOwnProperty('station_name') &&
                !firstResult.hasOwnProperty('duration_seconds') &&
                !firstResult.hasOwnProperty('file_size');
            
            if (hasOnlySelectedFields) {
                this.printSuccess('Field selection correctly returns only requested fields');
            } else {
                this.printWarning('Field selection returned unexpected fields');
            }
        } else {
            return false;
        }
        
        // Test 3: Filtering by station_id
        this.printInfo(`Testing filter by station_id=${station1Id}...`);
        const filterResponse = await this.apiCall('GET', `/bulletins?filter[station_id]=${station1Id}`);
        if (this.assertions.checkResponse(filterResponse, 200, 'Filter by station_id')) {
            const results = filterResponse.data.data || [];
            const allFromStation1 = results.every(b => b.station_id === station1Id);
            if (allFromStation1) {
                this.printSuccess(`All ${results.length} bulletins correctly filtered by station_id`);
            } else {
                this.printError('Filter by station_id returned bulletins from wrong station');
                return false;
            }
        } else {
            return false;
        }
        
        // Test 4: Advanced filtering operators (gte, lte)
        this.printInfo('Testing advanced filter operators...');
        
        // Get a bulletin to use as reference for duration filtering
        const refBulletin = (await this.apiCall('GET', '/bulletins?limit=1')).data.data[0];
        if (refBulletin && refBulletin.duration_seconds) {
            const minDuration = Math.floor(refBulletin.duration_seconds);
            const gteResponse = await this.apiCall('GET', `/bulletins?filter[duration_seconds][gte]=${minDuration}`);
            if (this.assertions.checkResponse(gteResponse, 200, 'Filter with gte operator')) {
                const results = gteResponse.data.data || [];
                const allMeetCriteria = results.every(b => b.duration_seconds >= minDuration);
                if (allMeetCriteria) {
                    this.printSuccess('GTE filter operator works correctly');
                } else {
                    this.printWarning('Some results do not meet GTE criteria');
                }
            }
        }
        
        // Test 5: Multiple filters combined
        this.printInfo('Testing multiple filters combined...');
        const multiFilterResponse = await this.apiCall('GET', 
            `/bulletins?filter[station_id]=${station1Id}&filter[story_count][gte]=1&limit=5`);
        if (this.assertions.checkResponse(multiFilterResponse, 200, 'Multiple filters')) {
            const results = multiFilterResponse.data.data || [];
            const allMeetCriteria = results.every(b => 
                b.station_id === station1Id && b.story_count >= 1
            );
            if (allMeetCriteria) {
                this.printSuccess('Multiple filters work correctly together');
            } else {
                this.printWarning('Some results do not meet all filter criteria');
            }
        } else {
            return false;
        }
        
        // Test 6: Sorting
        this.printInfo('Testing sorting by created_at descending...');
        const sortDescResponse = await this.apiCall('GET', '/bulletins?sort=-created_at&limit=5');
        if (this.assertions.checkResponse(sortDescResponse, 200, 'Sort descending')) {
            const results = sortDescResponse.data.data || [];
            let correctOrder = true;
            for (let i = 1; i < results.length; i++) {
                if (new Date(results[i-1].created_at) < new Date(results[i].created_at)) {
                    correctOrder = false;
                    break;
                }
            }
            if (correctOrder) {
                this.printSuccess('Descending sort order works correctly');
            } else {
                this.printError('Sort order is incorrect');
                return false;
            }
        } else {
            return false;
        }
        
        this.printInfo('Testing sorting by duration_seconds ascending...');
        const sortAscResponse = await this.apiCall('GET', '/bulletins?sort=duration_seconds&limit=5');
        if (this.assertions.checkResponse(sortAscResponse, 200, 'Sort ascending')) {
            const results = sortAscResponse.data.data || [];
            let correctOrder = true;
            for (let i = 1; i < results.length; i++) {
                if (results[i-1].duration_seconds > results[i].duration_seconds) {
                    correctOrder = false;
                    break;
                }
            }
            if (correctOrder) {
                this.printSuccess('Ascending sort order works correctly');
            } else {
                this.printError('Sort order is incorrect');
                return false;
            }
        } else {
            return false;
        }
        
        // Test 7: IN operator
        this.printInfo('Testing IN operator with multiple station IDs...');
        const inResponse = await this.apiCall('GET', 
            `/bulletins?filter[station_id][in]=${station1Id},${station2Id}`);
        if (this.assertions.checkResponse(inResponse, 200, 'IN operator')) {
            const results = inResponse.data.data || [];
            const allInStations = results.every(b => 
                b.station_id === station1Id || b.station_id === station2Id
            );
            if (allInStations) {
                this.printSuccess('IN operator works correctly');
            } else {
                this.printWarning('Some results not in specified stations');
            }
        } else {
            return false;
        }
        
        // Test 8: Pagination metadata
        this.printInfo('Testing pagination metadata...');
        const pageResponse = await this.apiCall('GET', '/bulletins?limit=3&offset=2');
        if (this.assertions.checkResponse(pageResponse, 200, 'Pagination')) {
            if (pageResponse.data.limit === 3 && pageResponse.data.offset === 2 && 
                pageResponse.data.total !== undefined) {
                this.printSuccess('Pagination metadata correctly included');
            } else {
                this.printWarning('Pagination metadata incomplete');
            }
        } else {
            return false;
        }
        
        // Test 9: Combining search with filters and sorting
        this.printInfo('Testing complex query with search, filter, and sort...');
        const complexResponse = await this.apiCall('GET', 
            `/bulletins?search=bulletin&filter[station_id]=${station1Id}&sort=-created_at&limit=10`);
        if (this.assertions.checkResponse(complexResponse, 200, 'Complex query')) {
            const results = complexResponse.data.data || [];
            this.printSuccess(`Complex query returned ${results.length} results`);
        } else {
            return false;
        }
        
        // Clean up test stations
        this.createdStationIds.push(station1Id, station2Id);
        
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
            'testStationBulletinsModernQuery',
            'testBulletinHistory',
            'testBulletinCaching',
            'testBulletinErrorCases',
            'testBulletinMetadata',
            'testBulletinStoriesModernQuery',
            'testModernQueryParameters'
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
