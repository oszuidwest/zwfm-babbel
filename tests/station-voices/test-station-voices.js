// Babbel station-voices tests.
// Tests station-voice relationship management and jingle functionality.

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

class StationVoicesTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);
        
        // Global variables for tracking created resources
        this.createdStationIds = [];
        this.createdVoiceIds = [];
        this.createdStationVoiceIds = [];
    }
    
    /**
     * Helper to create JSON data for station-voice requests
     */
    createStationVoiceData(data) {
        const stationVoiceData = {};

        if (data.station_id !== undefined) stationVoiceData.station_id = data.station_id;
        if (data.voice_id !== undefined) stationVoiceData.voice_id = data.voice_id;
        if (data.mix_point !== undefined) stationVoiceData.mix_point = data.mix_point;

        return stationVoiceData;
    }
    
    /**
     * Helper function to create a station
     */
    async createStation(name) {
        // Add timestamp to ensure uniqueness
        const uniqueName = `${name}_${Date.now()}_${process.pid}`;
        const response = await this.apiCall('POST', '/stations', {
            name: uniqueName,
            max_stories_per_block: 5,
            pause_seconds: 2.0
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
     * Helper function to create a voice
     */
    async createVoice(name) {
        // Add timestamp to ensure uniqueness
        const uniqueName = `${name}_${Date.now()}_${process.pid}`;
        const response = await this.apiCall('POST', '/voices', {
            name: uniqueName
        });
        
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
     * Test creating station-voice relationship
     */
    async testCreateStationVoice() {
        this.printSection('Testing Station-Voice Creation');
        
        // Create a station and voice first
        this.printInfo('Creating test station...');
        const stationId = await this.createStation('SV Test Station');
        if (!stationId) {
            this.printError('Failed to create test station');
            return false;
        }
        this.printSuccess(`Created station (ID: ${stationId})`);
        
        this.printInfo('Creating test voice...');
        const voiceId = await this.createVoice('SV Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }
        this.printSuccess(`Created voice (ID: ${voiceId})`);
        
        // Test creating station-voice relationship with JSON
        this.printInfo('Creating station-voice relationship with JSON...');
        const svData = this.createStationVoiceData({
            station_id: parseInt(stationId),
            voice_id: parseInt(voiceId),
            mix_point: 2.5
        });

        const response = await this.apiCall('POST', '/station-voices', svData);

        if (response.status === 201) {
            const svId = this.parseJsonField(response.data, 'id');
            if (svId) {
                this.createdStationVoiceIds.push(svId);
                this.printSuccess(`Created station-voice relationship (ID: ${svId})`);
            } else {
                this.printError('Could not extract station-voice ID from response');
                return false;
            }
        } else {
            this.printError(`Failed to create station-voice relationship (HTTP: ${response.status})`);
            return false;
        }

        // Test creating duplicate relationship (should fail)
        this.printInfo('Testing duplicate station-voice relationship...');
        const duplicateData = this.createStationVoiceData({
            station_id: parseInt(stationId),
            voice_id: parseInt(voiceId),
            mix_point: 3.0
        });

        const duplicateResponse = await this.apiCall('POST', '/station-voices', duplicateData);
        
        if (duplicateResponse.status === 409) {
            this.printSuccess('Duplicate relationship correctly rejected (409 Conflict)');
        } else {
            this.printError(`Duplicate relationship not rejected (HTTP: ${duplicateResponse.status})`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test creating station-voice with audio file upload
     */
    async testCreateStationVoiceWithAudio() {
        this.printSection('Testing Station-Voice Creation with Audio Upload');

        // Create a station and voice first
        this.printInfo('Creating test station for audio upload...');
        const stationId = await this.createStation('Audio Test Station');
        if (!stationId) {
            this.printError('Failed to create test station');
            return false;
        }

        this.printInfo('Creating test voice for audio upload...');
        const voiceId = await this.createVoice('Audio Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }

        // Create a simple test audio file if it doesn't exist
        const testAudio = '/tmp/test_jingle.wav';
        const fs = require('fs');

        if (!fs.existsSync(testAudio)) {
            this.printInfo('Creating test audio file...');
            // Create a minimal WAV file (silent audio) for testing
            try {
                const { execSync } = require('child_process');
                execSync(`ffmpeg -f lavfi -i anullsrc=r=44100:cl=stereo -t 1 -f wav "${testAudio}" 2>/dev/null`, { stdio: 'ignore' });
                if (fs.existsSync(testAudio)) {
                    this.printSuccess('Created test audio file');
                } else {
                    this.printWarning('Could not create test audio file, skipping audio upload test');
                    return true; // Skip this test
                }
            } catch (error) {
                this.printWarning('ffmpeg not available, skipping audio upload test');
                return true; // Skip this test
            }
        }

        // Step 1: Create station-voice with JSON (no jingle yet)
        this.printInfo('Step 1: Creating station-voice relationship with JSON...');
        const svData = {
            station_id: parseInt(stationId),
            voice_id: parseInt(voiceId),
            mix_point: 1.5
        };

        const createResponse = await this.apiCall('POST', '/station-voices', svData);

        if (createResponse.status !== 201) {
            this.printError(`Failed to create station-voice (HTTP: ${createResponse.status})`);
            this.printError(`Response: ${JSON.stringify(createResponse.data)}`);
            return false;
        }

        const svId = this.parseJsonField(createResponse.data, 'id');
        if (!svId) {
            this.printError('Could not extract station-voice ID from response');
            return false;
        }

        this.createdStationVoiceIds.push(svId);
        this.printSuccess(`Station-voice relationship created (ID: ${svId})`);

        // Step 2: Upload jingle separately
        this.printInfo('Step 2: Uploading jingle file separately...');
        const jingleUploadResponse = await this.uploadFile(`/station-voices/${svId}/audio`, {}, testAudio, 'jingle');

        if (jingleUploadResponse.status !== 201) {
            this.printError(`Failed to upload jingle (HTTP: ${jingleUploadResponse.status})`);
            this.printError(`Response: ${JSON.stringify(jingleUploadResponse.data)}`);
            return false;
        }

        this.printSuccess('Jingle uploaded successfully');

        // Verify the jingle file was saved
        const jinglePath = `${this.audioDir}/processed/station_${stationId}_voice_${voiceId}_jingle.wav`;
        if (await this.waitForAudioFile(jinglePath, 5)) {
            this.printSuccess('Jingle file saved successfully');
        } else {
            this.printWarning('Jingle file not found at expected location');
        }

        return true;
    }
    
    /**
     * Test basic listing functionality
     */
    async testListStationVoices() {
        this.printSection('Testing Basic Station-Voice Listing');
        
        // Create some test data
        this.printInfo('Creating test data for basic listing...');
        const station1 = await this.createStation('Basic List Station 1');
        const station2 = await this.createStation('Basic List Station 2');
        const voice1 = await this.createVoice('Basic List Voice 1');
        const voice2 = await this.createVoice('Basic List Voice 2');
        
        // Create relationships
        const sv1Data = this.createStationVoiceData({
            station_id: parseInt(station1),
            voice_id: parseInt(voice1),
            mix_point: 1.0
        });
        const sv1Response = await this.apiCall('POST', '/station-voices', sv1Data);

        const sv2Data = this.createStationVoiceData({
            station_id: parseInt(station2),
            voice_id: parseInt(voice2),
            mix_point: 2.0
        });
        const sv2Response = await this.apiCall('POST', '/station-voices', sv2Data);
        
        // Track created station-voice relationships
        if (sv1Response.status === 201) {
            const svId = this.parseJsonField(sv1Response.data, 'id');
            if (svId) this.createdStationVoiceIds.push(svId);
        }
        if (sv2Response.status === 201) {
            const svId = this.parseJsonField(sv2Response.data, 'id');
            if (svId) this.createdStationVoiceIds.push(svId);
        }
        
        // Test basic listing
        this.printInfo('Testing basic station-voice listing...');
        const response = await this.apiCall('GET', '/station-voices');
        
        if (this.assertions.checkResponse(response, 200, 'List station-voices')) {
            const body = response.data;
            this.assertions.assertJsonField(body, 'data', 'Station-voices data array');
            
            const count = body.data ? body.data.length : 0;
            this.printSuccess(`Station-voice listing returned ${count} relationships`);
            
            // Verify response structure and joined data
            if (body.data && body.data.length > 0) {
                const firstRelation = body.data[0];
                this.assertions.assertJsonField(firstRelation, 'id', 'Station-voice ID');
                this.assertions.assertJsonField(firstRelation, 'station_id', 'Station ID');
                this.assertions.assertJsonField(firstRelation, 'voice_id', 'Voice ID');
                this.assertions.assertJsonField(firstRelation, 'mix_point', 'Mix point');
                
                // Check for joined fields from related tables
                if (firstRelation.hasOwnProperty('station_name')) {
                    this.printSuccess('Response includes joined station_name field');
                } else {
                    this.printInfo('Response may not include joined station_name field');
                }
                
                if (firstRelation.hasOwnProperty('voice_name')) {
                    this.printSuccess('Response includes joined voice_name field');
                } else {
                    this.printInfo('Response may not include joined voice_name field');
                }
            }
        } else {
            return false;
        }
        
        return true;
    }

    /**
     * Test audio_file and audio_url fields and filtering
     */
    async testAudioFieldsAndFiltering() {
        this.printSection('Testing Audio Fields and Filtering');

        // Create test data - station-voices WITHOUT audio
        this.printInfo('Creating station-voices without audio for filter testing...');
        const station1 = await this.createStation('Audio Filter Test Station 1');
        const station2 = await this.createStation('Audio Filter Test Station 2');
        const voice1 = await this.createVoice('Audio Filter Test Voice 1');
        const voice2 = await this.createVoice('Audio Filter Test Voice 2');

        if (!station1 || !station2 || !voice1 || !voice2) {
            this.printError('Failed to create test data for audio filter testing');
            return false;
        }

        // Create station-voice relationships without audio
        const sv1Response = await this.apiCall('POST', '/station-voices', this.createStationVoiceData({
            station_id: parseInt(station1),
            voice_id: parseInt(voice1),
            mix_point: 1.0
        }));

        const sv1Id = this.parseJsonField(sv1Response.data, 'id');
        if (sv1Id) this.createdStationVoiceIds.push(sv1Id);

        const sv2Response = await this.apiCall('POST', '/station-voices', this.createStationVoiceData({
            station_id: parseInt(station2),
            voice_id: parseInt(voice2),
            mix_point: 2.0
        }));

        const sv2Id = this.parseJsonField(sv2Response.data, 'id');
        if (sv2Id) this.createdStationVoiceIds.push(sv2Id);

        if (!sv1Id) {
            this.printError('Failed to create station-voice for audio filter testing');
            return false;
        }

        // Test 1: Verify audio_file and audio_url fields are present in response
        this.printInfo('Testing audio_file and audio_url fields in response...');
        const singleResponse = await this.apiCall('GET', `/station-voices/${sv1Id}`);
        if (this.assertions.checkResponse(singleResponse, 200, 'Get single station-voice for audio fields check')) {
            const sv = singleResponse.data;

            // audio_url should always be present (even without audio file)
            if (sv.hasOwnProperty('audio_url') && typeof sv.audio_url === 'string') {
                this.printSuccess('audio_url field is present and always populated');
            } else {
                this.printError('audio_url field is missing or not a string');
                return false;
            }

            // audio_file should be present (empty string when no audio)
            if (sv.hasOwnProperty('audio_file')) {
                if (sv.audio_file === '') {
                    this.printSuccess('audio_file field is present (empty for station-voice without jingle)');
                } else {
                    this.printInfo(`audio_file field has value: ${sv.audio_file}`);
                }
            } else {
                this.printError('audio_file field is missing from response');
                return false;
            }
        } else {
            return false;
        }

        // Test 2: Filter for station-voices WITHOUT audio (filter[audio_url]=)
        this.printInfo('Testing filter for station-voices without audio (filter[audio_url]=)...');
        const noAudioResponse = await this.apiCall('GET', '/station-voices?filter%5Baudio_url%5D=');
        if (this.assertions.checkResponse(noAudioResponse, 200, 'Filter station-voices without audio')) {
            const stationVoices = noAudioResponse.data.data || [];
            // All returned station-voices should have empty audio_file
            const allWithoutAudio = stationVoices.every(sv => sv.audio_file === '');
            if (allWithoutAudio) {
                this.printSuccess(`Audio filter (no audio) works correctly (${stationVoices.length} station-voices without jingle)`);
            } else {
                const withAudio = stationVoices.filter(sv => sv.audio_file !== '');
                this.printError(`Audio filter returned ${withAudio.length} station-voices WITH audio - filter not working`);
                return false;
            }
        } else {
            return false;
        }

        // Test 3: Upload jingle to one station-voice and test WITH audio filter
        this.printInfo('Uploading jingle to test WITH audio filter...');
        const fs = require('fs');
        const testAudio = '/tmp/test_jingle_filter.wav';

        if (!fs.existsSync(testAudio)) {
            try {
                const { execSync } = require('child_process');
                execSync(`ffmpeg -f lavfi -i anullsrc=r=44100:cl=stereo -t 1 -f wav "${testAudio}" 2>/dev/null`, { stdio: 'ignore' });
            } catch (error) {
                this.printWarning('ffmpeg not available, skipping WITH audio filter test');
                return true; // Skip this part of the test
            }
        }

        if (fs.existsSync(testAudio)) {
            const uploadResponse = await this.uploadFile(`/station-voices/${sv1Id}/audio`, {}, testAudio, 'jingle');
            if (uploadResponse.status === 201) {
                this.printSuccess('Jingle uploaded for filter testing');

                // Test filter for station-voices WITH audio (filter[audio_url][ne]=)
                this.printInfo('Testing filter for station-voices with audio (filter[audio_url][ne]=)...');
                const withAudioResponse = await this.apiCall('GET', '/station-voices?filter%5Baudio_url%5D%5Bne%5D=');
                if (this.assertions.checkResponse(withAudioResponse, 200, 'Filter station-voices with audio')) {
                    const stationVoices = withAudioResponse.data.data || [];
                    // All returned station-voices should have non-empty audio_file
                    const allWithAudio = stationVoices.every(sv => sv.audio_file !== '');
                    // Our uploaded station-voice should be in the results
                    const containsOurSV = stationVoices.some(sv => String(sv.id) === String(sv1Id));

                    if (allWithAudio && containsOurSV) {
                        this.printSuccess(`Audio filter (with audio) works correctly (${stationVoices.length} station-voices with jingle, includes our station-voice)`);
                    } else if (!allWithAudio) {
                        const withoutAudio = stationVoices.filter(sv => sv.audio_file === '');
                        this.printError(`Audio filter returned ${withoutAudio.length} station-voices WITHOUT audio - filter not working`);
                        return false;
                    } else {
                        this.printWarning('Our station-voice not in results, but filter seems to work');
                    }
                } else {
                    return false;
                }

                // Verify audio_file field contains the filename after upload
                this.printInfo('Verifying audio_file field after jingle upload...');
                const verifyResponse = await this.apiCall('GET', `/station-voices/${sv1Id}`);
                if (this.assertions.checkResponse(verifyResponse, 200, 'Verify audio_file after upload')) {
                    const sv = verifyResponse.data;
                    if (sv.audio_file && sv.audio_file !== '') {
                        this.printSuccess(`audio_file field contains filename: ${sv.audio_file}`);
                    } else {
                        this.printError('audio_file field is empty after jingle upload');
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                this.printWarning(`Jingle upload failed (HTTP: ${uploadResponse.status}), skipping WITH audio filter test`);
            }
        }

        return true;
    }

    /**
     * Tests Modern Query Parameter System features for station-voices endpoint.
     */
    async testModernQueryParameters() {
        this.printSection('Testing Modern Query Parameters');
        
        // Create test data with varied mix points and names for comprehensive testing
        this.printInfo('Creating test data for query parameter testing...');
        
        const testStations = [
            'Alpha Radio Station',
            'Beta FM Network', 
            'Gamma Broadcasting',
            'Delta News Radio',
            'Echo Station Network'
        ];
        
        const testVoices = [
            'John Announcer',
            'Sarah Newsreader',
            'Mike Broadcasting Voice',
            'Lisa Radio Host',
            'Tom News Voice'
        ];
        
        const stationIds = [];
        const voiceIds = [];
        const createdStationVoices = [];
        
        // Create stations
        for (const stationName of testStations) {
            const stationId = await this.createStation(stationName);
            if (stationId) {
                stationIds.push(stationId);
            }
        }
        
        // Create voices
        for (const voiceName of testVoices) {
            const voiceId = await this.createVoice(voiceName);
            if (voiceId) {
                voiceIds.push(voiceId);
            }
        }
        
        if (stationIds.length < 5 || voiceIds.length < 5) {
            this.printError('Failed to create sufficient test data for query testing');
            return false;
        }
        
        // Create station-voice relationships with varying mix points
        const mixPoints = [1.0, 2.5, 3.0, 1.5, 2.0];
        for (let i = 0; i < 5; i++) {
            const response = await this.apiCall('POST', '/station-voices', this.createStationVoiceData({
                station_id: parseInt(stationIds[i]),
                voice_id: parseInt(voiceIds[i]),
                mix_point: mixPoints[i]
            }));
            
            if (response.status === 201) {
                const svId = this.parseJsonField(response.data, 'id');
                if (svId) {
                    this.createdStationVoiceIds.push(svId);
                    createdStationVoices.push(svId);
                }
            }
        }
        
        if (createdStationVoices.length < 5) {
            this.printError('Failed to create sufficient station-voice relationships');
            return false;
        }
        
        // Test 1: Search functionality across station and voice names
        this.printInfo('Testing search parameter...');
        const searchResponse = await this.apiCall('GET', '/station-voices?search=Radio');
        if (this.assertions.checkResponse(searchResponse, 200, 'Search station-voices')) {
            const results = searchResponse.data.data || [];
            this.printInfo(`Search for "Radio" returned ${results.length} relationships`);
            // Check if search works on joined fields
            const radioMatches = results.filter(sv => 
                (sv.station_name && sv.station_name.includes('Radio')) ||
                (sv.voice_name && sv.voice_name.includes('Radio'))
            );
            if (radioMatches.length > 0) {
                this.printSuccess(`Search found ${radioMatches.length} relationships with "Radio" in station/voice names`);
            }
        }
        
        // Test 2: Modern filter syntax for station_id
        this.printInfo('Testing modern filter syntax for station_id...');
        const filterStationResponse = await this.apiCall('GET', `/station-voices?filter[station_id]=${stationIds[0]}`);
        if (this.assertions.checkResponse(filterStationResponse, 200, 'Filter by station_id')) {
            const results = filterStationResponse.data.data || [];
            const stationMatches = results.filter(sv => sv.station_id == stationIds[0]);
            this.printInfo(`Filter[station_id] returned ${results.length} relationships, ${stationMatches.length} matching station`);
            if (stationMatches.length > 0) {
                this.printSuccess('Modern filter syntax works for station_id');
            }
        }
        
        // Test 3: Modern filter syntax for voice_id
        this.printInfo('Testing modern filter syntax for voice_id...');
        const filterVoiceResponse = await this.apiCall('GET', `/station-voices?filter[voice_id]=${voiceIds[1]}`);
        if (this.assertions.checkResponse(filterVoiceResponse, 200, 'Filter by voice_id')) {
            const results = filterVoiceResponse.data.data || [];
            const voiceMatches = results.filter(sv => sv.voice_id == voiceIds[1]);
            this.printInfo(`Filter[voice_id] returned ${results.length} relationships, ${voiceMatches.length} matching voice`);
            if (voiceMatches.length > 0) {
                this.printSuccess('Modern filter syntax works for voice_id');
            }
        }
        
        // Test 4: Filter on joined station_name field
        this.printInfo('Testing filter on joined station_name field...');
        const filterStationNameResponse = await this.apiCall('GET', '/station-voices?filter[station_name]=Alpha Radio Station');
        if (this.assertions.checkResponse(filterStationNameResponse, 200, 'Filter by station_name')) {
            const results = filterStationNameResponse.data.data || [];
            this.printInfo(`Filter[station_name] returned ${results.length} relationships`);
            if (results.length > 0) {
                this.printSuccess('Filter on joined station_name field works');
            }
        }
        
        // Test 5: Filter on joined voice_name field
        this.printInfo('Testing filter on joined voice_name field...');
        const filterVoiceNameResponse = await this.apiCall('GET', '/station-voices?filter[voice_name]=John Announcer');
        if (this.assertions.checkResponse(filterVoiceNameResponse, 200, 'Filter by voice_name')) {
            const results = filterVoiceNameResponse.data.data || [];
            this.printInfo(`Filter[voice_name] returned ${results.length} relationships`);
            if (results.length > 0) {
                this.printSuccess('Filter on joined voice_name field works');
            }
        }
        
        // Test 6: Filter with 'in' operator for multiple station IDs
        this.printInfo('Testing filter with in operator for station IDs...');
        const inResponse = await this.apiCall('GET', `/station-voices?filter[station_id][in]=${stationIds.slice(0, 3).join(',')}`);
        if (this.assertions.checkResponse(inResponse, 200, 'Filter with in operator')) {
            const results = inResponse.data.data || [];
            const inMatches = results.filter(sv => stationIds.slice(0, 3).includes(sv.station_id));
            this.printInfo(`Filter[station_id][in] returned ${results.length} relationships, ${inMatches.length} matching station IDs`);
            if (inMatches.length > 0) {
                this.printSuccess('Filter with in operator works for station IDs');
            }
        }
        
        // Test 7: Filter mix_point with gte operator
        this.printInfo('Testing filter mix_point with gte operator...');
        const mixPointGteResponse = await this.apiCall('GET', '/station-voices?filter[mix_point][gte]=2.0');
        if (this.assertions.checkResponse(mixPointGteResponse, 200, 'Filter mix_point gte')) {
            const results = mixPointGteResponse.data.data || [];
            const gteMatches = results.filter(sv => parseFloat(sv.mix_point) >= 2.0);
            this.printInfo(`Filter[mix_point][gte] returned ${results.length} relationships, ${gteMatches.length} with mix_point >= 2.0`);
            if (gteMatches.length > 0) {
                this.printSuccess('Filter with gte operator works for mix_point');
            }
        }
        
        // Test 8: Filter mix_point with lte operator
        this.printInfo('Testing filter mix_point with lte operator...');
        const mixPointLteResponse = await this.apiCall('GET', '/station-voices?filter[mix_point][lte]=2.0');
        if (this.assertions.checkResponse(mixPointLteResponse, 200, 'Filter mix_point lte')) {
            const results = mixPointLteResponse.data.data || [];
            const lteMatches = results.filter(sv => parseFloat(sv.mix_point) <= 2.0);
            this.printInfo(`Filter[mix_point][lte] returned ${results.length} relationships, ${lteMatches.length} with mix_point <= 2.0`);
            if (lteMatches.length > 0) {
                this.printSuccess('Filter with lte operator works for mix_point');
            }
        }
        
        // Test 9: Filter mix_point with between operator
        this.printInfo('Testing filter mix_point with between operator...');
        const betweenResponse = await this.apiCall('GET', '/station-voices?filter[mix_point][between]=1.5,2.5');
        if (this.assertions.checkResponse(betweenResponse, 200, 'Filter mix_point between')) {
            const results = betweenResponse.data.data || [];
            const betweenMatches = results.filter(sv => {
                const mp = parseFloat(sv.mix_point);
                return mp >= 1.5 && mp <= 2.5;
            });
            this.printInfo(`Filter[mix_point][between] returned ${results.length} relationships, ${betweenMatches.length} with mix_point 1.5-2.5`);
            if (betweenMatches.length > 0) {
                this.printSuccess('Filter with between operator works for mix_point');
            }
        }
        
        // Test 10: Modern sort syntax - ascending by station_name
        this.printInfo('Testing sort by station_name ascending...');
        const sortAscResponse = await this.apiCall('GET', '/station-voices?sort=station_name');
        if (this.assertions.checkResponse(sortAscResponse, 200, 'Sort station_name asc')) {
            const results = sortAscResponse.data.data || [];
            if (results.length > 1) {
                const isSorted = results.every((sv, i) => 
                    i === 0 || !sv.station_name || !results[i-1].station_name ||
                    sv.station_name >= results[i-1].station_name
                );
                if (isSorted) {
                    this.printSuccess('Station-voices correctly sorted by station_name ascending');
                } else {
                    this.printWarning('Station-voices may not be sorted correctly by station_name');
                }
            }
        }
        
        // Test 11: Modern sort syntax - descending by mix_point
        this.printInfo('Testing sort by mix_point descending...');
        const sortDescResponse = await this.apiCall('GET', '/station-voices?sort=-mix_point');
        if (this.assertions.checkResponse(sortDescResponse, 200, 'Sort mix_point desc')) {
            const results = sortDescResponse.data.data || [];
            if (results.length > 1) {
                const isSorted = results.every((sv, i) => 
                    i === 0 || parseFloat(sv.mix_point) <= parseFloat(results[i-1].mix_point)
                );
                if (isSorted) {
                    this.printSuccess('Station-voices correctly sorted by mix_point descending');
                } else {
                    this.printWarning('Station-voices may not be sorted correctly by mix_point');
                }
            }
        }
        
        // Test 12: Multiple sort fields
        this.printInfo('Testing multiple sort fields...');
        const multiSortResponse = await this.apiCall('GET', '/station-voices?sort=station_name:asc,mix_point:desc');
        if (this.assertions.checkResponse(multiSortResponse, 200, 'Multiple sort fields')) {
            this.printSuccess('Multiple sort fields accepted');
        }
        
        // Test 13: Field selection
        this.printInfo('Testing field selection...');
        const fieldsResponse = await this.apiCall('GET', '/station-voices?fields=id,station_name,voice_name,mix_point');
        if (this.assertions.checkResponse(fieldsResponse, 200, 'Field selection')) {
            const results = fieldsResponse.data.data || [];
            if (results.length > 0) {
                const firstRelation = results[0];
                const hasSelectedFields = 
                    firstRelation.hasOwnProperty('id') && 
                    firstRelation.hasOwnProperty('mix_point');
                    
                const hasJoinedFields =
                    firstRelation.hasOwnProperty('station_name') ||
                    firstRelation.hasOwnProperty('voice_name');
                    
                if (hasSelectedFields) {
                    this.printSuccess('Field selection returned core fields');
                }
                
                if (hasJoinedFields) {
                    this.printSuccess('Field selection includes joined fields');
                }
                
                this.printInfo(`Fields in response: ${Object.keys(firstRelation).join(', ')}`);
            }
        }
        
        // Test 14: Complex combined query
        this.printInfo('Testing complex combined query...');
        const complexResponse = await this.apiCall('GET', 
            `/station-voices?search=Radio&filter[mix_point][gte]=1.5&sort=-mix_point&fields=id,station_name,voice_name,mix_point&limit=10`);
        if (this.assertions.checkResponse(complexResponse, 200, 'Complex combined query')) {
            this.printSuccess('Complex query with multiple parameters accepted');
            const results = complexResponse.data.data || [];
            this.printInfo(`Complex query returned ${results.length} results`);
        }
        
        // Test 15: Pagination with limit and offset
        this.printInfo('Testing pagination with limit and offset...');
        const paginationResponse = await this.apiCall('GET', '/station-voices?limit=2&offset=1');
        if (this.assertions.checkResponse(paginationResponse, 200, 'Pagination')) {
            const results = paginationResponse.data.data || [];
            if (results.length <= 2) {
                this.printSuccess(`Pagination limit working (returned ${results.length} relationships)`);
            } else {
                this.printWarning(`Pagination limit may not be working (returned ${results.length} relationships)`);
            }
        }
        
        return true;
    }
    
    /**
     * Test updating station-voice
     */
    async testUpdateStationVoice() {
        this.printSection('Testing Station-Voice Update');
        
        // Create test data
        this.printInfo('Creating test data for update...');
        const stationId = await this.createStation('Update Test Station');
        const voiceId = await this.createVoice('Update Test Voice');
        
        // Create a station-voice relationship
        const response = await this.apiCall('POST', '/station-voices', this.createStationVoiceData({
            station_id: parseInt(stationId),
            voice_id: parseInt(voiceId),
            mix_point: 1.0
        }));

        const svId = this.parseJsonField(response.data, 'id');
        if (!svId) {
            this.printError('Failed to create station-voice for update test');
            return false;
        }

        // Test updating mix_point
        this.printInfo('Updating station-voice mix_point...');
        const updateData = this.createStationVoiceData({ mix_point: 3.5 });
        const updateResponse = await this.apiCall('PUT', `/station-voices/${svId}`, updateData);
        
        if (this.assertions.checkResponse(updateResponse, 200, 'Update station-voice')) {
            this.printSuccess('Station-voice updated successfully');
            
            // Verify the update
            const getResponse = await this.apiCall('GET', `/station-voices/${svId}`);
            const mixPoint = this.parseJsonField(getResponse.data, 'mix_point');
            
            if (parseFloat(mixPoint) === 3.5) {
                this.printSuccess('Mix point updated correctly');
            } else {
                this.printError(`Mix point not updated correctly (got: ${mixPoint})`);
                return false;
            }
        } else {
            return false;
        }
        
        // Test updating non-existent station-voice
        this.printInfo('Testing update of non-existent station-voice...');
        const nonExistentData = this.createStationVoiceData({ mix_point: 5.0 });
        const nonExistentResponse = await this.apiCall('PUT', '/station-voices/99999', nonExistentData);
        
        if (nonExistentResponse.status === 404) {
            this.printSuccess('Non-existent station-voice update correctly rejected');
        } else {
            this.printError(`Non-existent station-voice update not rejected (HTTP: ${nonExistentResponse.status})`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test deleting station-voice
     */
    async testDeleteStationVoice() {
        this.printSection('Testing Station-Voice Deletion');
        
        // Create test data
        this.printInfo('Creating test data for deletion...');
        const stationId = await this.createStation('Delete Test Station');
        const voiceId = await this.createVoice('Delete Test Voice');
        
        // Create a station-voice relationship
        const response = await this.apiCall('POST', '/station-voices', this.createStationVoiceData({
            station_id: parseInt(stationId),
            voice_id: parseInt(voiceId),
            mix_point: 2.0
        }));
        
        const svId = this.parseJsonField(response.data, 'id');
        if (!svId) {
            this.printError('Failed to create station-voice for deletion test');
            return false;
        }
        
        // Test deleting the station-voice
        this.printInfo('Deleting station-voice...');
        const deleteResponse = await this.apiCall('DELETE', `/station-voices/${svId}`);
        
        if (this.assertions.checkResponse(deleteResponse, 204, 'Delete station-voice')) {
            this.printSuccess('Station-voice deleted successfully');
            
            // Verify it's deleted
            const getResponse = await this.apiCall('GET', `/station-voices/${svId}`);
            
            if (getResponse.status === 404) {
                this.printSuccess('Deleted station-voice correctly returns 404');
            } else {
                this.printError(`Deleted station-voice still accessible (HTTP: ${getResponse.status})`);
                return false;
            }
        } else {
            return false;
        }
        
        // Test deleting non-existent station-voice
        this.printInfo('Testing deletion of non-existent station-voice...');
        const nonExistentResponse = await this.apiCall('DELETE', '/station-voices/99999');
        
        if (nonExistentResponse.status === 404) {
            this.printSuccess('Non-existent station-voice deletion correctly returns 404');
        } else {
            this.printError(`Non-existent station-voice deletion returned unexpected code: ${nonExistentResponse.status}`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test jingle file upload functionality
     */
    async testJingleUpload() {
        this.printSection('Testing Jingle Upload');
        
        // This is a placeholder for jingle upload testing
        // In a real implementation, you would test multipart file uploads
        this.printInfo('Jingle upload tests would be implemented here');
        this.printSuccess('Jingle upload test placeholder completed');
        
        return true;
    }
    
    /**
     * Setup function
     */
    async setup() {
        this.printInfo('Setting up station-voice tests...');
        await this.restoreAdminSession();
        return true;
    }
    
    /**
     * Cleanup function
     */
    async cleanup() {
        this.printInfo('Cleaning up station-voice tests...');
        
        // Clean up in reverse order: station-voices, then voices, then stations
        for (const svId of this.createdStationVoiceIds) {
            try {
                await this.apiCall('DELETE', `/station-voices/${svId}`);
                this.printInfo(`Cleaned up station-voice: ${svId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        for (const voiceId of this.createdVoiceIds) {
            try {
                await this.apiCall('DELETE', `/voices/${voiceId}`);
                this.printInfo(`Cleaned up voice: ${voiceId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
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
        this.printHeader('Station-Voice Tests');
        
        await this.setup();
        
        const tests = [
            'testCreateStationVoice',
            'testCreateStationVoiceWithAudio',
            'testListStationVoices',
            'testAudioFieldsAndFiltering',
            'testModernQueryParameters',
            'testUpdateStationVoice',
            'testDeleteStationVoice',
            'testJingleUpload'
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
            this.printSuccess('All station-voice tests passed!');
            return true;
        } else {
            this.printError(`${failed} station-voice tests failed`);
            return false;
        }
    }
}

module.exports = StationVoicesTests;
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
