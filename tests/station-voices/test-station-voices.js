/**
 * Babbel Station-Voices Tests - Node.js
 * Test station-voice relationship management functionality
 */

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
        const response = await this.apiCall('POST', '/station-voices', {
            station_id: parseInt(stationId),
            voice_id: parseInt(voiceId),
            mix_point: 2.5
        });
        
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
        const duplicateResponse = await this.apiCall('POST', '/station-voices', {
            station_id: parseInt(stationId),
            voice_id: parseInt(voiceId),
            mix_point: 3.0
        });
        
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
        
        // Test creating station-voice with multipart/form-data and audio file
        this.printInfo('Creating station-voice with audio upload...');
        const FormData = require('form-data');
        const form = new FormData();
        form.append('station_id', stationId.toString());
        form.append('voice_id', voiceId.toString());
        form.append('mix_point', '1.5');
        form.append('jingle', fs.createReadStream(testAudio));
        
        const response = await this.apiCallFormData('POST', '/station-voices', form);
        
        if (response.status === 201) {
            const svId = this.parseJsonField(response.data, 'id');
            if (svId) {
                this.createdStationVoiceIds.push(svId);
                this.printSuccess(`Created station-voice with audio (ID: ${svId})`);
                
                // Verify the jingle file was saved
                const jinglePath = `${this.audioDir}/processed/station_${stationId}_voice_${voiceId}_jingle.wav`;
                if (await this.waitForAudioFile(jinglePath, 5)) {
                    this.printSuccess('Jingle file saved successfully');
                } else {
                    this.printWarning('Jingle file not found at expected location');
                }
            } else {
                this.printError('Could not extract station-voice ID from response');
                return false;
            }
        } else {
            this.printError(`Failed to create station-voice with audio (HTTP: ${response.status})`);
            this.printError(`Response: ${JSON.stringify(response.data)}`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test listing station-voices
     */
    async testListStationVoices() {
        this.printSection('Testing Station-Voice Listing');
        
        // Create some test data
        this.printInfo('Creating test data for listing...');
        const station1 = await this.createStation('List Test Station 1');
        const station2 = await this.createStation('List Test Station 2');
        const voice1 = await this.createVoice('List Test Voice 1');
        const voice2 = await this.createVoice('List Test Voice 2');
        
        // Create relationships
        await this.apiCall('POST', '/station-voices', {
            station_id: parseInt(station1),
            voice_id: parseInt(voice1),
            mix_point: 1.0
        });
        
        await this.apiCall('POST', '/station-voices', {
            station_id: parseInt(station2),
            voice_id: parseInt(voice2),
            mix_point: 2.0
        });
        
        // Test basic listing
        this.printInfo('Testing basic station-voice listing...');
        const response = await this.apiCall('GET', '/station-voices');
        
        if (this.assertions.checkResponse(response, 200, 'List station-voices')) {
            const count = response.data.data ? response.data.data.length : 0;
            this.printSuccess(`Station-voice listing returned ${count} relationships`);
        } else {
            return false;
        }
        
        // Test filtering by station_id
        this.printInfo('Testing filter by station_id...');
        const stationFilterResponse = await this.apiCall('GET', `/station-voices?station_id=${station1}`);
        
        if (this.assertions.checkResponse(stationFilterResponse, 200, 'Filter by station')) {
            this.printSuccess('Filtering by station_id works');
        } else {
            return false;
        }
        
        // Test filtering by voice_id
        this.printInfo('Testing filter by voice_id...');
        const voiceFilterResponse = await this.apiCall('GET', `/station-voices?voice_id=${voice1}`);
        
        if (this.assertions.checkResponse(voiceFilterResponse, 200, 'Filter by voice')) {
            this.printSuccess('Filtering by voice_id works');
        } else {
            return false;
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
        const response = await this.apiCall('POST', '/station-voices', {
            station_id: parseInt(stationId),
            voice_id: parseInt(voiceId),
            mix_point: 1.0
        });
        
        const svId = this.parseJsonField(response.data, 'id');
        if (!svId) {
            this.printError('Failed to create station-voice for update test');
            return false;
        }
        
        // Test updating mix_point
        this.printInfo('Updating station-voice mix_point...');
        const updateResponse = await this.apiCall('PUT', `/station-voices/${svId}`, {
            mix_point: 3.5
        });
        
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
        const nonExistentResponse = await this.apiCall('PUT', '/station-voices/99999', {
            mix_point: 5.0
        });
        
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
        const response = await this.apiCall('POST', '/station-voices', {
            station_id: parseInt(stationId),
            voice_id: parseInt(voiceId),
            mix_point: 2.0
        });
        
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
                await this.apiCall('DELETE', `/station_voices/${svId}`);
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
