/**
 * Babbel Stations Tests - Node.js
 * Test station management functionality
 */

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

class StationsTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);
        
        // Global variables for cleanup
        this.createdStationIds = [];
    }
    
    /**
     * Test creating stations
     */
    async testCreateStations() {
        this.printSection('Testing Station Creation');
        
        const testStations = [
            { name: 'CRUD Test FM', max_stories_per_block: 5, pause_seconds: 2.0 },
            { name: 'Another Test Station', max_stories_per_block: 3, pause_seconds: 1.5 },
            { name: 'Validation Station', max_stories_per_block: 10, pause_seconds: 3.0 }
        ];
        
        for (const stationData of testStations) {
            const name = stationData.name;
            
            this.printInfo(`Creating station: ${name}`);
            
            const response = await this.apiCall('POST', '/stations', stationData);
            
            const stationId = this.assertions.checkResponse(response, 201, `Create station ${name}`);
            if (stationId) {
                this.createdStationIds.push(stationId);
                this.printSuccess(`Created station: ${name} (ID: ${stationId})`);
                
                // The API returns just {id, message}, so fetch the full station to verify
                this.printInfo('Fetching created station to verify data...');
                const verifyResponse = await this.apiCall('GET', `/stations/${stationId}`);
                
                if (verifyResponse.status === 200) {
                    const stationData = verifyResponse.data;
                    this.assertions.assertJsonFieldEquals(stationData, 'name', name, 'Station name');
                    this.assertions.assertJsonFieldEquals(stationData, 'id', stationId, 'Station ID');
                    this.assertions.assertJsonField(stationData, 'created_at', 'Created timestamp');
                    this.assertions.assertJsonField(stationData, 'updated_at', 'Updated timestamp');
                } else {
                    this.printWarning('Could not verify created station data');
                }
            } else {
                this.printError(`Failed to create station: ${name}`);
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Test reading stations
     */
    async testReadStations() {
        this.printSection('Testing Station Reading');
        
        // Test listing all stations
        this.printInfo('Testing list all stations...');
        const response = await this.apiCall('GET', '/stations');
        
        if (this.assertions.checkResponse(response, 200, 'List all stations')) {
            const body = response.data;
            this.assertions.assertJsonField(body, 'data', 'Stations data array');
            
            const stationCount = body.data ? body.data.length : 0;
            this.printSuccess(`Listed stations (count: ${stationCount})`);
            
            // Verify structure of first station
            if (body.data && body.data.length > 0) {
                const firstStation = body.data[0];
                this.assertions.assertJsonField(firstStation, 'id', 'First station ID');
                this.assertions.assertJsonField(firstStation, 'name', 'First station name');
                this.assertions.assertJsonField(firstStation, 'max_stories_per_block', 'First station max stories');
                this.assertions.assertJsonField(firstStation, 'pause_seconds', 'First station pause seconds');
            }
        } else {
            return false;
        }
        
        // Test getting individual station
        if (this.createdStationIds.length > 0) {
            const stationId = this.createdStationIds[0];
            this.printInfo(`Testing get individual station (ID: ${stationId})...`);
            
            const response = await this.apiCall('GET', `/stations/${stationId}`);
            
            if (this.assertions.checkResponse(response, 200, 'Get individual station')) {
                const body = response.data;
                this.assertions.assertJsonFieldEquals(body, 'id', stationId, 'Station ID matches');
                this.assertions.assertJsonField(body, 'name', 'Station name');
                this.printSuccess('Retrieved individual station');
            } else {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Test updating stations
     */
    async testUpdateStations() {
        this.printSection('Testing Station Updates');
        
        if (this.createdStationIds.length === 0) {
            this.printError('No stations available for update testing');
            return false;
        }
        
        const stationId = this.createdStationIds[0];
        this.printInfo(`Using station ID: ${stationId} for update tests`);
        
        // Test full update (PUT)
        this.printInfo('Testing station full update (PUT)...');
        const updateData = {
            name: 'Updated Test Station',
            max_stories_per_block: 7,
            pause_seconds: 2.5
        };
        
        const response = await this.apiCall('PUT', `/stations/${stationId}`, updateData);
        
        if (this.assertions.checkResponse(response, 200, 'Update station (PUT)')) {
            // The API returns just {message}, so fetch the station to verify update
            this.printInfo('Fetching updated station to verify changes...');
            const verifyResponse = await this.apiCall('GET', `/stations/${stationId}`);
            
            if (verifyResponse.status === 200) {
                const body = verifyResponse.data;
                this.assertions.assertJsonFieldEquals(body, 'name', 'Updated Test Station', 'Updated name');
                this.assertions.assertJsonFieldEquals(body, 'max_stories_per_block', '7', 'Updated max stories');
                this.assertions.assertJsonFieldEquals(body, 'pause_seconds', '2.5', 'Updated pause seconds');
                this.printSuccess('Station updated successfully');
            } else {
                this.printWarning('Could not verify updated station data');
            }
        } else {
            return false;
        }
        
        // Note: Stations API doesn't have PATCH endpoint, only PUT
        // Test another full update to ensure it still works
        this.printInfo('Testing station second update (PUT)...');
        const patchData = {
            name: 'Second Update Station',
            max_stories_per_block: 8,
            pause_seconds: 3.0
        };
        
        const response2 = await this.apiCall('PUT', `/stations/${stationId}`, patchData);
        
        if (this.assertions.checkResponse(response2, 200, 'Second update station (PUT)')) {
            // The API returns just {message}, so fetch the station to verify patch
            this.printInfo('Fetching patched station to verify changes...');
            const verifyResponse = await this.apiCall('GET', `/stations/${stationId}`);
            
            if (verifyResponse.status === 200) {
                const body = verifyResponse.data;
                this.assertions.assertJsonFieldEquals(body, 'name', 'Second Update Station', 'Updated name');
                this.assertions.assertJsonFieldEquals(body, 'max_stories_per_block', '8', 'Updated max stories');
                this.assertions.assertJsonFieldEquals(body, 'pause_seconds', '3', 'Updated pause seconds');
                this.printSuccess('Station patched successfully');
            } else {
                this.printWarning('Could not verify patched station data');
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test station validation
     */
    async testStationValidation() {
        this.printSection('Testing Station Validation');
        
        const validationTests = [
            { data: {}, description: 'Missing required fields' },
            { data: { name: '' }, description: 'Empty name' },
            { data: { name: 'Test', max_stories_per_block: -1 }, description: 'Negative max stories' },
            { data: { name: 'Test', max_stories_per_block: 0 }, description: 'Zero max stories' },
            { data: { name: 'Test', max_stories_per_block: 5, pause_seconds: -1 }, description: 'Negative pause seconds' },
            { data: { name: 'Test', max_stories_per_block: 5, pause_seconds: 'invalid' }, description: 'Invalid pause seconds type' }
        ];
        
        for (const testCase of validationTests) {
            const { data, description } = testCase;
            
            this.printInfo(`Testing validation: ${description}`);
            
            const response = await this.apiCall('POST', '/stations', data);
            
            if (this.assertions.assertHttpError(response.status, `Validation: ${description}`)) {
                this.printSuccess(`Validation correctly rejected: ${description}`);
            } else {
                this.printError(`Validation should have rejected: ${description}`);
            }
        }
        
        return true;
    }
    
    /**
     * Test station deletion
     */
    async testDeleteStations() {
        this.printSection('Testing Station Deletion');
        
        if (this.createdStationIds.length === 0) {
            this.printError('No stations available for deletion testing');
            return false;
        }
        
        // Delete the last created station
        this.printInfo(`Available station IDs for deletion: [${this.createdStationIds.join(', ')}]`);
        const stationId = this.createdStationIds[this.createdStationIds.length - 1];
        
        if (!stationId) {
            this.printError('No valid station ID for deletion test');
            return false;
        }
        
        this.printInfo(`Testing station deletion (ID: ${stationId})...`);
        
        const response = await this.apiCall('DELETE', `/stations/${stationId}`);
        
        if (this.assertions.checkResponse(response, 204, 'Delete station')) {
            this.printSuccess('Station deleted successfully');
            
            // Verify station is no longer accessible
            this.printInfo('Verifying station is deleted...');
            const verifyResponse = await this.apiCall('GET', `/stations/${stationId}`);
            
            if (this.assertions.assertStatusCode(verifyResponse.status, 404, 'Get deleted station')) {
                this.printSuccess('Deleted station correctly returns 404');
            } else {
                this.printError('Deleted station still accessible');
                return false;
            }
            
            // Remove from our tracking array
            this.createdStationIds = this.createdStationIds.slice(0, -1);
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test station duplicate names
     */
    async testDuplicateNames() {
        this.printSection('Testing Duplicate Station Names');
        
        const stationName = 'Unique Test Station';
        
        // Create first station
        this.printInfo(`Creating first station with name: ${stationName}`);
        const response = await this.apiCall('POST', '/stations', {
            name: stationName,
            max_stories_per_block: 5,
            pause_seconds: 2.0
        });
        
        const firstId = this.assertions.checkResponse(response, 201, 'Create first station');
        if (firstId) {
            this.createdStationIds.push(firstId);
            this.printSuccess(`Created first station (ID: ${firstId})`);
        } else {
            this.printError('Failed to create first station');
            return false;
        }
        
        // Try to create second station with same name
        this.printInfo('Attempting to create duplicate station...');
        const response2 = await this.apiCall('POST', '/stations', {
            name: stationName,
            max_stories_per_block: 3,
            pause_seconds: 1.5
        });
        
        if (this.assertions.assertHttpError(response2.status, 'Duplicate station name')) {
            this.printSuccess('Duplicate station name correctly rejected');
        } else {
            this.printError('Duplicate station name unexpectedly accepted');
            return false;
        }
        
        return true;
    }
    
    /**
     * Restore admin session (compatibility helper)
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
     * Setup function
     */
    async setup() {
        this.printInfo('Setting up station tests...');
        // Ensure we're logged in as admin
        if (!(await this.restoreAdminSession())) {
            this.printError('Could not establish admin session');
            return false;
        }
        return true;
    }
    
    /**
     * Cleanup function
     */
    async cleanup() {
        this.printInfo('Cleaning up station tests...');
        
        // Delete all created stations
        for (const stationId of this.createdStationIds) {
            if (stationId) {
                try {
                    await this.apiCall('DELETE', `/stations/${stationId}`);
                    this.printInfo(`Cleaned up station: ${stationId}`);
                } catch (error) {
                    // Ignore cleanup errors
                }
            }
        }
        
        this.createdStationIds = [];
        return true;
    }
    
    /**
     * Main test runner
     */
    async run() {
        this.printHeader('Station Tests');
        
        await this.setup();
        
        const tests = [
            'testCreateStations',
            'testReadStations',
            'testUpdateStations',
            'testStationValidation',
            'testDuplicateNames',
            'testDeleteStations'
        ];
        
        let failed = 0;
        
        for (const test of tests) {
            if (await this.runTest(this[test], test)) {
                this.printSuccess(`✓ ${test} passed`);
            } else {
                this.printError(`✗ ${test} failed`);
                failed++;
            }
            console.error(''); // Add spacing between tests
        }
        
        await this.cleanup();
        
        this.printSummary();
        
        if (failed === 0) {
            this.printSuccess('All station tests passed!');
            return true;
        } else {
            this.printError(`${failed} station tests failed`);
            return false;
        }
    }
}

module.exports = StationsTests;
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
