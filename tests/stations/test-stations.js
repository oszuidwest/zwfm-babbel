// Babbel stations tests.
// Tests station management functionality including CRUD operations and validation.

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

class StationsTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);
        
        // Track created resources for cleanup.
        this.createdStationIds = [];
    }
    
    /**
     * Tests station creation with multiple test cases.
     */
    async testCreateStations() {
        this.printSection('Testing Station Creation');
        
        // Use timestamp to ensure unique names for each test run
        const timestamp = Date.now();
        const testStations = [
            { name: `CRUD Test FM ${timestamp}`, max_stories_per_block: 5, pause_seconds: 2.0 },
            { name: `Another Test Station ${timestamp}`, max_stories_per_block: 3, pause_seconds: 1.5 },
            { name: `Validation Station ${timestamp}`, max_stories_per_block: 10, pause_seconds: 3.0 }
        ];
        
        for (const stationData of testStations) {
            const name = stationData.name;
            
            this.printInfo(`Creating station: ${name}`);
            
            const response = await this.apiCall('POST', '/stations', stationData);
            
            const stationId = this.assertions.checkResponse(response, 201, `Create station ${name}`);
            if (stationId) {
                this.createdStationIds.push(stationId);
                this.printSuccess(`Created station: ${name} (ID: ${stationId})`);
                
                // The API returns basic response, so fetch full station data to verify creation.
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
     * Tests station retrieval operations including listing and individual access.
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
            
            // Verify response structure of first station.
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
     * Tests Modern Query Parameter System features for stations endpoint.
     */
    async testModernQueryParameters() {
        this.printSection('Testing Modern Query Parameters');
        
        // First create some test stations with varied data for filtering
        this.printInfo('Creating test stations for query testing...');
        const queryTimestamp = Date.now();
        const testStations = [
            { name: `Alpha Radio ${queryTimestamp}`, max_stories_per_block: 3, pause_seconds: 1.0 },
            { name: `Beta FM ${queryTimestamp}`, max_stories_per_block: 5, pause_seconds: 2.0 },
            { name: `Gamma Station ${queryTimestamp}`, max_stories_per_block: 7, pause_seconds: 3.0 },
            { name: `Delta Broadcasting ${queryTimestamp}`, max_stories_per_block: 10, pause_seconds: 2.5 },
            { name: `Echo Radio Network ${queryTimestamp}`, max_stories_per_block: 5, pause_seconds: 1.5 }
        ];
        
        const queryTestIds = [];
        for (const station of testStations) {
            const response = await this.apiCall('POST', '/stations', station);
            if (response.status === 201) {
                const id = this.parseJsonField(response.data, 'id');
                if (id) {
                    queryTestIds.push(id);
                    this.createdStationIds.push(id);
                }
            }
        }
        
        if (queryTestIds.length < 5) {
            this.printError('Failed to create test stations for query testing');
            return false;
        }
        
        // Test 1: Search functionality
        this.printInfo('Testing search parameter...');
        const searchResponse = await this.apiCall('GET', '/stations?search=Radio');
        if (this.assertions.checkResponse(searchResponse, 200, 'Search stations')) {
            const results = searchResponse.data.data || [];
            const radioStations = results.filter(s => s.name && s.name.includes('Radio'));
            if (radioStations.length > 0) {
                this.printSuccess(`Search found ${radioStations.length} stations with "Radio" in name`);
            } else {
                this.printWarning('Search did not filter results as expected');
            }
        }
        
        // Test 2: Filtering with exact match
        this.printInfo('Testing filter with exact match...');
        const filterExactResponse = await this.apiCall('GET', '/stations?filter[max_stories_per_block]=5');
        if (this.assertions.checkResponse(filterExactResponse, 200, 'Filter exact match')) {
            const results = filterExactResponse.data.data || [];
            const exactMatches = results.filter(s => s.max_stories_per_block === 5);
            this.printInfo(`Filter returned ${results.length} stations, ${exactMatches.length} with exact max_stories=5`);
        }
        
        // Test 3: Filtering with operators (gte, lte)
        this.printInfo('Testing filter with gte operator...');
        const filterGteResponse = await this.apiCall('GET', '/stations?filter[max_stories_per_block][gte]=7');
        if (this.assertions.checkResponse(filterGteResponse, 200, 'Filter with gte')) {
            const results = filterGteResponse.data.data || [];
            const gteMatches = results.filter(s => s.max_stories_per_block >= 7);
            this.printInfo(`Filter[gte] returned ${results.length} stations, ${gteMatches.length} with max_stories>=7`);
        }
        
        // Test 4: Multiple filters combined
        this.printInfo('Testing multiple filters...');
        const multiFilterResponse = await this.apiCall('GET', '/stations?filter[max_stories_per_block][gte]=5&filter[pause_seconds][lte]=2.0');
        if (this.assertions.checkResponse(multiFilterResponse, 200, 'Multiple filters')) {
            const results = multiFilterResponse.data.data || [];
            this.printInfo(`Multiple filters returned ${results.length} stations`);
        }
        
        // Test 5: Sorting (ascending)
        this.printInfo('Testing sort ascending by name...');
        const sortAscResponse = await this.apiCall('GET', '/stations?sort=name');
        if (this.assertions.checkResponse(sortAscResponse, 200, 'Sort ascending')) {
            const results = sortAscResponse.data.data || [];
            if (results.length > 1) {
                const isSorted = results.every((s, i) => 
                    i === 0 || s.name >= results[i-1].name
                );
                if (isSorted) {
                    this.printSuccess('Stations correctly sorted by name ascending');
                } else {
                    this.printWarning('Stations may not be sorted correctly');
                }
            }
        }
        
        // Test 6: Sorting (descending with minus sign)
        this.printInfo('Testing sort descending by max_stories_per_block...');
        const sortDescResponse = await this.apiCall('GET', '/stations?sort=-max_stories_per_block');
        if (this.assertions.checkResponse(sortDescResponse, 200, 'Sort descending')) {
            const results = sortDescResponse.data.data || [];
            if (results.length > 1) {
                const isSorted = results.every((s, i) => 
                    i === 0 || s.max_stories_per_block <= results[i-1].max_stories_per_block
                );
                if (isSorted) {
                    this.printSuccess('Stations correctly sorted by max_stories descending');
                } else {
                    this.printWarning('Stations may not be sorted correctly');
                }
            }
        }
        
        // Test 7: Multiple sort fields
        this.printInfo('Testing multiple sort fields...');
        const multiSortResponse = await this.apiCall('GET', '/stations?sort=max_stories_per_block,-name');
        if (this.assertions.checkResponse(multiSortResponse, 200, 'Multiple sort fields')) {
            this.printSuccess('Multiple sort fields accepted');
        }
        
        // Test 8: Field selection
        this.printInfo('Testing field selection...');
        const fieldsResponse = await this.apiCall('GET', '/stations?fields=id,name');
        if (this.assertions.checkResponse(fieldsResponse, 200, 'Field selection')) {
            const results = fieldsResponse.data.data || [];
            if (results.length > 0) {
                const firstStation = results[0];
                const hasOnlySelectedFields = 
                    firstStation.hasOwnProperty('id') && 
                    firstStation.hasOwnProperty('name') &&
                    !firstStation.hasOwnProperty('max_stories_per_block') &&
                    !firstStation.hasOwnProperty('pause_seconds');
                    
                if (hasOnlySelectedFields) {
                    this.printSuccess('Field selection returned only requested fields');
                } else {
                    this.printInfo('Field selection may not be working as expected');
                    this.printInfo(`Fields in response: ${Object.keys(firstStation).join(', ')}`);
                }
            }
        }
        
        // Test 9: Pagination with limit and offset
        this.printInfo('Testing pagination with limit and offset...');
        const paginationResponse = await this.apiCall('GET', '/stations?limit=2&offset=1');
        if (this.assertions.checkResponse(paginationResponse, 200, 'Pagination')) {
            const results = paginationResponse.data.data || [];
            if (results.length <= 2) {
                this.printSuccess(`Pagination limit working (returned ${results.length} stations)`);
            } else {
                this.printWarning(`Pagination limit may not be working (returned ${results.length} stations)`);
            }
        }
        
        // Test 10: Complex combined query
        this.printInfo('Testing complex combined query...');
        const complexResponse = await this.apiCall('GET', '/stations?search=Station&filter[max_stories_per_block][gte]=5&sort=-pause_seconds&fields=id,name,pause_seconds&limit=10');
        if (this.assertions.checkResponse(complexResponse, 200, 'Complex combined query')) {
            this.printSuccess('Complex query with multiple parameters accepted');
            const results = complexResponse.data.data || [];
            this.printInfo(`Complex query returned ${results.length} results`);
        }
        
        // Test 11: Filter with 'in' operator
        this.printInfo('Testing filter with in operator...');
        const inResponse = await this.apiCall('GET', `/stations?filter[id][in]=${queryTestIds.slice(0, 3).join(',')}`);
        if (this.assertions.checkResponse(inResponse, 200, 'Filter with in operator')) {
            const results = inResponse.data.data || [];
            this.printInfo(`Filter[in] returned ${results.length} stations`);
        }
        
        // Test 12: Filter with 'between' operator
        this.printInfo('Testing filter with between operator...');
        const betweenResponse = await this.apiCall('GET', '/stations?filter[pause_seconds][between]=1.5,2.5');
        if (this.assertions.checkResponse(betweenResponse, 200, 'Filter with between operator')) {
            const results = betweenResponse.data.data || [];
            const betweenMatches = results.filter(s => s.pause_seconds >= 1.5 && s.pause_seconds <= 2.5);
            this.printInfo(`Filter[between] returned ${results.length} stations, ${betweenMatches.length} in range 1.5-2.5`);
        }
        
        return true;
    }
    
    /**
     * Tests station update operations with various data changes.
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
     * Tests station field validation and error handling.
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
     * Tests station deletion functionality.
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
     * Tests that duplicate station names are properly rejected.
     */
    async testDuplicateNames() {
        this.printSection('Testing Duplicate Station Names');
        
        const stationName = `Unique Test Station ${Date.now()}`;
        
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
     * Sets up station tests by ensuring admin session.
     * @returns {Promise<boolean>} True if setup succeeded.
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
     * Cleans up test stations and resources.
     * @returns {Promise<boolean>} True if cleanup succeeded.
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
     * Main test runner for station tests.
     * @returns {Promise<boolean>} True if all tests passed.
     */
    async run() {
        this.printHeader('Station Tests');
        
        await this.setup();
        
        const tests = [
            'testCreateStations',
            'testReadStations',
            'testModernQueryParameters',
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
            console.error(''); // Add visual spacing between tests.
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
