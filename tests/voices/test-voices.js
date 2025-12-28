// Babbel voices tests.
// Tests voice management functionality including CRUD operations and story associations.

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

class VoicesTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);
        
        // Track created resources for cleanup.
        this.createdVoiceIds = [];
    }
    
    /**
     * Helper function to create a voice and track its ID
     */
    async createVoice(name) {
        // Add timestamp to ensure uniqueness
        const uniqueName = `${name}_${Date.now()}_${process.pid}`;
        const response = await this.apiCall('POST', '/voices', { name: uniqueName });
        
        if (response.status === 201) {
            // API returns {id: X, message: "..."} on creation
            const voiceId = this.parseJsonField(response.data, 'id');
            
            if (voiceId) {
                this.createdVoiceIds.push(voiceId);
                return { id: voiceId, name: uniqueName };
            }
        }
        
        return null;
    }
    
    /**
     * Test voice creation
     */
    async testVoiceCreation() {
        this.printSection('Testing Voice Creation');
        
        // Test creating a valid voice
        this.printInfo('Creating a new voice...');
        const voiceData = await this.createVoice('Test Voice 1');
        
        if (voiceData) {
            this.printSuccess(`Voice created successfully (ID: ${voiceData.id})`);
            
            // Verify the voice exists
            const response = await this.apiCall('GET', `/voices/${voiceData.id}`);
            if (this.assertions.checkResponse(response, 200, 'Get created voice')) {
                const body = response.data;
                const name = this.parseJsonField(body, 'name');
                
                // Check against the actual unique name we created
                if (name === voiceData.name) {
                    this.printSuccess('Voice data verified');
                } else {
                    this.printError(`Voice name mismatch: expected '${voiceData.name}', got '${name}'`);
                    return false;
                }
            } else {
                return false;
            }
        } else {
            this.printError('Failed to create voice');
            return false;
        }
        
        // Test creating voice with duplicate name (use the actual unique name)
        this.printInfo('Testing duplicate voice name...');
        const duplicateResponse = await this.apiCall('POST', '/voices', { name: voiceData.name });
        
        if (duplicateResponse.status === 409) {
            this.printSuccess('Duplicate voice correctly rejected (409 Conflict)');
        } else {
            this.printError(`Duplicate voice not rejected (HTTP: ${duplicateResponse.status})`);
            return false;
        }
        
        // Test invalid voice creation (missing name)
        this.printInfo('Testing voice creation without name...');
        const invalidResponse = await this.apiCall('POST', '/voices', {});
        
        if (invalidResponse.status === 422) {
            this.printSuccess('Invalid voice correctly rejected (422)');
        } else {
            this.printError(`Invalid voice not rejected (HTTP: ${invalidResponse.status})`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test basic voice listing
     */
    async testVoiceListing() {
        this.printSection('Testing Basic Voice Listing');
        
        // Create some test voices
        this.printInfo('Creating test voices for listing...');
        await this.createVoice('List Test Voice 1');
        await this.createVoice('List Test Voice 2');
        await this.createVoice('List Test Voice 3');
        
        // Test basic listing
        this.printInfo('Testing basic voice listing...');
        const response = await this.apiCall('GET', '/voices');
        
        if (this.assertions.checkResponse(response, 200, 'List voices')) {
            const body = response.data;
            
            // Check for data array
            if (body.data && Array.isArray(body.data)) {
                const count = body.data.length;
                this.printSuccess(`Voice listing returned ${count} voices`);
            } else {
                this.printError('Voice listing response missing data array');
                return false;
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Tests Modern Query Parameter System features for voices endpoint.
     */
    async testModernQueryParameters() {
        this.printSection('Testing Modern Query Parameters');
        
        // First create some test voices with varied data for filtering
        this.printInfo('Creating test voices for query testing...');
        const testVoices = [
            'Alpha Voice',
            'Beta Announcer', 
            'Gamma Newsreader',
            'Delta Broadcasting Voice',
            'Echo Radio Voice',
            'Foxtrot News Voice'
        ];
        
        const queryTestIds = [];
        for (const voiceName of testVoices) {
            const voiceData = await this.createVoice(voiceName);
            if (voiceData && voiceData.id) {
                queryTestIds.push(voiceData.id);
            }
        }
        
        if (queryTestIds.length < 6) {
            this.printError('Failed to create test voices for query testing');
            return false;
        }
        
        // Test 1: Search functionality
        this.printInfo('Testing search parameter...');
        const searchResponse = await this.apiCall('GET', '/voices?search=Voice');
        if (this.assertions.checkResponse(searchResponse, 200, 'Search voices')) {
            const results = searchResponse.data.data || [];
            const voiceMatches = results.filter(v => v.name && v.name.includes('Voice'));
            if (voiceMatches.length > 0) {
                this.printSuccess(`Search found ${voiceMatches.length} voices with "Voice" in name`);
            } else {
                this.printWarning('Search did not filter results as expected');
            }
        }
        
        // Test 2: Filtering with exact match
        this.printInfo('Testing filter with exact ID match...');
        const filterExactResponse = await this.apiCall('GET', `/voices?filter[id]=${queryTestIds[0]}`);
        if (this.assertions.checkResponse(filterExactResponse, 200, 'Filter exact ID match')) {
            const results = filterExactResponse.data.data || [];
            const exactMatches = results.filter(v => v.id == queryTestIds[0]);
            this.printInfo(`Filter returned ${results.length} voices, ${exactMatches.length} with exact ID match`);
            if (exactMatches.length === 1) {
                this.printSuccess('Filter by ID returned exactly one matching voice');
            } else {
                this.printWarning('Filter by ID did not return expected single result');
            }
        }
        
        // Test 3: Filtering with 'in' operator for multiple IDs
        this.printInfo('Testing filter with in operator...');
        const inResponse = await this.apiCall('GET', `/voices?filter[id][in]=${queryTestIds.slice(0, 3).join(',')}`);
        if (this.assertions.checkResponse(inResponse, 200, 'Filter with in operator')) {
            const results = inResponse.data.data || [];
            const inMatches = results.filter(v => queryTestIds.slice(0, 3).includes(v.id));
            this.printInfo(`Filter[in] returned ${results.length} voices, ${inMatches.length} matching the ID list`);
            if (inMatches.length === 3) {
                this.printSuccess('Filter with in operator returned all requested voices');
            } else {
                this.printInfo('Filter with in operator may not have returned all expected voices');
            }
        }
        
        // Test 4: Sorting (ascending by name)
        this.printInfo('Testing sort ascending by name...');
        const sortAscResponse = await this.apiCall('GET', '/voices?sort=name');
        if (this.assertions.checkResponse(sortAscResponse, 200, 'Sort ascending')) {
            const results = sortAscResponse.data.data || [];
            if (results.length > 1) {
                const isSorted = results.every((v, i) => 
                    i === 0 || (v.name && results[i-1].name && v.name >= results[i-1].name)
                );
                if (isSorted) {
                    this.printSuccess('Voices correctly sorted by name ascending');
                } else {
                    this.printWarning('Voices may not be sorted correctly');
                }
            }
        }
        
        // Test 5: Sorting (descending with minus sign)
        this.printInfo('Testing sort descending by name...');
        const sortDescResponse = await this.apiCall('GET', '/voices?sort=-name');
        if (this.assertions.checkResponse(sortDescResponse, 200, 'Sort descending')) {
            const results = sortDescResponse.data.data || [];
            if (results.length > 1) {
                const isSorted = results.every((v, i) => 
                    i === 0 || (v.name && results[i-1].name && v.name <= results[i-1].name)
                );
                if (isSorted) {
                    this.printSuccess('Voices correctly sorted by name descending');
                } else {
                    this.printWarning('Voices may not be sorted correctly');
                }
            }
        }
        
        // Test 6: Sorting by created_at descending (most recent first)
        this.printInfo('Testing sort by created_at descending...');
        const sortCreatedResponse = await this.apiCall('GET', '/voices?sort=-created_at');
        if (this.assertions.checkResponse(sortCreatedResponse, 200, 'Sort by created_at desc')) {
            this.printSuccess('Sort by created_at descending accepted');
        }
        
        // Test 7: Multiple sort fields
        this.printInfo('Testing multiple sort fields...');
        const multiSortResponse = await this.apiCall('GET', '/voices?sort=name,-created_at');
        if (this.assertions.checkResponse(multiSortResponse, 200, 'Multiple sort fields')) {
            this.printSuccess('Multiple sort fields accepted');
        }
        
        // Test 8: Field selection
        this.printInfo('Testing field selection...');
        const fieldsResponse = await this.apiCall('GET', '/voices?fields=id,name');
        if (this.assertions.checkResponse(fieldsResponse, 200, 'Field selection')) {
            const results = fieldsResponse.data.data || [];
            if (results.length > 0) {
                const firstVoice = results[0];
                const hasOnlySelectedFields = 
                    firstVoice.hasOwnProperty('id') && 
                    firstVoice.hasOwnProperty('name') &&
                    !firstVoice.hasOwnProperty('created_at') &&
                    !firstVoice.hasOwnProperty('updated_at');
                    
                if (hasOnlySelectedFields) {
                    this.printSuccess('Field selection returned only requested fields');
                } else {
                    this.printInfo('Field selection may not be working as expected');
                    this.printInfo(`Fields in response: ${Object.keys(firstVoice).join(', ')}`);
                }
            }
        }
        
        // Test 9: Field selection with timestamps
        this.printInfo('Testing field selection with timestamps...');
        const fieldsTimeResponse = await this.apiCall('GET', '/voices?fields=id,name,created_at,updated_at');
        if (this.assertions.checkResponse(fieldsTimeResponse, 200, 'Field selection with timestamps')) {
            const results = fieldsTimeResponse.data.data || [];
            if (results.length > 0) {
                const firstVoice = results[0];
                const hasTimestamps = firstVoice.hasOwnProperty('created_at') && firstVoice.hasOwnProperty('updated_at');
                if (hasTimestamps) {
                    this.printSuccess('Field selection correctly included timestamp fields');
                } else {
                    this.printInfo('Field selection may not include all timestamp fields');
                    this.printInfo(`Fields in response: ${Object.keys(firstVoice).join(', ')}`);
                }
            }
        }
        
        // Test 10: Pagination with limit and offset
        this.printInfo('Testing pagination with limit and offset...');
        const paginationResponse = await this.apiCall('GET', '/voices?limit=2&offset=1');
        if (this.assertions.checkResponse(paginationResponse, 200, 'Pagination')) {
            const results = paginationResponse.data.data || [];
            if (results.length <= 2) {
                this.printSuccess(`Pagination limit working (returned ${results.length} voices)`);
            } else {
                this.printWarning(`Pagination limit may not be working (returned ${results.length} voices)`);
            }
        }
        
        // Test 11: Complex combined query
        this.printInfo('Testing complex combined query...');
        const complexResponse = await this.apiCall('GET', `/voices?search=Voice&filter[id][in]=${queryTestIds.slice(2, 5).join(',')}&sort=-name&fields=id,name&limit=10`);
        if (this.assertions.checkResponse(complexResponse, 200, 'Complex combined query')) {
            this.printSuccess('Complex query with multiple parameters accepted');
            const results = complexResponse.data.data || [];
            this.printInfo(`Complex query returned ${results.length} results`);
        }
        
        // Test 12: Filtering by name with exact match
        this.printInfo('Testing filter with name exact match...');
        const nameFilterResponse = await this.apiCall('GET', `/voices?filter[name]=${encodeURIComponent('Alpha Voice')}`);
        if (this.assertions.checkResponse(nameFilterResponse, 200, 'Filter by name exact match')) {
            const results = nameFilterResponse.data.data || [];
            const exactNameMatches = results.filter(v => v.name && v.name.includes('Alpha Voice'));
            this.printInfo(`Name filter returned ${results.length} voices, ${exactNameMatches.length} with exact name match`);
        }
        
        // Test 12b: Filtering with 'like' operator if supported
        this.printInfo('Testing filter with like operator...');
        const likeFilterResponse = await this.apiCall('GET', '/voices?filter[name][like]=%Announcer%');
        if (this.assertions.checkResponse(likeFilterResponse, 200, 'Filter with like operator')) {
            const results = likeFilterResponse.data.data || [];
            this.printInfo(`Like filter returned ${results.length} voices`);
        }
        
        // Test 12c: Filtering with 'not' operator if supported
        this.printInfo('Testing filter with not operator...');
        const notFilterResponse = await this.apiCall('GET', `/voices?filter[id][not]=${queryTestIds[0]}`);
        if (this.assertions.checkResponse(notFilterResponse, 200, 'Filter with not operator')) {
            const results = notFilterResponse.data.data || [];
            const excludedMatches = results.filter(v => v.id == queryTestIds[0]);
            if (excludedMatches.length === 0) {
                this.printSuccess('Not filter correctly excluded the specified voice');
            } else {
                this.printInfo('Not filter may not be working as expected');
            }
            this.printInfo(`Not filter returned ${results.length} voices`);
        }
        
        return true;
    }
    
    /**
     * Test voice updates
     */
    async testVoiceUpdates() {
        this.printSection('Testing Voice Updates');
        
        // Create voice for testing. to update
        this.printInfo('Creating voice for update tests...');
        const voiceData = await this.createVoice('Update Test Voice');
        
        if (!voiceData) {
            this.printError('Failed to create test voice');
            return false;
        }
        
        // Test updating voice name
        this.printInfo('Updating voice name...');
        const updateResponse = await this.apiCall('PUT', `/voices/${voiceData.id}`, { 
            name: 'Updated Voice Name' 
        });
        
        if (this.assertions.checkResponse(updateResponse, 200, 'Update voice')) {
            // Verify the update
            const getResponse = await this.apiCall('GET', `/voices/${voiceData.id}`);
            const name = this.parseJsonField(getResponse.data, 'name');
            
            if (name === 'Updated Voice Name') {
                this.printSuccess('Voice name updated successfully');
            } else {
                this.printError('Voice name not updated correctly');
                return false;
            }
        } else {
            return false;
        }
        
        // Test updating with duplicate name
        this.printInfo('Testing update with duplicate name...');
        const duplicateVoiceData = await this.createVoice('Duplicate Test Voice');
        
        if (!duplicateVoiceData) {
            this.printError('Failed to create duplicate test voice');
            return false;
        }
        
        // Try to update first voice to have the same name as the second voice
        const duplicateResponse = await this.apiCall('PUT', `/voices/${voiceData.id}`, { 
            name: duplicateVoiceData.name  // Use the actual created name with timestamp
        });
        
        if (duplicateResponse.status === 409) {
            this.printSuccess('Duplicate name correctly rejected on update');
        } else {
            this.printError(`Duplicate name not rejected (HTTP: ${duplicateResponse.status})`);
            return false;
        }
        
        // Test updating non-existent voice
        this.printInfo('Testing update of non-existent voice...');
        const nonExistentResponse = await this.apiCall('PUT', '/voices/99999', { 
            name: 'Non-existent' 
        });
        
        if (nonExistentResponse.status === 404) {
            this.printSuccess('Non-existent voice update correctly rejected');
        } else {
            this.printError(`Non-existent voice update not rejected (HTTP: ${nonExistentResponse.status})`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test voice deletion
     */
    async testVoiceDeletion() {
        this.printSection('Testing Voice Deletion');
        
        // Create voice for testing. to delete
        this.printInfo('Creating voice for deletion test...');
        const voiceData = await this.createVoice('Delete Test Voice');
        
        if (!voiceData) {
            this.printError('Failed to create test voice');
            return false;
        }
        
        // Test deleting the voice
        this.printInfo('Deleting voice...');
        const deleteResponse = await this.apiCall('DELETE', `/voices/${voiceData.id}`);
        
        if (this.assertions.checkResponse(deleteResponse, 204, 'Delete voice')) {
            this.printSuccess('Voice deleted successfully');
            
            // Verify voice is deleted
            const getResponse = await this.apiCall('GET', `/voices/${voiceData.id}`);
            
            if (getResponse.status === 404) {
                this.printSuccess('Deleted voice correctly returns 404');
            } else {
                this.printError(`Deleted voice still accessible (HTTP: ${getResponse.status})`);
                return false;
            }
        } else {
            return false;
        }
        
        // Test deleting non-existent voice
        this.printInfo('Testing deletion of non-existent voice...');
        const nonExistentResponse = await this.apiCall('DELETE', '/voices/99999');
        
        if (nonExistentResponse.status === 404) {
            this.printSuccess('Non-existent voice deletion correctly returns 404');
        } else {
            this.printError(`Non-existent voice deletion returned unexpected code: ${nonExistentResponse.status}`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test voice with associated stories
     */
    async testVoiceWithStories() {
        this.printSection('Testing Voice with Associated Stories');
        
        // Create voice for testing.
        this.printInfo('Creating voice for story association test...');
        const voiceData = await this.createVoice('Story Test Voice');
        
        if (!voiceData) {
            this.printError('Failed to create test voice');
            return false;
        }
        
        // Create a story with this voice (pure JSON API)
        this.printInfo('Creating story with voice...');
        const storyData = {
            title: 'Test Story with Voice',
            text: 'This is a test story.',
            voice_id: parseInt(voiceData.id, 10),
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
        };

        const storyResponse = await this.apiCall('POST', '/stories', storyData);
        
        if (storyResponse.status === 201) {
            this.printSuccess('Story created with voice');
            
            // Try to delete the voice (should fail or handle gracefully)
            this.printInfo('Attempting to delete voice with associated story...');
            const deleteResponse = await this.apiCall('DELETE', `/voices/${voiceData.id}`);
            
            // This might return 409 (conflict) or 204 (if cascade delete is enabled)
            if (deleteResponse.status === 409) {
                this.printSuccess('Voice with stories correctly protected from deletion');
            } else if (deleteResponse.status === 204) {
                this.printSuccess('Voice deleted (cascade delete enabled)');
            } else {
                this.printWarning(`Unexpected response when deleting voice with stories: ${deleteResponse.status}`);
            }
        } else {
            this.printError(`Failed to create story with voice (HTTP: ${storyResponse.status})`);
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
        this.printInfo('Setting up voice tests...');
        await this.restoreAdminSession();
        return true;
    }
    
    /**
     * Cleanup function
     */
    async cleanup() {
        this.printInfo('Cleaning up voice tests...');
        
        // Delete all created voices
        for (const voiceId of this.createdVoiceIds) {
            try {
                await this.apiCall('DELETE', `/voices/${voiceId}`);
                this.printInfo(`Cleaned up voice: ${voiceId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Clean up any test stories
        try {
            const storiesResponse = await this.apiCall('GET', '/stories');
            if (storiesResponse.status === 200 && storiesResponse.data.data) {
                for (const story of storiesResponse.data.data) {
                    if (story.title && story.title.includes('Test')) {
                        await this.apiCall('DELETE', `/stories/${story.id}`);
                        this.printInfo(`Cleaned up test story: ${story.id}`);
                    }
                }
            }
        } catch (error) {
            // Ignore cleanup errors
        }
        
        return true;
    }
    
    /**
     * Main test runner
     */
    async run() {
        this.printHeader('Voice Tests');
        
        await this.setup();
        
        const tests = [
            'testVoiceCreation',
            'testVoiceListing',
            'testModernQueryParameters',
            'testVoiceUpdates',
            'testVoiceDeletion',
            'testVoiceWithStories'
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
            this.printSuccess('All voice tests passed!');
            return true;
        } else {
            this.printError(`${failed} voice tests failed`);
            return false;
        }
    }
}

module.exports = VoicesTests;
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
