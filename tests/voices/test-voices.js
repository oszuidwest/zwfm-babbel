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
     * Test voice listing
     */
    async testVoiceListing() {
        this.printSection('Testing Voice Listing');
        
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
        
        // Test pagination
        this.printInfo('Testing voice pagination...');
        const paginationResponse = await this.apiCall('GET', '/voices?limit=2&offset=0');
        
        if (this.assertions.checkResponse(paginationResponse, 200, 'List voices with pagination')) {
            const body = paginationResponse.data;
            const count = body.data ? body.data.length : 0;
            
            if (count <= 2) {
                this.printSuccess(`Pagination limit respected (returned ${count} voices)`);
            } else {
                this.printError(`Pagination limit not respected (returned ${count} voices)`);
                return false;
            }
        } else {
            return false;
        }
        
        // Test search
        this.printInfo('Testing voice search...');
        const searchResponse = await this.apiCall('GET', '/voices?search=List%20Test');
        
        if (this.assertions.checkResponse(searchResponse, 200, 'Search voices')) {
            const body = searchResponse.data;
            const count = body.data ? body.data.length : 0;
            
            if (count >= 3) {
                this.printSuccess(`Search returned ${count} matching voices`);
            } else {
                this.printError(`Search returned unexpected number of voices: ${count}`);
                return false;
            }
        } else {
            return false;
        }
        
        // Test sorting
        this.printInfo('Testing voice sorting...');
        const sortResponse = await this.apiCall('GET', '/voices?sort=-name');
        
        if (this.assertions.checkResponse(sortResponse, 200, 'Sort voices')) {
            this.printSuccess('Voice sorting request succeeded');
        } else {
            return false;
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
        
        // Create a story with this voice (using form data with individual weekday fields)
        this.printInfo('Creating story with voice...');
        const formFields = {
            title: 'Test Story with Voice',
            text: 'This is a test story.',
            voice_id: voiceData.id,
            status: 'active',
            start_date: '2024-01-01',
            end_date: '2024-12-31',
            monday: 'true',
            tuesday: 'true',
            wednesday: 'true',
            thursday: 'true',
            friday: 'true',
            saturday: 'false',
            sunday: 'false'
        };
        
        const storyResponse = await this.uploadFile('/stories', formFields);
        
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
