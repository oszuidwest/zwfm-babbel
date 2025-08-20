/**
 * Babbel Stories Tests - Node.js
 * Test story management functionality with file uploads
 */

const BaseTest = require('../lib/BaseTest');
const Assertions = require('../lib/assertions');

class StoriesTests extends BaseTest {
    constructor() {
        super();
        this.assertions = new Assertions(this);
        
        // Global variables for tracking created resources
        this.createdStoryIds = [];
        this.createdVoiceIds = [];
    }
    
    /**
     * Helper function to create a voice for stories
     */
    async createVoice(baseName) {
        // Add timestamp to ensure uniqueness
        const uniqueName = `${baseName}_${Date.now()}_${process.pid}`;
        
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
     * Helper function to create a story and track its ID
     */
    async createStory(title, text, voiceId) {
        const formFields = {
            title,
            text,
            voice_id: voiceId,
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
        
        const response = await this.uploadFile('/stories', formFields);
        
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
     * Test story creation
     */
    async testStoryCreation() {
        this.printSection('Testing Story Creation');
        
        // Create a voice for the story
        const voiceId = await this.createVoice('TestStoryVoice');
        if (!voiceId) {
            this.printError('Failed to create voice for story tests');
            return false;
        }
        
        // Test creating a story
        const storyId = await this.createStory('Test Story Title', 'This is a test story content.', voiceId);
        
        if (storyId) {
            this.printSuccess(`Story created successfully (ID: ${storyId})`);
            
            // Verify the story exists
            const response = await this.apiCall('GET', `/stories/${storyId}`);
            if (this.assertions.checkResponse(response, 200, 'Get created story')) {
                this.assertions.assertJsonFieldEquals(response.data, 'title', 'Test Story Title', 'Story title');
                this.assertions.assertJsonFieldEquals(response.data, 'id', storyId, 'Story ID');
                this.printSuccess('Story data verified');
            } else {
                return false;
            }
        } else {
            this.printError('Failed to create story');
            return false;
        }
        
        return true;
    }
    
    /**
     * Test story CRUD operations
     */
    async testStoryCrud() {
        this.printSection('Testing Story CRUD Operations');
        
        // Create a voice
        const voiceId = await this.createVoice('CrudTestVoice');
        if (!voiceId) {
            this.printError('Failed to create voice for CRUD tests');
            return false;
        }
        
        // Create story
        const storyId = await this.createStory('CRUD Test Story', 'Initial content', voiceId);
        if (!storyId) {
            this.printError('Failed to create story for CRUD tests');
            return false;
        }
        
        // Test reading
        const readResponse = await this.apiCall('GET', `/stories/${storyId}`);
        if (!this.assertions.checkResponse(readResponse, 200, 'Read story')) {
            return false;
        }
        
        // Test updating
        const updateFields = {
            title: 'Updated CRUD Story',
            text: 'Updated content',
            voice_id: voiceId,
            status: 'active',
            start_date: '2024-01-01',
            end_date: '2024-12-31',
            monday: 'true',
            tuesday: 'false',
            wednesday: 'true',
            thursday: 'false',
            friday: 'true',
            saturday: 'false',
            sunday: 'false'
        };
        
        const updateResponse = await this.uploadFile(`/stories/${storyId}`, updateFields, null, 'file', 'PUT');
        if (this.assertions.checkResponse(updateResponse, 200, 'Update story')) {
            this.printSuccess('Story updated successfully');
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test story listing and filtering
     */
    async testStoryListing() {
        this.printSection('Testing Story Listing');
        
        // Create a voice and some test stories
        this.printInfo('Creating test data for listing...');
        const voiceId = await this.createVoice('List Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }
        
        await this.createStory('List Story 1', 'Content 1', voiceId);
        await this.createStory('List Story 2', 'Content 2', voiceId);
        await this.createStory('List Story 3', 'Content 3', voiceId);
        
        // Test basic listing
        this.printInfo('Testing basic story listing...');
        const response = await this.apiCall('GET', '/stories');
        
        if (this.assertions.checkResponse(response, 200, 'List stories')) {
            // Check for data array
            if (response.data.data && Array.isArray(response.data.data)) {
                const count = response.data.data.length;
                this.printSuccess(`Story listing returned ${count} stories`);
            } else {
                this.printError('Story listing response missing data array');
                return false;
            }
        } else {
            return false;
        }
        
        // Test pagination
        this.printInfo('Testing story pagination...');
        const paginationResponse = await this.apiCall('GET', '/stories?limit=2&offset=0');
        
        if (this.assertions.checkResponse(paginationResponse, 200, 'List stories with pagination')) {
            const count = paginationResponse.data.data ? paginationResponse.data.data.length : 0;
            if (count <= 2) {
                this.printSuccess(`Pagination limit respected (returned ${count} stories)`);
            } else {
                this.printError(`Pagination limit not respected (returned ${count} stories)`);
                return false;
            }
        } else {
            return false;
        }
        
        // Test filtering by voice_id using modern filter
        this.printInfo('Testing filter by voice_id...');
        const filterResponse = await this.apiCall('GET', `/stories?filter%5Bvoice_id%5D=${voiceId}`);
        
        if (this.assertions.checkResponse(filterResponse, 200, 'Filter by voice')) {
            this.printSuccess('Filtering by voice_id works');
        } else {
            return false;
        }
        
        // Test filtering by status
        this.printInfo('Testing filter by status...');
        const statusResponse = await this.apiCall('GET', '/stories?status=active');
        
        if (this.assertions.checkResponse(statusResponse, 200, 'Filter by status')) {
            this.printSuccess('Filtering by status works');
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test story updates
     */
    async testStoryUpdates() {
        this.printSection('Testing Story Updates');
        
        // Create a voice and story to update
        this.printInfo('Creating test data for update...');
        const voiceId = await this.createVoice('Update Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }
        
        const storyId = await this.createStory('Update Test Story', 'Original content', voiceId);
        if (!storyId) {
            this.printError('Failed to create test story');
            return false;
        }
        
        // Test updating story title and text
        this.printInfo('Updating story title and text...');
        const updateFields = {
            title: 'Updated Story Title',
            text: 'Updated story content'
        };
        
        const updateResponse = await this.uploadFile(`/stories/${storyId}`, updateFields, null, null, 'PUT');
        
        if (this.assertions.checkResponse(updateResponse, 200, 'Update story')) {
            // Verify the update
            const getResponse = await this.apiCall('GET', `/stories/${storyId}`);
            const title = this.parseJsonField(getResponse.data, 'title');
            const text = this.parseJsonField(getResponse.data, 'text');
            
            if (title === 'Updated Story Title' && text === 'Updated story content') {
                this.printSuccess('Story updated successfully');
            } else {
                this.printError('Story not updated correctly');
                return false;
            }
        } else {
            return false;
        }
        
        // Test updating weekday schedule
        this.printInfo('Updating story weekday schedule...');
        const weekdayFields = {
            monday: 'false',
            tuesday: 'true',
            wednesday: 'false',
            thursday: 'true',
            friday: 'false',
            saturday: 'true',
            sunday: 'true'
        };
        
        const weekdayResponse = await this.uploadFile(`/stories/${storyId}`, weekdayFields, null, null, 'PUT');
        
        if (this.assertions.checkResponse(weekdayResponse, 200, 'Update weekdays')) {
            this.printSuccess('Story weekday schedule updated');
        } else {
            return false;
        }
        
        // Test updating status
        this.printInfo('Updating story status to draft...');
        const statusFields = { status: 'draft' };
        
        const statusResponse = await this.uploadFile(`/stories/${storyId}`, statusFields, null, null, 'PUT');
        
        if (this.assertions.checkResponse(statusResponse, 200, 'Update status')) {
            // Verify the status update
            const getResponse = await this.apiCall('GET', `/stories/${storyId}`);
            const status = this.parseJsonField(getResponse.data, 'status');
            
            if (status === 'draft') {
                this.printSuccess('Story status updated to draft');
            } else {
                this.printError('Story status not updated correctly');
                return false;
            }
        } else {
            return false;
        }
        
        // Test updating non-existent story
        this.printInfo('Testing update of non-existent story...');
        const nonExistentResponse = await this.uploadFile('/stories/99999', { title: 'Non-existent' }, null, null, 'PUT');
        
        if (nonExistentResponse.status === 404) {
            this.printSuccess('Non-existent story update correctly rejected');
        } else {
            this.printError(`Non-existent story update not rejected (HTTP: ${nonExistentResponse.status})`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test story deletion
     */
    async testStoryDeletion() {
        this.printSection('Testing Story Deletion');
        
        // Create a voice and story to delete
        this.printInfo('Creating test data for deletion...');
        const voiceId = await this.createVoice('Delete Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }
        
        const storyId = await this.createStory('Delete Test Story', 'To be deleted', voiceId);
        if (!storyId) {
            this.printError('Failed to create test story');
            return false;
        }
        
        // Test soft delete (default)
        this.printInfo('Soft deleting story...');
        const deleteResponse = await this.apiCall('DELETE', `/stories/${storyId}`);
        
        if (this.assertions.checkResponse(deleteResponse, 204, 'Delete story')) {
            this.printSuccess('Story soft deleted successfully');
            
            // Verify story is soft deleted
            const getResponse = await this.apiCall('GET', `/stories/${storyId}`);
            
            if (getResponse.status === 404) {
                this.printSuccess('Soft deleted story returns 404');
            } else {
                this.printInfo('Soft deleted story still accessible (soft delete behavior)');
            }
        } else {
            return false;
        }
        
        // Create another story for hard delete test
        const storyId2 = await this.createStory('Hard Delete Test Story', 'To be permanently deleted', voiceId);
        if (!storyId2) {
            this.printError('Failed to create second test story');
            return false;
        }
        
        // Test hard delete (if supported)
        this.printInfo('Testing hard delete...');
        const hardDeleteResponse = await this.apiCall('DELETE', `/stories/${storyId2}?hard=true`);
        
        if (hardDeleteResponse.status === 204) {
            this.printSuccess('Story hard deleted successfully');
        } else if (hardDeleteResponse.status === 400 || hardDeleteResponse.status === 403) {
            this.printInfo('Hard delete not supported or not allowed');
        } else {
            this.printWarning(`Unexpected response for hard delete: ${hardDeleteResponse.status}`);
        }
        
        // Test deleting non-existent story
        this.printInfo('Testing deletion of non-existent story...');
        const nonExistentResponse = await this.apiCall('DELETE', '/stories/99999');
        
        if (nonExistentResponse.status === 404) {
            this.printSuccess('Non-existent story deletion correctly returns 404');
        } else {
            this.printError(`Non-existent story deletion returned unexpected code: ${nonExistentResponse.status}`);
            return false;
        }
        
        return true;
    }
    
    /**
     * Test story scheduling
     */
    async testStoryScheduling() {
        this.printSection('Testing Story Scheduling');
        
        // Create a voice
        this.printInfo('Creating test voice for scheduling tests...');
        const voiceId = await this.createVoice('Schedule Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }
        
        // Test creating a future-dated story
        this.printInfo('Creating future-dated story...');
        const futureFields = {
            title: 'Future Story',
            text: 'This story is scheduled for the future.',
            voice_id: voiceId,
            status: 'active',
            start_date: '2030-01-01',
            end_date: '2030-12-31',
            monday: 'true',
            tuesday: 'true',
            wednesday: 'true',
            thursday: 'true',
            friday: 'true',
            saturday: 'true',
            sunday: 'true'
        };
        
        const futureResponse = await this.uploadFile('/stories', futureFields);
        
        if (futureResponse.status === 201) {
            this.printSuccess('Future-dated story created');
            const storyId = this.parseJsonField(futureResponse.data, 'id');
            if (storyId) {
                this.createdStoryIds.push(storyId);
            }
        } else {
            this.printError(`Failed to create future-dated story (HTTP: ${futureResponse.status})`);
            return false;
        }
        
        // Test creating a weekend-only story
        this.printInfo('Creating weekend-only story...');
        const weekendFields = {
            title: 'Weekend Story',
            text: 'This story only plays on weekends.',
            voice_id: voiceId,
            status: 'active',
            start_date: '2024-01-01',
            end_date: '2024-12-31',
            monday: 'false',
            tuesday: 'false',
            wednesday: 'false',
            thursday: 'false',
            friday: 'false',
            saturday: 'true',
            sunday: 'true'
        };
        
        const weekendResponse = await this.uploadFile('/stories', weekendFields);
        
        if (weekendResponse.status === 201) {
            this.printSuccess('Weekend-only story created');
            const weekendStoryId = this.parseJsonField(weekendResponse.data, 'id');
            if (weekendStoryId) {
                this.createdStoryIds.push(weekendStoryId);
            }
        } else {
            this.printError(`Failed to create weekend-only story (HTTP: ${weekendResponse.status})`);
            return false;
        }
        
        // Test modern date filtering for active stories
        this.printInfo('Testing modern date filtering for active stories...');
        
        // Test modern filter for a Saturday date (should find weekend story)
        const saturdayDate = '2024-06-15'; // This is a Saturday
        const saturdayResponse = await this.apiCall('GET', `/stories?filter%5Bstart_date%5D%5Blte%5D=${saturdayDate}&filter%5Bend_date%5D%5Bgte%5D=${saturdayDate}&filter%5Bsaturday%5D=1`);
        
        if (this.assertions.checkResponse(saturdayResponse, 200, 'Filter by Saturday date')) {
            const stories = saturdayResponse.data.data || [];
            const hasWeekend = stories.some(story => story.title && story.title.includes('Weekend Story'));
            
            if (hasWeekend) {
                this.printSuccess('Weekend story correctly appears on Saturday');
            } else {
                this.printWarning('Weekend story not found on Saturday date');
            }
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test comprehensive modern query capabilities
     */
    async testModernQueryParams() {
        this.printSection('Testing Comprehensive Modern Query Parameters');
        
        // Create test data
        this.printInfo('Creating diverse test data for modern queries...');
        const voice1 = await this.createVoice('Alice Anderson');
        const voice2 = await this.createVoice('Bob Brown');
        const voice3 = await this.createVoice('Charlie Chen');
        
        if (!voice1 || !voice2 || !voice3) {
            this.printError('Failed to create test voices');
            return false;
        }
        
        // Create diverse stories for testing
        await this.createStory('Breaking News Today', 'Important breaking news content', voice1);
        await this.createStory('Weather Update Morning', "Today's weather forecast", voice2);
        await this.createStory('Sports Highlights', 'Latest sports results', voice3);
        await this.createStory('Traffic Report Rush Hour', 'Current traffic conditions', voice1);
        await this.createStory('Entertainment News', 'Celebrity updates', voice2);
        
        // Test comparison operators (gt, gte, lt, lte)
        this.printInfo('Testing comparison operators...');
        const today = new Date().toISOString().split('T')[0];
        const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        
        const gteResponse = await this.apiCall('GET', `/stories?filter%5Bcreated_at%5D%5Bgte%5D=${yesterday}`);
        if (this.assertions.checkResponse(gteResponse, 200, 'GTE operator')) {
            this.printSuccess('Greater than or equal (gte) operator works');
        } else {
            return false;
        }
        
        // Test multiple filters combined
        this.printInfo('Testing multiple filters combined...');
        const multiFilterResponse = await this.apiCall('GET', `/stories?filter%5Bvoice_id%5D=${voice1}&filter%5Bstatus%5D=active&filter%5Bmonday%5D=1`);
        if (this.assertions.checkResponse(multiFilterResponse, 200, 'Multiple filters')) {
            this.printSuccess('Multiple filter conditions work together');
        } else {
            return false;
        }
        
        // Test sorting combinations
        this.printInfo('Testing complex sorting...');
        const sortResponse = await this.apiCall('GET', '/stories?sort=-created_at,+title');
        if (this.assertions.checkResponse(sortResponse, 200, 'Multi-field sort')) {
            this.printSuccess('Multi-field sorting works');
        } else {
            return false;
        }
        
        // Test colon notation sorting
        const colonSortResponse = await this.apiCall('GET', '/stories?sort=created_at:desc,title:asc');
        if (this.assertions.checkResponse(colonSortResponse, 200, 'Colon notation sort')) {
            this.printSuccess('Colon notation sorting works');
        } else {
            return false;
        }
        
        // Test search functionality
        this.printInfo('Testing search across multiple fields...');
        const searchResponse = await this.apiCall('GET', '/stories?search=News');
        if (this.assertions.checkResponse(searchResponse, 200, 'Search')) {
            const count = searchResponse.data.data ? searchResponse.data.data.length : 0;
            this.printSuccess(`Search functionality works (found ${count} results)`);
        } else {
            return false;
        }
        
        return true;
    }
    
    /**
     * Test story audio upload and download
     */
    async testStoryAudio() {
        this.printSection('Testing Story Audio Upload and Download');
        
        // Create a voice for the test story
        this.printInfo('Creating test voice for audio test...');
        const voiceId = await this.createVoice('Audio Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }
        
        // Create a test audio file
        this.printInfo('Creating test audio file...');
        const testAudio = '/tmp/test_audio_upload.wav';
        const fs = require('fs');
        
        try {
            const { execSync } = require('child_process');
            execSync(`ffmpeg -f lavfi -i anullsrc=r=44100:cl=stereo -t 2 -f wav "${testAudio}" -y 2>/dev/null`, { stdio: 'ignore' });
            if (!fs.existsSync(testAudio)) {
                this.printWarning('Could not create test audio file, skipping audio test');
                return true; // Skip this test
            }
            this.printSuccess('Created test audio file');
        } catch (error) {
            this.printWarning('ffmpeg not available, skipping audio test');
            return true; // Skip this test
        }
        
        // Test creating story with audio upload
        this.printInfo('Creating story with audio file upload...');
        const audioFields = {
            title: 'Story With Audio Upload Test',
            text: 'This story has uploaded audio for testing',
            voice_id: voiceId,
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
        
        const audioResponse = await this.uploadFile('/stories', audioFields, testAudio, 'audio');
        
        if (audioResponse.status !== 201) {
            this.printError(`Failed to create story with audio (HTTP: ${audioResponse.status})`);
            this.printError(`Response: ${JSON.stringify(audioResponse.data)}`);
            fs.unlinkSync(testAudio);
            return false;
        }
        
        const storyId = this.parseJsonField(audioResponse.data, 'id');
        if (!storyId) {
            this.printError('Failed to extract story ID from response');
            fs.unlinkSync(testAudio);
            return false;
        }
        
        this.createdStoryIds.push(storyId);
        this.printSuccess(`Story with audio created successfully (ID: ${storyId})`);
        
        // Verify the story has an audio URL
        this.printInfo('Verifying story has audio URL...');
        const getResponse = await this.apiCall('GET', `/stories/${storyId}`);
        
        if (this.assertions.checkResponse(getResponse, 200, 'Get story with audio')) {
            const audioUrl = this.parseJsonField(getResponse.data, 'audio_url');
            
            if (audioUrl) {
                this.printSuccess(`Story has audio URL: ${audioUrl}`);
                
                // Test downloading the audio
                this.printInfo('Testing audio download from API...');
                const downloadPath = '/tmp/downloaded_story_audio.wav';
                const downloadResponse = await this.downloadFile(audioUrl, downloadPath);
                
                if (downloadResponse === 200) {
                    if (fs.existsSync(downloadPath)) {
                        const stats = fs.statSync(downloadPath);
                        if (stats.size > 0) {
                            this.printSuccess(`Audio downloaded successfully (${stats.size} bytes)`);
                        } else {
                            this.printWarning('Downloaded file is empty');
                        }
                        fs.unlinkSync(downloadPath);
                    } else {
                        this.printError('Download failed - file not created');
                        fs.unlinkSync(testAudio);
                        return false;
                    }
                } else {
                    this.printError(`Audio download failed (HTTP: ${downloadResponse})`);
                    fs.unlinkSync(testAudio);
                    return false;
                }
            } else {
                this.printError('Story missing audio URL');
                fs.unlinkSync(testAudio);
                return false;
            }
        } else {
            fs.unlinkSync(testAudio);
            return false;
        }
        
        // Clean up
        fs.unlinkSync(testAudio);
        
        return true;
    }
    
    /**
     * Setup function
     */
    async setup() {
        this.printInfo('Setting up story tests...');
        await this.restoreAdminSession();
        return true;
    }
    
    /**
     * Cleanup function
     */
    async cleanup() {
        this.printInfo('Cleaning up story tests...');
        
        // Delete all created stories
        for (const storyId of this.createdStoryIds) {
            try {
                await this.apiCall('DELETE', `/stories/${storyId}`);
                this.printInfo(`Cleaned up story: ${storyId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
        }
        
        // Delete all created voices
        for (const voiceId of this.createdVoiceIds) {
            try {
                await this.apiCall('DELETE', `/voices/${voiceId}`);
                this.printInfo(`Cleaned up voice: ${voiceId}`);
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
        this.printHeader('Story Tests');
        
        await this.setup();
        
        const tests = [
            'testStoryCreation',
            'testStoryCrud',
            'testStoryListing',
            'testStoryUpdates',
            'testStoryDeletion',
            'testStoryScheduling',
            'testModernQueryParams',
            'testStoryAudio'
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
            this.printSuccess('All story tests passed!');
            return true;
        } else {
            this.printError(`${failed} story tests failed`);
            return false;
        }
    }
}

module.exports = StoriesTests;
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
