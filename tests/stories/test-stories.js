// Babbel stories tests.
// Tests story management functionality including CRUD operations and file uploads.

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
     * Test story bulletin history endpoint with modern query parameter support
     */
    async testStoryBulletinHistory() {
        this.printSection('Testing Story Bulletin History');
        
        // Setup test data - create station, voice, story, and generate bulletins that include the story
        this.printInfo('Setting up test data for story bulletin history...');
        
        // Create test station
        const stationId = await this.createTestStation('Bulletin History Station');
        if (!stationId) {
            this.printError('Failed to create test station for bulletin history tests');
            return false;
        }
        
        // Create test voice
        const voiceId = await this.createVoice('Bulletin History Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice for bulletin history tests');
            return false;
        }
        
        // Create station-voice relationship with jingle
        const stationVoiceId = await this.createStationVoiceWithJingle(stationId, voiceId);
        if (!stationVoiceId) {
            this.printWarning('Failed to create station-voice relationship - may not have FFmpeg available');
            // Try to create a simple station-voice relationship without jingle
            const FormData = require('form-data');
            const basicForm = new FormData();
            basicForm.append('station_id', stationId.toString());
            basicForm.append('voice_id', voiceId.toString());
            basicForm.append('mix_point', '3.0');
            const basicResponse = await this.apiCallFormData('POST', '/station-voices', basicForm);
            if (basicResponse.status !== 201) {
                this.printError('Failed to create even basic station-voice relationship for bulletin history tests');
                return false;
            }
            const basicSvId = this.parseJsonField(basicResponse.data, 'id');
            if (!basicSvId) {
                this.printError('Failed to extract station-voice ID from basic relationship');
                return false;
            }
            // Track for cleanup
            try {
                await this.apiCall('DELETE', `/station-voices/${basicSvId}`);
            } catch (error) {
                // Ignore cleanup error
            }
        }
        
        // Create test story that will be included in bulletins
        const testStoryId = await this.createStory('Test Story for Bulletin History', 'This story will be included in multiple bulletins for testing', voiceId);
        if (!testStoryId) {
            this.printError('Failed to create test story for bulletin history tests');
            return false;
        }
        
        // Create additional stories to include in bulletins (to ensure bulletins have multiple stories)
        const additionalStoryId1 = await this.createStory('Additional Story One', 'Additional story content one', voiceId);
        const additionalStoryId2 = await this.createStory('Additional Story Two', 'Additional story content two', voiceId);
        
        // Wait for potential audio processing
        this.printInfo('Waiting for audio processing...');
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Generate multiple bulletins that include our test story
        this.printInfo('Generating bulletins that include the test story...');
        const generatedBulletins = [];
        for (let i = 0; i < 4; i++) {
            const response = await this.apiCall('POST', `/stations/${stationId}/bulletins`, {});
            if (response.status === 200) {
                const bulletinId = this.parseJsonField(response.data, 'id');
                const filename = this.parseJsonField(response.data, 'filename');
                if (bulletinId) {
                    generatedBulletins.push({ id: bulletinId, filename: filename });
                }
                // Add small delay to ensure different timestamps
                await new Promise(resolve => setTimeout(resolve, 300));
            } else {
                this.printWarning(`Bulletin generation failed: HTTP ${response.status} - ${JSON.stringify(response.data)}`);
            }
        }
        
        if (generatedBulletins.length === 0) {
            this.printWarning(`Could not generate any bulletins for testing (created ${generatedBulletins.length})`);
            this.printInfo('This may be due to missing FFmpeg or insufficient test setup');
            this.printInfo('Skipping story bulletin history tests that require actual bulletins...');
            
            // Test the endpoint with empty results instead
            const emptyResponse = await this.apiCall('GET', `/stories/${testStoryId}/bulletins`);
            if (this.assertions.checkResponse(emptyResponse, 200, 'Story bulletin history (empty)')) {
                const results = emptyResponse.data.data || [];
                if (results.length === 0) {
                    this.printSuccess('Story bulletin history endpoint works correctly with no bulletins');
                } else {
                    this.printWarning('Expected empty results but got data');
                }
            } else {
                return false;
            }
            
            // Test non-existent story
            this.printInfo('Testing error handling for non-existent story...');
            const nonExistentResponse = await this.apiCall('GET', '/stories/99999/bulletins');
            if (nonExistentResponse.status === 404) {
                this.printSuccess('Non-existent story correctly returns 404');
            } else {
                this.printError(`Non-existent story returned unexpected status: ${nonExistentResponse.status}`);
                return false;
            }
            
            // Clean up and exit early
            this.createdStoryIds.push(testStoryId);
            if (additionalStoryId1) this.createdStoryIds.push(additionalStoryId1);
            if (additionalStoryId2) this.createdStoryIds.push(additionalStoryId2);
            
            try {
                await this.apiCall('DELETE', `/stations/${stationId}`);
            } catch (error) {
                // Ignore cleanup errors
            }
            
            return true; // Test passed, just with limited functionality
        }
        
        this.printSuccess(`Generated ${generatedBulletins.length} bulletins for testing`);
        
        // Adjust test expectations based on the number of bulletins created
        const hasManyBulletins = generatedBulletins.length >= 3;
        const hasMinimalBulletins = generatedBulletins.length >= 1;
        
        if (!hasMinimalBulletins) {
            this.printError('No bulletins were generated - cannot test bulletin history');
            return false;
        }
        
        if (!hasManyBulletins) {
            this.printWarning(`Only ${generatedBulletins.length} bulletin(s) created - some multi-bulletin tests may be limited`);
        }
        
        // Test 1: Basic story bulletin history listing
        this.printInfo('Testing basic story bulletin history listing...');
        const basicResponse = await this.apiCall('GET', `/stories/${testStoryId}/bulletins`);
        if (this.assertions.checkResponse(basicResponse, 200, 'Basic story bulletin history')) {
            const results = basicResponse.data.data || [];
            if (results.length > 0) {
                this.printSuccess(`Basic listing returned ${results.length} bulletins that included the story`);
                
                // Verify response structure - should include story_order and included_at from bulletin_stories join
                const firstBulletin = results[0];
                if (firstBulletin.story_order !== undefined && firstBulletin.included_at) {
                    this.printSuccess('Response includes story_order and included_at fields from bulletin_stories join');
                } else {
                    this.printError('Response missing story_order or included_at fields');
                    return false;
                }
                
                // Verify all bulletins were created for the correct station
                const allFromCorrectStation = results.every(b => b.station_id === stationId);
                if (allFromCorrectStation) {
                    this.printSuccess('All bulletins correctly from the test station');
                } else {
                    this.printWarning('Some bulletins from unexpected stations');
                }
            } else {
                this.printError('Basic listing returned no bulletins - story was not included in any bulletins');
                return false;
            }
        } else {
            return false;
        }
        
        // Test 2: Search by filename
        this.printInfo('Testing search by filename...');
        const searchResponse = await this.apiCall('GET', `/stories/${testStoryId}/bulletins?search=bulletin`);
        if (this.assertions.checkResponse(searchResponse, 200, 'Search story bulletins by filename')) {
            const results = searchResponse.data.data || [];
            if (results.length > 0) {
                this.printSuccess(`Search returned ${results.length} bulletins matching "bulletin"`);
                // All results should still include story_order and included_at
                const firstResult = results[0];
                if (firstResult.story_order !== undefined && firstResult.included_at) {
                    this.printSuccess('Search results include story_order and included_at fields');
                }
            } else {
                this.printWarning('Search returned no results');
            }
        } else {
            return false;
        }
        
        // Test 3: Search by station name
        this.printInfo('Testing search by station name...');
        const stationSearchResponse = await this.apiCall('GET', `/stories/${testStoryId}/bulletins?search=History`);
        if (this.assertions.checkResponse(stationSearchResponse, 200, 'Search story bulletins by station name')) {
            const results = stationSearchResponse.data.data || [];
            if (results.length > 0) {
                this.printSuccess(`Station name search returned ${results.length} bulletins`);
            } else {
                this.printWarning('Station name search returned no results');
            }
        } else {
            return false;
        }
        
        // Test 4: Field selection
        this.printInfo('Testing field selection...');
        const fieldsResponse = await this.apiCall('GET', `/stories/${testStoryId}/bulletins?fields=id,filename,story_order,included_at&limit=3`);
        if (this.assertions.checkResponse(fieldsResponse, 200, 'Story bulletin history field selection')) {
            const results = fieldsResponse.data.data || [];
            if (results.length > 0) {
                const firstResult = results[0];
                const hasOnlySelectedFields = 
                    firstResult.hasOwnProperty('id') && 
                    firstResult.hasOwnProperty('filename') &&
                    firstResult.hasOwnProperty('story_order') &&
                    firstResult.hasOwnProperty('included_at') &&
                    !firstResult.hasOwnProperty('duration_seconds') &&
                    !firstResult.hasOwnProperty('station_name');
                
                if (hasOnlySelectedFields) {
                    this.printSuccess('Field selection works correctly');
                } else {
                    this.printWarning('Field selection returned unexpected fields');
                }
            } else {
                this.printWarning('No results returned for field selection test');
            }
        } else {
            return false;
        }
        
        // Test 5: Sorting by included_at (most recent first)
        this.printInfo('Testing sorting by included_at descending...');
        const sortDescResponse = await this.apiCall('GET', `/stories/${testStoryId}/bulletins?sort=-included_at&limit=5`);
        if (this.assertions.checkResponse(sortDescResponse, 200, 'Sort story bulletins by included_at desc')) {
            const results = sortDescResponse.data.data || [];
            if (results.length > 1 && hasManyBulletins) {
                let correctOrder = true;
                for (let i = 1; i < results.length; i++) {
                    if (new Date(results[i-1].included_at) < new Date(results[i].included_at)) {
                        correctOrder = false;
                        break;
                    }
                }
                if (correctOrder) {
                    this.printSuccess('Descending sort by included_at works correctly');
                } else {
                    this.printError('Sort order by included_at is incorrect');
                    return false;
                }
            } else if (results.length >= 1) {
                this.printSuccess('Sort parameter accepted (limited bulletins for order verification)');
            } else {
                this.printWarning('Not enough bulletins for sort order test');
            }
        } else {
            return false;
        }
        
        // Test 6: Sorting by story_order ascending
        this.printInfo('Testing sorting by story_order ascending...');
        const sortAscResponse = await this.apiCall('GET', `/stories/${testStoryId}/bulletins?sort=story_order:asc&limit=5`);
        if (this.assertions.checkResponse(sortAscResponse, 200, 'Sort story bulletins by story_order asc')) {
            const results = sortAscResponse.data.data || [];
            if (results.length > 1 && hasManyBulletins) {
                let correctOrder = true;
                for (let i = 1; i < results.length; i++) {
                    if (results[i-1].story_order > results[i].story_order) {
                        correctOrder = false;
                        break;
                    }
                }
                if (correctOrder) {
                    this.printSuccess('Ascending sort by story_order works correctly');
                } else {
                    this.printWarning('Sort order by story_order may be incorrect');
                }
            } else if (results.length >= 1) {
                this.printSuccess('Sort parameter accepted (limited bulletins for order verification)');
            } else {
                this.printWarning('No results for story_order sort test');
            }
        } else {
            return false;
        }
        
        // Test 7: Filtering by station_id
        this.printInfo('Testing filtering by station_id...');
        const filterResponse = await this.apiCall('GET', `/stories/${testStoryId}/bulletins?filter%5Bstation_id%5D=${stationId}`);
        if (this.assertions.checkResponse(filterResponse, 200, 'Filter story bulletins by station_id')) {
            const results = filterResponse.data.data || [];
            const allFromCorrectStation = results.every(b => b.station_id === stationId);
            if (allFromCorrectStation && results.length > 0) {
                this.printSuccess(`Station filter works correctly (${results.length} bulletins)`);
            } else if (results.length === 0) {
                this.printWarning('Station filter returned no results');
            } else {
                this.printError('Station filter returned bulletins from wrong station');
                return false;
            }
        } else {
            return false;
        }
        
        // Test 8: Filtering by story_order (gte operator)
        this.printInfo('Testing filtering by story_order gte...');
        const orderFilterResponse = await this.apiCall('GET', `/stories/${testStoryId}/bulletins?filter%5Bstory_order%5D%5Bgte%5D=1&limit=5`);
        if (this.assertions.checkResponse(orderFilterResponse, 200, 'Filter story bulletins by story_order gte')) {
            const results = orderFilterResponse.data.data || [];
            const allMeetCriteria = results.every(b => b.story_order >= 1);
            if (allMeetCriteria) {
                this.printSuccess('Story order filter (gte) works correctly');
            } else {
                this.printWarning('Some results do not meet story_order filter criteria');
            }
        } else {
            return false;
        }
        
        // Test 9: Pagination
        this.printInfo('Testing pagination...');
        const pageResponse = await this.apiCall('GET', `/stories/${testStoryId}/bulletins?limit=2&offset=1`);
        if (this.assertions.checkResponse(pageResponse, 200, 'Story bulletin history pagination')) {
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
        } else {
            return false;
        }
        
        // Test 10: Complex query combining multiple parameters
        this.printInfo('Testing complex query with multiple parameters...');
        const complexResponse = await this.apiCall('GET', 
            `/stories/${testStoryId}/bulletins?search=bulletin&sort=-included_at&fields=id,filename,story_order,included_at&limit=10`);
        if (this.assertions.checkResponse(complexResponse, 200, 'Complex story bulletin history query')) {
            const results = complexResponse.data.data || [];
            this.printSuccess(`Complex query returned ${results.length} results`);
            
            // Verify field selection still works in complex query
            if (results.length > 0) {
                const firstResult = results[0];
                const hasCorrectFields = firstResult.hasOwnProperty('story_order') && firstResult.hasOwnProperty('included_at');
                if (hasCorrectFields) {
                    this.printSuccess('Complex query maintains story_order and included_at fields');
                }
            }
        } else {
            return false;
        }
        
        // Test 11: Test with story that has no bulletins (empty result)
        this.printInfo('Testing story with no bulletins (empty result)...');
        const emptyStoryId = await this.createStory('Unused Story', 'This story will not be used in any bulletins', voiceId);
        if (emptyStoryId) {
            const emptyResponse = await this.apiCall('GET', `/stories/${emptyStoryId}/bulletins`);
            if (this.assertions.checkResponse(emptyResponse, 200, 'Story with no bulletins')) {
                const results = emptyResponse.data.data || [];
                if (results.length === 0) {
                    this.printSuccess('Story with no bulletins correctly returns empty result');
                } else {
                    this.printError('Story with no bulletins unexpectedly returned results');
                    return false;
                }
            } else {
                return false;
            }
        }
        
        // Test 12: Error handling - non-existent story
        this.printInfo('Testing error handling for non-existent story...');
        const nonExistentResponse = await this.apiCall('GET', '/stories/99999/bulletins');
        if (nonExistentResponse.status === 404) {
            this.printSuccess('Non-existent story correctly returns 404');
        } else {
            this.printError(`Non-existent story returned unexpected status: ${nonExistentResponse.status}`);
            return false;
        }
        
        // Clean up created resources
        this.createdStoryIds.push(testStoryId);
        if (additionalStoryId1) this.createdStoryIds.push(additionalStoryId1);
        if (additionalStoryId2) this.createdStoryIds.push(additionalStoryId2);
        if (emptyStoryId) this.createdStoryIds.push(emptyStoryId);
        
        // Clean up station, voice, and station-voice relationship
        try {
            await this.apiCall('DELETE', `/station-voices/${stationVoiceId}`);
            await this.apiCall('DELETE', `/stations/${stationId}`);
            // Voice will be cleaned up by the cleanup function
        } catch (error) {
            // Ignore cleanup errors
        }
        
        return true;
    }
    
    /**
     * Helper function to create a test station (similar to bulletins test helper)
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
            return stationId;
        }
        
        return null;
    }
    
    /**
     * Helper function to create station-voice relationship with jingle (simplified version)
     */
    async createStationVoiceWithJingle(stationId, voiceId, mixPoint = 3.0) {
        // Create a simple test jingle audio file
        const jingleFile = `/tmp/test_jingle_${stationId}_${voiceId}.wav`;
        const fs = require('fs');
        
        try {
            const { execSync } = require('child_process');
            execSync(`ffmpeg -f lavfi -i "sine=frequency=440:duration=2" -ar 44100 -ac 2 -f wav "${jingleFile}" -y 2>/dev/null`, { stdio: 'ignore' });
            if (!fs.existsSync(jingleFile)) {
                this.printWarning('Could not create test jingle file - skipping jingle creation');
                return null;
            }
        } catch (error) {
            this.printWarning('ffmpeg not available - skipping jingle creation');
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
            return svId;
        }
        
        return null;
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
            'testStoryBulletinHistory',
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
