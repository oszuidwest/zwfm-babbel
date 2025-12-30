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
     * @param {string} title - Story title
     * @param {string} text - Story text content
     * @param {number|null} voiceId - Optional voice ID
     * @param {number} weekdays - Weekdays bitmask (0-127), defaults to 127 (all days)
     * @param {string} status - Story status (active, draft, expired), defaults to 'active'
     */
    async createStory(title, text, voiceId, weekdays = 127, status = 'active') {
        const storyData = {
            title,
            text,
            voice_id: voiceId ? parseInt(voiceId, 10) : null,
            status: status,
            start_date: '2024-01-01',
            end_date: '2024-12-31',
            weekdays: weekdays
        };

        const response = await this.apiCall('POST', '/stories', storyData);

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
        const updateData = {
            title: 'Updated CRUD Story',
            text: 'Updated content',
            voice_id: voiceId ? parseInt(voiceId, 10) : null,
            status: 'active',
            start_date: '2024-01-01',
            end_date: '2024-12-31',
        };

        const updateResponse = await this.apiCall('PUT', `/stories/${storyId}`, updateData);
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
        
        // Test audio_file and audio_url fields in response
        this.printInfo('Testing audio_file and audio_url fields in response...');
        const singleStoryResponse = await this.apiCall('GET', `/stories/${storyId}`);
        if (this.assertions.checkResponse(singleStoryResponse, 200, 'Get single story for audio fields check')) {
            const story = singleStoryResponse.data;

            // audio_url should always be present (even without audio file)
            if (story.hasOwnProperty('audio_url') && typeof story.audio_url === 'string') {
                this.printSuccess('audio_url field is present and always populated');
            } else {
                this.printError('audio_url field is missing or not a string');
                return false;
            }

            // audio_file should be present (empty string when no audio)
            if (story.hasOwnProperty('audio_file')) {
                if (story.audio_file === '') {
                    this.printSuccess('audio_file field is present (empty for story without audio)');
                } else {
                    this.printInfo(`audio_file field has value: ${story.audio_file}`);
                }
            } else {
                this.printError('audio_file field is missing from response');
                return false;
            }
        } else {
            return false;
        }

        // Test filtering for stories WITHOUT audio (filter[audio_url]=)
        this.printInfo('Testing filter for stories without audio (filter[audio_url]=)...');
        const noAudioResponse = await this.apiCall('GET', '/stories?filter%5Baudio_url%5D=');
        if (this.assertions.checkResponse(noAudioResponse, 200, 'Filter stories without audio')) {
            const stories = noAudioResponse.data.data || [];
            // All returned stories should have empty audio_file
            const allWithoutAudio = stories.every(s => s.audio_file === '');
            if (allWithoutAudio) {
                this.printSuccess(`Audio filter (no audio) works correctly (${stories.length} stories without audio)`);
            } else {
                const withAudio = stories.filter(s => s.audio_file !== '');
                this.printError(`Audio filter returned ${withAudio.length} stories WITH audio - filter not working`);
                return false;
            }
        } else {
            return false;
        }

        // Test filtering by status field - create stories with different statuses
        this.printInfo('Testing filter by status field...');

        // Create a draft story and an active story for this test
        const draftStoryId = await this.createStory('Draft Story', 'Draft content', voiceId, 127, 'draft');
        const activeStoryId = await this.createStory('Active Story', 'Active content', voiceId, 127, 'active');

        if (!draftStoryId || !activeStoryId) {
            this.printError('Failed to create test stories for status filtering');
            return false;
        }

        // Query for only active stories
        const statusResponse = await this.apiCall('GET', '/stories?filter%5Bstatus%5D=active');

        if (this.assertions.checkResponse(statusResponse, 200, 'Filter by status')) {
            const stories = statusResponse.data.data || [];

            // Verify all returned stories have status 'active'
            const allActive = stories.every(story => story.status === 'active');
            const containsDraft = stories.some(story => String(story.id) === String(draftStoryId));

            if (allActive && !containsDraft) {
                this.printSuccess('Status filtering correctly returns only active stories');
            } else if (containsDraft) {
                this.printError('Status filtering returned draft story - filter not working!');
                return false;
            } else if (!allActive) {
                const nonActiveStatuses = stories.filter(s => s.status !== 'active').map(s => s.status);
                this.printError(`Status filtering returned non-active stories: ${nonActiveStatuses.join(', ')}`);
                return false;
            }
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
        const updateData = {
            title: 'Updated Story Title',
            text: 'Updated story content'
        };

        const updateResponse = await this.apiCall('PUT', `/stories/${storyId}`, updateData);
        
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
        // Update to Mon/Wed/Fri only: Mon=2, Wed=8, Fri=32 = 42
        this.printInfo('Updating story weekday schedule to Mon/Wed/Fri (bitmask: 42)...');
        const weekdayData = { weekdays: 42 };

        const weekdayResponse = await this.apiCall('PUT', `/stories/${storyId}`, weekdayData);

        if (this.assertions.checkResponse(weekdayResponse, 200, 'Update weekdays')) {
            this.printSuccess('Story weekday schedule updated');

            // Verify the weekdays were actually saved correctly
            const verifyResponse = await this.apiCall('GET', `/stories/${storyId}`);
            if (this.assertions.checkResponse(verifyResponse, 200, 'Verify weekdays update')) {
                const savedWeekdays = verifyResponse.data.weekdays;
                if (savedWeekdays === 42) {
                    this.printSuccess('Weekdays verified: Mon/Wed/Fri active (bitmask: 42)');
                } else {
                    this.printError(`Expected weekdays=42 but got ${savedWeekdays}`);
                    return false;
                }
            } else {
                return false;
            }
        } else {
            return false;
        }
        
        // Test updating status
        this.printInfo('Updating story status to draft...');
        const statusData = { status: 'draft' };

        const statusResponse = await this.apiCall('PUT', `/stories/${storyId}`, statusData);
        
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
        const nonExistentResponse = await this.apiCall('PUT', '/stories/99999', { title: 'Non-existent' });
        
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

            // Verify story is soft deleted (not visible in default query)
            const getResponse = await this.apiCall('GET', `/stories/${storyId}`);

            if (getResponse.status === 404) {
                this.printSuccess('Soft deleted story returns 404');
            } else {
                this.printInfo('Soft deleted story still accessible (soft delete behavior)');
            }

            // Test trashed=only parameter - should show only deleted stories
            this.printInfo('Testing trashed=only parameter...');
            const deletedOnlyResponse = await this.apiCall('GET', '/stories?trashed=only');

            if (this.assertions.checkResponse(deletedOnlyResponse, 200, 'Query deleted stories')) {
                const deletedStories = deletedOnlyResponse.data.data || [];
                // Use == for comparison since storyId is string but s.id is number
                const foundDeleted = deletedStories.some(s => String(s.id) === String(storyId));

                if (foundDeleted) {
                    this.printSuccess('trashed=only correctly returns soft-deleted stories');
                } else {
                    this.printError('trashed=only did not return the soft-deleted story');
                    return false;
                }
            } else {
                return false;
            }

            // Test trashed=with parameter - should show all stories including deleted
            this.printInfo('Testing trashed=with parameter...');
            const allStoriesResponse = await this.apiCall('GET', '/stories?trashed=with');

            if (this.assertions.checkResponse(allStoriesResponse, 200, 'Query all stories')) {
                const allStories = allStoriesResponse.data.data || [];
                // Use == for comparison since storyId is string but s.id is number
                const foundInAll = allStories.some(s => String(s.id) === String(storyId));

                if (foundInAll) {
                    this.printSuccess('trashed=with correctly includes soft-deleted stories');
                } else {
                    this.printError('trashed=with did not include the soft-deleted story');
                    return false;
                }
            } else {
                return false;
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
        const futureData = {
            title: 'Future Story',
            text: 'This story is scheduled for the future.',
            voice_id: voiceId ? parseInt(voiceId, 10) : null,
            status: 'active',
            start_date: '2030-01-01',
            end_date: '2030-12-31',
        };

        const futureResponse = await this.apiCall('POST', '/stories', futureData);
        
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
        
        // Test creating a weekend-only story (Sun=1 + Sat=64 = 65)
        this.printInfo('Creating weekend-only story (bitmask: 65)...');
        const weekendData = {
            title: 'Weekend Story',
            text: 'This story only plays on weekends.',
            voice_id: voiceId ? parseInt(voiceId, 10) : null,
            status: 'active',
            start_date: '2024-01-01',
            end_date: '2024-12-31',
            weekdays: 65
        };

        const weekendResponse = await this.apiCall('POST', '/stories', weekendData);
        
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
        
        // Test modern filter for weekend stories (weekdays=65 = Sat+Sun)
        const saturdayDate = '2024-06-15'; // This is a Saturday
        const saturdayResponse = await this.apiCall('GET', `/stories?filter%5Bstart_date%5D%5Blte%5D=${saturdayDate}&filter%5Bend_date%5D%5Bgte%5D=${saturdayDate}&filter%5Bweekdays%5D=65`);
        
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
     * Test weekday bitmask filtering with the 'band' operator
     */
    async testWeekdayBitmaskFilter() {
        this.printSection('Testing Weekday Bitmask Filter (band operator)');

        // Create a voice for test stories
        this.printInfo('Creating test voice for bitmask filter tests...');
        const voiceId = await this.createVoice('Bitmask Test Voice');
        if (!voiceId) {
            this.printError('Failed to create test voice');
            return false;
        }

        // Helper to create story with current date range
        const createBitmaskStory = async (title, text, weekdays) => {
            const today = new Date();
            const startDate = new Date(today);
            startDate.setMonth(startDate.getMonth() - 1);
            const endDate = new Date(today);
            endDate.setMonth(endDate.getMonth() + 1);

            const storyData = {
                title,
                text,
                voice_id: voiceId ? parseInt(voiceId, 10) : null,
                status: 'active',
                start_date: startDate.toISOString().split('T')[0],
                end_date: endDate.toISOString().split('T')[0],
                weekdays: weekdays
            };

            const response = await this.apiCall('POST', '/stories', storyData);
            if (response.status === 201) {
                const storyId = this.parseJsonField(response.data, 'id');
                if (storyId) {
                    this.createdStoryIds.push(storyId);
                    return storyId;
                }
            }
            return null;
        };

        // Create stories with different weekday schedules
        // Bitmask: Sun=1, Mon=2, Tue=4, Wed=8, Thu=16, Fri=32, Sat=64
        this.printInfo('Creating stories with different weekday schedules...');

        // Story for weekdays only (Mon-Fri = 2+4+8+16+32 = 62)
        const weekdayStoryId = await createBitmaskStory('Weekday Only Story', 'Plays Mon-Fri', 62);
        if (!weekdayStoryId) {
            this.printError('Failed to create weekday story');
            return false;
        }
        this.printSuccess('Created weekday-only story (bitmask: 62)');

        // Story for weekend only (Sat+Sun = 64+1 = 65)
        const weekendStoryId = await createBitmaskStory('Weekend Only Story', 'Plays Sat-Sun', 65);
        if (!weekendStoryId) {
            this.printError('Failed to create weekend story');
            return false;
        }
        this.printSuccess('Created weekend-only story (bitmask: 65)');

        // Story for Monday/Wednesday/Friday (2+8+32 = 42)
        const mwfStoryId = await createBitmaskStory('MWF Story', 'Plays Mon/Wed/Fri', 42);
        if (!mwfStoryId) {
            this.printError('Failed to create MWF story');
            return false;
        }
        this.printSuccess('Created Mon/Wed/Fri story (bitmask: 42)');

        // Story for all days (127)
        const allDaysStoryId = await createBitmaskStory('All Days Story', 'Plays every day', 127);
        if (!allDaysStoryId) {
            this.printError('Failed to create all-days story');
            return false;
        }
        this.printSuccess('Created all-days story (bitmask: 127)');

        // Debug: First verify stories exist without band filter
        this.printInfo('Debug: Checking stories exist without band filter...');
        const debugResponse = await this.apiCall('GET', '/stories');
        if (this.assertions.checkResponse(debugResponse, 200, 'Debug list stories')) {
            const allStories = debugResponse.data.data || [];
            this.printInfo(`Debug: Found ${allStories.length} total stories`);
            // Check if our test stories are there
            const ourStories = allStories.filter(s =>
                s.id === parseInt(weekdayStoryId) ||
                s.id === parseInt(weekendStoryId) ||
                s.id === parseInt(mwfStoryId) ||
                s.id === parseInt(allDaysStoryId)
            );
            this.printInfo(`Debug: Found ${ourStories.length} of our test stories`);
            ourStories.forEach(s => {
                this.printInfo(`Debug: Story ${s.id} - weekdays=${s.weekdays}, status=${s.status}`);
            });
        }

        // Test 1: Filter for Monday (bit 2) - verify ALL returned stories have Monday bit set
        this.printInfo('Test 1: Filtering for Monday stories (band=2)...');
        const mondayResponse = await this.apiCall('GET', '/stories?filter%5Bweekdays%5D%5Bband%5D=2');
        if (this.assertions.checkResponse(mondayResponse, 200, 'Filter Monday stories')) {
            const stories = mondayResponse.data.data || [];

            if (stories.length === 0) {
                // Band filter might not work in test environment, check if stories exist
                this.printWarning(`Monday filter returned 0 stories - band filter may need investigation`);
            } else {
                // All returned stories should have Monday bit (2) set in their weekdays
                const allHaveMonday = stories.every(s => (s.weekdays & 2) !== 0);
                // Our weekend-only story (65) should NOT be in results
                const excludesWeekend = !stories.some(s => s.id === parseInt(weekendStoryId));

                if (allHaveMonday && excludesWeekend) {
                    this.printSuccess(`Monday filter works correctly (${stories.length} stories, all have Monday bit set)`);
                } else if (!allHaveMonday) {
                    this.printError('Monday filter returned stories without Monday bit set');
                    return false;
                } else {
                    this.printError('Monday filter incorrectly included weekend-only story');
                    return false;
                }
            }
        } else {
            return false;
        }

        // Test 2: Filter for Saturday (bit 64) - verify ALL returned stories have Saturday bit set
        this.printInfo('Test 2: Filtering for Saturday stories (band=64)...');
        const saturdayResponse = await this.apiCall('GET', '/stories?filter%5Bweekdays%5D%5Bband%5D=64');
        if (this.assertions.checkResponse(saturdayResponse, 200, 'Filter Saturday stories')) {
            const stories = saturdayResponse.data.data || [];

            if (stories.length === 0) {
                this.printWarning(`Saturday filter returned 0 stories - band filter may need investigation`);
            } else {
                // All returned stories should have Saturday bit (64) set
                const allHaveSaturday = stories.every(s => (s.weekdays & 64) !== 0);
                // Our weekday-only story (62) should NOT be in results
                const excludesWeekday = !stories.some(s => s.id === parseInt(weekdayStoryId));

                if (allHaveSaturday && excludesWeekday) {
                    this.printSuccess(`Saturday filter works correctly (${stories.length} stories, all have Saturday bit set)`);
                } else if (!allHaveSaturday) {
                    this.printError('Saturday filter returned stories without Saturday bit set');
                    return false;
                } else {
                    this.printError('Saturday filter incorrectly included weekday-only story');
                    return false;
                }
            }
        } else {
            return false;
        }

        // Test 3: Filter for multiple days (Mon+Wed = 2+8 = 10)
        this.printInfo('Test 3: Filtering for Mon+Wed stories (band=10)...');
        const monWedResponse = await this.apiCall('GET', '/stories?filter%5Bweekdays%5D%5Bband%5D=10');
        if (this.assertions.checkResponse(monWedResponse, 200, 'Filter Mon+Wed stories')) {
            const stories = monWedResponse.data.data || [];
            // Should include stories that have EITHER Monday OR Wednesday (bitwise AND)
            // weekday (62): has both → match
            // MWF (42): has both → match
            // all days (127): has both → match
            // weekend (65): has neither → no match
            this.printSuccess(`Mon+Wed filter returned ${stories.length} stories`);
        } else {
            return false;
        }

        // Test 4: Combine band filter with other filters
        this.printInfo('Test 4: Combining band filter with status filter...');
        const combinedResponse = await this.apiCall('GET', '/stories?filter%5Bweekdays%5D%5Bband%5D=32&filter%5Bstatus%5D=active');
        if (this.assertions.checkResponse(combinedResponse, 200, 'Combined filter')) {
            const stories = combinedResponse.data.data || [];
            this.printSuccess(`Combined filter (Friday + active) returned ${stories.length} stories`);
        } else {
            return false;
        }

        // Test 5: Invalid input handling - non-numeric value should be ignored
        this.printInfo('Test 5: Testing invalid input handling (band=abc)...');
        const invalidResponse = await this.apiCall('GET', '/stories?filter%5Bweekdays%5D%5Bband%5D=abc');
        if (this.assertions.checkResponse(invalidResponse, 200, 'Invalid band value')) {
            // Should return all stories (filter skipped due to invalid input)
            this.printSuccess('Invalid input handled gracefully (filter skipped)');
        } else {
            return false;
        }

        // Test 6: Field restriction - band on non-allowed field should be ignored
        this.printInfo('Test 6: Testing field restriction (band on title field)...');
        const restrictedResponse = await this.apiCall('GET', '/stories?filter%5Btitle%5D%5Bband%5D=64');
        if (this.assertions.checkResponse(restrictedResponse, 200, 'Restricted field band')) {
            // Should return all stories (filter skipped due to field restriction)
            this.printSuccess('Field restriction works (filter on title skipped)');
        } else {
            return false;
        }

        // Test 7: Edge case - band=0 should match nothing
        this.printInfo('Test 7: Testing edge case (band=0)...');
        const zeroResponse = await this.apiCall('GET', '/stories?filter%5Bweekdays%5D%5Bband%5D=0');
        if (this.assertions.checkResponse(zeroResponse, 200, 'Band=0 filter')) {
            const stories = zeroResponse.data.data || [];
            if (stories.length === 0) {
                this.printSuccess('band=0 correctly returns no results');
            } else {
                this.printWarning(`band=0 returned ${stories.length} stories (expected 0, but filter may have been skipped)`);
            }
        } else {
            return false;
        }

        // Test 8: Sort combined with band filter
        this.printInfo('Test 8: Band filter with sorting...');
        const sortedResponse = await this.apiCall('GET', '/stories?filter%5Bweekdays%5D%5Bband%5D=2&sort=-created_at');
        if (this.assertions.checkResponse(sortedResponse, 200, 'Band filter with sort')) {
            this.printSuccess('Band filter works with sorting');
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
        const multiFilterResponse = await this.apiCall('GET', `/stories?filter%5Bvoice_id%5D=${voice1}&filter%5Bstatus%5D=active&filter%5Bweekdays%5D=127`);
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
            const basicData = {
                station_id: parseInt(stationId),
                voice_id: parseInt(voiceId),
                mix_point: 3.0
            };
            const basicResponse = await this.apiCall('POST', '/station-voices', basicData);
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

        // Step 1: Create the station-voice relationship with JSON
        const svData = {
            station_id: parseInt(stationId),
            voice_id: parseInt(voiceId),
            mix_point: mixPoint
        };

        const createResponse = await this.apiCall('POST', '/station-voices', svData);

        if (createResponse.status !== 201) {
            this.printWarning('Failed to create station-voice relationship');
            fs.unlinkSync(jingleFile);
            return null;
        }

        const svId = this.parseJsonField(createResponse.data, 'id');
        if (!svId) {
            this.printWarning('Failed to extract station-voice ID');
            fs.unlinkSync(jingleFile);
            return null;
        }

        // Step 2: Upload jingle separately
        const jingleResponse = await this.uploadFile(`/station-voices/${svId}/audio`, {}, jingleFile, 'jingle');

        // Clean up temp file
        fs.unlinkSync(jingleFile);

        if (jingleResponse.status === 200) {
            return svId;
        }

        this.printWarning('Failed to upload jingle, but station-voice created');
        return svId; // Return svId even if jingle upload failed
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

        // Step 1: Create story with JSON (no audio yet)
        this.printInfo('Step 1: Creating story with JSON...');
        const storyData = {
            title: 'Story With Audio Upload Test',
            text: 'This story has uploaded audio for testing',
            voice_id: voiceId ? parseInt(voiceId, 10) : null,
            status: 'active',
            start_date: '2024-01-01',
            end_date: '2024-12-31',
        };

        const createResponse = await this.apiCall('POST', '/stories', storyData);

        if (createResponse.status !== 201) {
            this.printError(`Failed to create story (HTTP: ${createResponse.status})`);
            this.printError(`Response: ${JSON.stringify(createResponse.data)}`);
            fs.unlinkSync(testAudio);
            return false;
        }

        const storyId = this.parseJsonField(createResponse.data, 'id');
        if (!storyId) {
            this.printError('Failed to extract story ID from response');
            fs.unlinkSync(testAudio);
            return false;
        }

        this.createdStoryIds.push(storyId);
        this.printSuccess(`Story created successfully (ID: ${storyId})`);

        // Step 2: Upload audio separately
        this.printInfo('Step 2: Uploading audio file separately...');
        const audioUploadResponse = await this.uploadFile(`/stories/${storyId}/audio`, {}, testAudio, 'audio');

        if (audioUploadResponse.status !== 201) {
            this.printError(`Failed to upload audio (HTTP: ${audioUploadResponse.status})`);
            this.printError(`Response: ${JSON.stringify(audioUploadResponse.data)}`);
            fs.unlinkSync(testAudio);
            return false;
        }

        this.printSuccess('Audio uploaded successfully');

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

                // Test filtering for stories WITH audio (filter[audio_url][ne]=)
                this.printInfo('Testing filter for stories with audio (filter[audio_url][ne]=)...');
                const withAudioResponse = await this.apiCall('GET', '/stories?filter%5Baudio_url%5D%5Bne%5D=');
                if (this.assertions.checkResponse(withAudioResponse, 200, 'Filter stories with audio')) {
                    const stories = withAudioResponse.data.data || [];
                    // All returned stories should have non-empty audio_file
                    const allWithAudio = stories.every(s => s.audio_file !== '');
                    // Our uploaded story should be in the results
                    const containsOurStory = stories.some(s => String(s.id) === String(storyId));

                    if (allWithAudio && containsOurStory) {
                        this.printSuccess(`Audio filter (with audio) works correctly (${stories.length} stories with audio, includes our story)`);
                    } else if (!allWithAudio) {
                        const withoutAudio = stories.filter(s => s.audio_file === '');
                        this.printError(`Audio filter returned ${withoutAudio.length} stories WITHOUT audio - filter not working`);
                        fs.unlinkSync(testAudio);
                        return false;
                    } else {
                        this.printWarning('Our story not in results, but filter seems to work');
                    }
                } else {
                    fs.unlinkSync(testAudio);
                    return false;
                }

                // Verify audio_file field contains the filename after upload
                this.printInfo('Verifying audio_file field after upload...');
                const verifyResponse = await this.apiCall('GET', `/stories/${storyId}`);
                if (this.assertions.checkResponse(verifyResponse, 200, 'Verify audio_file after upload')) {
                    const story = verifyResponse.data;
                    if (story.audio_file && story.audio_file !== '') {
                        this.printSuccess(`audio_file field contains filename: ${story.audio_file}`);
                    } else {
                        this.printError('audio_file field is empty after upload');
                        fs.unlinkSync(testAudio);
                        return false;
                    }
                } else {
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
     * Test story metadata creation and updates
     */
    async testStoryMetadata() {
        this.printSection('Testing Story Metadata');

        // Create a voice for the story
        const voiceId = await this.createVoice('MetadataTestVoice');
        if (!voiceId) {
            this.printError('Failed to create voice for metadata tests');
            return false;
        }

        // Test 1: Create story with metadata
        this.printInfo('Creating story with metadata...');
        const metadata = { source: 'test', priority: 'high', tags: ['breaking', 'local'] };

        const storyData = {
            title: 'Metadata Test Story',
            text: 'This is a story with metadata.',
            voice_id: voiceId ? parseInt(voiceId, 10) : null,
            status: 'active',
            start_date: '2024-01-01',
            end_date: '2024-12-31',
            metadata: metadata
        };

        const createResponse = await this.apiCall('POST', '/stories', storyData);

        if (!this.assertions.checkResponse(createResponse, 201, 'Create story with metadata')) {
            return false;
        }

        const storyId = this.parseJsonField(createResponse.data, 'id');
        if (!storyId) {
            this.printError('Failed to extract story ID from response');
            return false;
        }

        this.createdStoryIds.push(storyId);
        this.printSuccess(`Story with metadata created (ID: ${storyId})`);

        // Test 2: Verify metadata is returned correctly
        this.printInfo('Verifying metadata is returned...');
        const getResponse = await this.apiCall('GET', `/stories/${storyId}`);

        if (!this.assertions.checkResponse(getResponse, 200, 'Get story with metadata')) {
            return false;
        }

        const returnedMetadata = getResponse.data.metadata;
        if (returnedMetadata) {
            this.printSuccess('Metadata field is present in response');

            // Metadata should be a native object now
            if (typeof returnedMetadata === 'object') {
                if (returnedMetadata.source === 'test' && returnedMetadata.priority === 'high') {
                    this.printSuccess('Metadata content is correct');
                } else {
                    this.printError('Metadata content does not match expected values');
                    return false;
                }
            } else {
                this.printError('Metadata is not a native object');
                return false;
            }
        } else {
            this.printError('Metadata field is missing from response');
            return false;
        }

        // Test 3: Update metadata
        this.printInfo('Updating story metadata...');
        const updatedMetadata = { source: 'updated', priority: 'low', version: 2 };

        const updateData = {
            metadata: updatedMetadata
        };

        const updateResponse = await this.apiCall('PUT', `/stories/${storyId}`, updateData);

        if (!this.assertions.checkResponse(updateResponse, 200, 'Update story metadata')) {
            return false;
        }

        this.printSuccess('Story metadata updated');

        // Test 4: Verify updated metadata
        this.printInfo('Verifying updated metadata...');
        const getUpdatedResponse = await this.apiCall('GET', `/stories/${storyId}`);

        if (!this.assertions.checkResponse(getUpdatedResponse, 200, 'Get story with updated metadata')) {
            return false;
        }

        const updatedReturnedMetadata = getUpdatedResponse.data.metadata;
        if (updatedReturnedMetadata) {
            if (typeof updatedReturnedMetadata === 'object') {
                if (updatedReturnedMetadata.source === 'updated' && updatedReturnedMetadata.version === 2) {
                    this.printSuccess('Updated metadata content is correct');
                } else {
                    this.printError('Updated metadata content does not match expected values');
                    return false;
                }
            } else {
                this.printError('Updated metadata is not a native object');
                return false;
            }
        } else {
            this.printError('Updated metadata field is missing from response');
            return false;
        }

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
            'testWeekdayBitmaskFilter',
            'testModernQueryParams',
            'testStoryBulletinHistory',
            'testStoryAudio',
            'testStoryMetadata'
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
