/**
 * Babbel stories tests.
 * Tests story management functionality including CRUD operations, scheduling, and file uploads.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

const fs = require('fs');
const { execSync } = require('child_process');
const storiesSchema = require('../lib/schemas/stories.schema');
const { generateQueryTests } = require('../lib/generators');

describe('Stories', () => {
  // Shared helpers
  const createStoryWithDeps = async (title, text, voiceName, stationName, weekdays = 127, status = 'active') => {
    const voice = await global.helpers.createVoice(global.resources, voiceName);
    const station = await global.helpers.createStation(global.resources, stationName);

    const result = await global.helpers.createStory(global.resources, {
      title,
      text,
      voice_id: voice.id,
      weekdays,
      status
    }, [parseInt(station.id, 10)]);

    return result ? { id: result.id, voiceId: voice.id, stationId: station.id } : null;
  };

  // Setup function for query tests
  const setupQueryTestData = async () => {
    const ids = [];
    for (let i = 1; i <= 3; i++) {
      const result = await createStoryWithDeps(
        `QueryStory${i}`,
        `Query test content ${i}`,
        `QueryVoice${i}`,
        `QueryStation${i}`
      );
      if (result) ids.push(result.id);
    }
    return ids;
  };

  // Generate query parameter tests
  generateQueryTests(storiesSchema, setupQueryTestData);

  // === BUSINESS LOGIC TESTS ===

  describe('Story CRUD', () => {
    let voiceId, stationId, storyId;

    beforeAll(async () => {
      // Arrange: Create dependencies
      const voice = await global.helpers.createVoice(global.resources, 'CrudTestVoice');
      const station = await global.helpers.createStation(global.resources, 'CrudTestStation');
      voiceId = voice.id;
      stationId = station.id;

      const story = await global.helpers.createStory(global.resources, {
        title: 'CRUD Test Story',
        text: 'Initial content',
        voice_id: voiceId,
        weekdays: 127,
        status: 'active'
      }, [parseInt(stationId, 10)]);
      storyId = story.id;
    });

    test('when fetching story by ID, then returns story', async () => {
      // Act
      const response = await global.api.apiCall('GET', `/stories/${storyId}`);

      // Assert
      expect(response.status).toBe(200);
      expect(response.data.title).toContain('CRUD Test Story');
    });

    test('when updating title and text, then persists changes', async () => {
      // Act
      const response = await global.api.apiCall('PUT', `/stories/${storyId}`, {
        title: 'Updated CRUD Story',
        text: 'Updated content'
      });

      // Assert
      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(getResponse.data.title).toBe('Updated CRUD Story');
    });

    test('when fetching non-existent story, then returns 404', async () => {
      // Act
      const response = await global.api.apiCall('GET', '/stories/999999');

      // Assert
      expect(response.status).toBe(404);
    });
  });

  describe('Story Soft Delete', () => {
    test('when deleting story, then soft deleted', async () => {
      // Arrange
      const result = await createStoryWithDeps('DeleteTest', 'To be deleted', 'DeleteVoice', 'DeleteStation');
      expect(result).not.toBeNull();

      // Act
      const response = await global.api.apiCall('DELETE', `/stories/${result.id}`);

      // Assert
      expect(response.status).toBe(204);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.status).toBe(404);
    });

    test('when trashed=only, then returns soft-deleted stories', async () => {
      // Arrange
      const result = await createStoryWithDeps('TrashedOnly', 'To be trashed', 'TrashVoice1', 'TrashStation1');
      await global.api.apiCall('DELETE', `/stories/${result.id}`);

      // Act
      const response = await global.api.apiCall('GET', '/stories?trashed=only');

      // Assert
      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      const found = stories.some(s => String(s.id) === String(result.id));
      expect(found).toBe(true);
    });

    test('when trashed=with, then includes soft-deleted stories', async () => {
      // Arrange
      const result = await createStoryWithDeps('TrashedWith', 'To be trashed', 'TrashVoice2', 'TrashStation2');
      await global.api.apiCall('DELETE', `/stories/${result.id}`);

      // Act
      const response = await global.api.apiCall('GET', '/stories?trashed=with');

      // Assert
      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      const found = stories.some(s => String(s.id) === String(result.id));
      expect(found).toBe(true);
    });
  });

  describe('Story Scheduling', () => {
    let voiceId, stationId;

    beforeAll(async () => {
      // Arrange: Create dependencies
      const voice = await global.helpers.createVoice(global.resources, 'ScheduleVoice');
      const station = await global.helpers.createStation(global.resources, 'ScheduleStation');
      voiceId = voice.id;
      stationId = station.id;
    });

    test('when creating future-dated story, then accepted', async () => {
      // Arrange
      const storyData = {
        title: `Future Story ${Date.now()}`,
        text: 'Scheduled for future',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2030-01-01',
        end_date: '2030-12-31',
        weekdays: 127,
        target_stations: [parseInt(stationId, 10)]
      };

      // Act
      const response = await global.api.apiCall('POST', '/stories', storyData);

      // Assert
      expect(response.status).toBe(201);

      // Cleanup
      global.resources.track('stories', response.data.id);
    });

    test('when creating weekend-only story, then accepted', async () => {
      // Arrange: weekdays=65 means Sun=1 + Sat=64
      const storyData = {
        title: `Weekend Story ${Date.now()}`,
        text: 'Weekend only',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 65,
        target_stations: [parseInt(stationId, 10)]
      };

      // Act
      const response = await global.api.apiCall('POST', '/stories', storyData);

      // Assert
      expect(response.status).toBe(201);

      // Cleanup
      global.resources.track('stories', response.data.id);
    });

    test('when updating weekday schedule, then persisted', async () => {
      // Arrange
      const result = await createStoryWithDeps('WeekdayUpdate', 'Test', 'WkdyVoice', 'WkdyStation');
      expect(result).not.toBeNull();

      // Act: Update to MWF (weekdays=42)
      const response = await global.api.apiCall('PUT', `/stories/${result.id}`, { weekdays: 42 });

      // Assert
      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.data.weekdays).toBe(42);
    });
  });

  describe('Station Targeting', () => {
    let voiceId, station1Id, station2Id;

    beforeAll(async () => {
      // Arrange: Create dependencies
      const voice = await global.helpers.createVoice(global.resources, 'TargetVoice');
      const station1 = await global.helpers.createStation(global.resources, 'Target1');
      const station2 = await global.helpers.createStation(global.resources, 'Target2');
      voiceId = voice.id;
      station1Id = station1.id;
      station2Id = station2.id;
    });

    test('when creating with multiple target_stations, then all assigned', async () => {
      // Arrange
      const storyData = {
        title: `Multi-Target ${Date.now()}`,
        text: 'Targets multiple stations',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 127,
        target_stations: [parseInt(station1Id, 10), parseInt(station2Id, 10)]
      };

      // Act
      const response = await global.api.apiCall('POST', '/stories', storyData);

      // Assert
      expect(response.status).toBe(201);

      // Cleanup
      global.resources.track('stories', response.data.id);

      // Verify target_stations if returned in response
      const getResponse = await global.api.apiCall('GET', `/stories/${response.data.id}`);
      expect(getResponse.status).toBe(200);
      if (getResponse.data.target_stations) {
        expect(getResponse.data.target_stations).toContain(parseInt(station1Id, 10));
        expect(getResponse.data.target_stations).toContain(parseInt(station2Id, 10));
      }
    });

    test('when target_stations missing, then rejected', async () => {
      // Arrange
      const storyData = {
        title: 'No Targets',
        text: 'Missing target stations',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        weekdays: 127
      };

      // Act
      const response = await global.api.apiCall('POST', '/stories', storyData);

      // Assert
      expect([400, 422]).toContain(response.status);
    });

    test('when target_stations empty array, then rejected', async () => {
      // Arrange
      const storyData = {
        title: 'Empty Targets',
        text: 'Empty array',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        weekdays: 127,
        target_stations: []
      };

      // Act
      const response = await global.api.apiCall('POST', '/stories', storyData);

      // Assert
      expect([400, 422]).toContain(response.status);
    });

    test('when target_stations has invalid ID, then rejected', async () => {
      // Arrange
      const storyData = {
        title: 'Invalid Station',
        text: 'Non-existent station',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        weekdays: 127,
        target_stations: [999999]
      };

      // Act
      const response = await global.api.apiCall('POST', '/stories', storyData);

      // Assert
      expect([404, 422]).toContain(response.status);
    });
  });

  describe('Story Audio', () => {
    const testAudio = '/tmp/test_story_audio.wav';

    beforeAll(async () => {
      try {
        execSync(`ffmpeg -f lavfi -i anullsrc=r=44100:cl=stereo -t 2 -f wav "${testAudio}" -y 2>/dev/null`, { stdio: 'ignore' });
      } catch {
        // ffmpeg not available
      }
    });

    afterAll(() => {
      if (fs.existsSync(testAudio)) fs.unlinkSync(testAudio);
    });

    test('when uploading audio, then attached to story', async () => {
      // Skip if ffmpeg not available
      if (!fs.existsSync(testAudio)) {
        console.log('Skipping audio test - ffmpeg not available');
        return;
      }

      // Arrange
      const result = await createStoryWithDeps('AudioUpload', 'Has audio', 'AudioVoice', 'AudioStation');
      expect(result).not.toBeNull();

      // Act
      const uploadResponse = await global.api.uploadFile(`/stories/${result.id}/audio`, {}, testAudio, 'audio');

      // Assert
      expect(uploadResponse.status).toBe(201);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.data.audio_file).not.toBe('');
    });

    test('when fetching story, then audio fields present', async () => {
      // Arrange
      const result = await createStoryWithDeps('AudioFields', 'Check fields', 'FieldsVoice', 'FieldsStation');
      expect(result).not.toBeNull();

      // Act
      const response = await global.api.apiCall('GET', `/stories/${result.id}`);

      // Assert
      expect(response.data).toHaveProperty('audio_url');
      expect(response.data).toHaveProperty('audio_file');
    });
  });

  describe('Story Metadata', () => {
    test('when creating with metadata, then stored', async () => {
      // Arrange
      const voice = await global.helpers.createVoice(global.resources, 'MetaVoice');
      const station = await global.helpers.createStation(global.resources, 'MetaStation');

      const storyData = {
        title: `Metadata Story ${Date.now()}`,
        text: 'Story with metadata',
        voice_id: parseInt(voice.id, 10),
        status: 'active',
        weekdays: 127,
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        target_stations: [parseInt(station.id, 10)],
        metadata: { source: 'test', priority: 'high' }
      };

      // Act
      const response = await global.api.apiCall('POST', '/stories', storyData);

      // Assert
      expect(response.status).toBe(201);

      // Cleanup
      global.resources.track('stories', response.data.id);

      const getResponse = await global.api.apiCall('GET', `/stories/${response.data.id}`);
      expect(getResponse.data.metadata.source).toBe('test');
    });

    test('when updating metadata, then persisted', async () => {
      // Arrange
      const result = await createStoryWithDeps('UpdateMeta', 'For update', 'MetaUpdVoice', 'MetaUpdStation');
      expect(result).not.toBeNull();

      // Act
      const response = await global.api.apiCall('PUT', `/stories/${result.id}`, {
        metadata: { source: 'updated', version: 2 }
      });

      // Assert
      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.data.metadata.source).toBe('updated');
      expect(getResponse.data.metadata.version).toBe(2);
    });
  });

  describe('Status Filtering', () => {
    test('when filtering by status, then returns matching', async () => {
      // Arrange
      await createStoryWithDeps('ActiveStory', 'Active', 'StatVoice1', 'StatStation1', 127, 'active');
      await createStoryWithDeps('DraftStory', 'Draft', 'StatVoice2', 'StatStation2', 127, 'draft');

      // Act
      const response = await global.api.apiCall('GET', '/stories?filter[status]=active');

      // Assert
      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      const allActive = stories.every(s => s.status === 'active');
      expect(allActive).toBe(true);
    });
  });
});
