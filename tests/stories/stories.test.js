/**
 * Babbel stories tests.
 * Tests story management functionality including CRUD operations, scheduling, and file uploads.
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

    test('retrieves story by ID', async () => {
      const response = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(response.status).toBe(200);
      expect(response.data.title).toContain('CRUD Test Story');
    });

    test('updates story title and text', async () => {
      const response = await global.api.apiCall('PUT', `/stories/${storyId}`, {
        title: 'Updated CRUD Story',
        text: 'Updated content'
      });

      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(getResponse.data.title).toBe('Updated CRUD Story');
    });

    test('returns 404 for non-existent story', async () => {
      const response = await global.api.apiCall('GET', '/stories/999999');
      expect(response.status).toBe(404);
    });
  });

  describe('Story Soft Delete', () => {
    test('soft deletes story', async () => {
      const result = await createStoryWithDeps('DeleteTest', 'To be deleted', 'DeleteVoice', 'DeleteStation');
      expect(result).not.toBeNull();

      const response = await global.api.apiCall('DELETE', `/stories/${result.id}`);
      expect(response.status).toBe(204);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.status).toBe(404);
    });

    test('trashed=only returns soft-deleted stories', async () => {
      const result = await createStoryWithDeps('TrashedOnly', 'To be trashed', 'TrashVoice1', 'TrashStation1');
      await global.api.apiCall('DELETE', `/stories/${result.id}`);

      const response = await global.api.apiCall('GET', '/stories?trashed=only');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      const found = stories.some(s => String(s.id) === String(result.id));
      expect(found).toBe(true);
    });

    test('trashed=with includes soft-deleted stories', async () => {
      const result = await createStoryWithDeps('TrashedWith', 'To be trashed', 'TrashVoice2', 'TrashStation2');
      await global.api.apiCall('DELETE', `/stories/${result.id}`);

      const response = await global.api.apiCall('GET', '/stories?trashed=with');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      const found = stories.some(s => String(s.id) === String(result.id));
      expect(found).toBe(true);
    });
  });

  describe('Story Scheduling', () => {
    let voiceId, stationId;

    beforeAll(async () => {
      const voice = await global.helpers.createVoice(global.resources, 'ScheduleVoice');
      const station = await global.helpers.createStation(global.resources, 'ScheduleStation');
      voiceId = voice.id;
      stationId = station.id;
    });

    test('creates future-dated story', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: `Future Story ${Date.now()}`,
        text: 'Scheduled for future',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2030-01-01',
        end_date: '2030-12-31',
        weekdays: 127,
        target_stations: [parseInt(stationId, 10)]
      });

      expect(response.status).toBe(201);
      global.resources.track('stories', response.data.id);
    });

    test('creates weekend-only story (weekdays=65)', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: `Weekend Story ${Date.now()}`,
        text: 'Weekend only',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 65, // Sun=1 + Sat=64
        target_stations: [parseInt(stationId, 10)]
      });

      expect(response.status).toBe(201);
      global.resources.track('stories', response.data.id);
    });

    test('updates weekday schedule', async () => {
      const result = await createStoryWithDeps('WeekdayUpdate', 'Test', 'WkdyVoice', 'WkdyStation');
      expect(result).not.toBeNull();

      const response = await global.api.apiCall('PUT', `/stories/${result.id}`, { weekdays: 42 }); // MWF
      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.data.weekdays).toBe(42);
    });
  });

  describe('Station Targeting', () => {
    let voiceId, station1Id, station2Id;

    beforeAll(async () => {
      const voice = await global.helpers.createVoice(global.resources, 'TargetVoice');
      const station1 = await global.helpers.createStation(global.resources, 'Target1');
      const station2 = await global.helpers.createStation(global.resources, 'Target2');
      voiceId = voice.id;
      station1Id = station1.id;
      station2Id = station2.id;
    });

    test('creates story with multiple target_stations', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: `Multi-Target ${Date.now()}`,
        text: 'Targets multiple stations',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 127,
        target_stations: [parseInt(station1Id, 10), parseInt(station2Id, 10)]
      });

      expect(response.status).toBe(201);
      global.resources.track('stories', response.data.id);

      // Verify target_stations if returned in response
      const getResponse = await global.api.apiCall('GET', `/stories/${response.data.id}`);
      expect(getResponse.status).toBe(200);
      if (getResponse.data.target_stations) {
        expect(getResponse.data.target_stations).toContain(parseInt(station1Id, 10));
        expect(getResponse.data.target_stations).toContain(parseInt(station2Id, 10));
      }
    });

    test('rejects story without target_stations', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'No Targets',
        text: 'Missing target stations',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        weekdays: 127
      });

      expect([400, 422]).toContain(response.status);
    });

    test('rejects story with empty target_stations', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Empty Targets',
        text: 'Empty array',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        weekdays: 127,
        target_stations: []
      });

      expect([400, 422]).toContain(response.status);
    });

    test('rejects story with invalid station ID', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Invalid Station',
        text: 'Non-existent station',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        weekdays: 127,
        target_stations: [999999]
      });

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

    test('uploads and verifies audio', async () => {
      if (!fs.existsSync(testAudio)) {
        console.log('Skipping audio test - ffmpeg not available');
        return;
      }

      const result = await createStoryWithDeps('AudioUpload', 'Has audio', 'AudioVoice', 'AudioStation');
      expect(result).not.toBeNull();

      const uploadResponse = await global.api.uploadFile(`/stories/${result.id}/audio`, {}, testAudio, 'audio');
      expect(uploadResponse.status).toBe(201);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.data.audio_file).not.toBe('');
    });

    test('audio_url and audio_file fields present', async () => {
      const result = await createStoryWithDeps('AudioFields', 'Check fields', 'FieldsVoice', 'FieldsStation');
      expect(result).not.toBeNull();

      const response = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(response.data).toHaveProperty('audio_url');
      expect(response.data).toHaveProperty('audio_file');
    });
  });

  describe('Story Metadata', () => {
    test('creates story with metadata', async () => {
      const voice = await global.helpers.createVoice(global.resources, 'MetaVoice');
      const station = await global.helpers.createStation(global.resources, 'MetaStation');

      const response = await global.api.apiCall('POST', '/stories', {
        title: `Metadata Story ${Date.now()}`,
        text: 'Story with metadata',
        voice_id: parseInt(voice.id, 10),
        status: 'active',
        weekdays: 127,
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        target_stations: [parseInt(station.id, 10)],
        metadata: { source: 'test', priority: 'high' }
      });

      expect(response.status).toBe(201);
      global.resources.track('stories', response.data.id);

      const getResponse = await global.api.apiCall('GET', `/stories/${response.data.id}`);
      expect(getResponse.data.metadata.source).toBe('test');
    });

    test('updates metadata', async () => {
      const result = await createStoryWithDeps('UpdateMeta', 'For update', 'MetaUpdVoice', 'MetaUpdStation');
      expect(result).not.toBeNull();

      const response = await global.api.apiCall('PUT', `/stories/${result.id}`, {
        metadata: { source: 'updated', version: 2 }
      });

      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.data.metadata.source).toBe('updated');
      expect(getResponse.data.metadata.version).toBe(2);
    });
  });

  describe('Status Filtering', () => {
    test('filters by status', async () => {
      await createStoryWithDeps('ActiveStory', 'Active', 'StatVoice1', 'StatStation1', 127, 'active');
      await createStoryWithDeps('DraftStory', 'Draft', 'StatVoice2', 'StatStation2', 127, 'draft');

      const response = await global.api.apiCall('GET', '/stories?filter[status]=active');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      const allActive = stories.every(s => s.status === 'active');
      expect(allActive).toBe(true);
    });
  });
});
