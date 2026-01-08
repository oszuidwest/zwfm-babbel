/**
 * Babbel stories tests.
 * Tests story management functionality including CRUD operations and file uploads.
 */

const fs = require('fs');
const { execSync } = require('child_process');

describe('Stories', () => {
  // Helpers
  const createVoice = async (name) => {
    const result = await global.helpers.createVoice(global.resources, name);
    return result ? result.id : null;
  };

  const createStation = async (name) => {
    const result = await global.helpers.createStation(global.resources, name);
    return result ? result.id : null;
  };

  const createStory = async (title, text, voiceId, weekdays = 127, status = 'active', targetStations = null) => {
    if (!targetStations || targetStations.length === 0) {
      const defaultStation = await createStation('DefaultStoryStation');
      targetStations = [parseInt(defaultStation, 10)];
    }

    const result = await global.helpers.createStory(global.resources, {
      title,
      text,
      voice_id: voiceId,
      weekdays,
      status
    }, targetStations);

    return result ? result.id : null;
  };

  describe('Story Creation', () => {
    let voiceId;

    beforeAll(async () => {
      voiceId = await createVoice('TestStoryVoice');
    });

    test('creates a story with valid data', async () => {
      const storyId = await createStory('Test Story Title', 'This is a test story content.', voiceId);

      expect(storyId).not.toBeNull();

      const response = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(response.status).toBe(200);
      expect(response.data.title).toContain('Test Story Title');
    });
  });

  describe('Story CRUD', () => {
    let voiceId, storyId;

    beforeAll(async () => {
      voiceId = await createVoice('CrudTestVoice');
      storyId = await createStory('CRUD Test Story', 'Initial content', voiceId);
    });

    test('reads story', async () => {
      const response = await global.api.apiCall('GET', `/stories/${storyId}`);

      expect(response.status).toBe(200);
    });

    test('updates story', async () => {
      const response = await global.api.apiCall('PUT', `/stories/${storyId}`, {
        title: 'Updated CRUD Story',
        text: 'Updated content',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31'
      });

      expect(response.status).toBe(200);
    });
  });

  describe('Story Listing', () => {
    let voiceId, storyId;

    beforeAll(async () => {
      voiceId = await createVoice('List Test Voice');
      storyId = await createStory('List Story 1', 'Content 1', voiceId);
      await createStory('List Story 2', 'Content 2', voiceId);
      await createStory('List Story 3', 'Content 3', voiceId);
    });

    test('lists stories in data array', async () => {
      const response = await global.api.apiCall('GET', '/stories');

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
      expect(Array.isArray(response.data.data)).toBe(true);
    });

    test('pagination limits results', async () => {
      const response = await global.api.apiCall('GET', '/stories?limit=2&offset=0');

      expect(response.status).toBe(200);
      expect(response.data.data.length).toBeLessThanOrEqual(2);
    });

    test('filters by voice_id', async () => {
      const response = await global.api.apiCall('GET', `/stories?filter%5Bvoice_id%5D=${voiceId}`);

      expect(response.status).toBe(200);
    });

    test('story has audio_url and audio_file fields', async () => {
      const response = await global.api.apiCall('GET', `/stories/${storyId}`);

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('audio_url');
      expect(typeof response.data.audio_url).toBe('string');
      expect(response.data).toHaveProperty('audio_file');
    });

    test('filters for stories without audio', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter%5Baudio_url%5D=');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      const allWithoutAudio = stories.every(s => s.audio_file === '');
      expect(allWithoutAudio).toBe(true);
    });

    test('filters by status', async () => {
      await createStory('Draft Story', 'Draft content', voiceId, 127, 'draft');

      const response = await global.api.apiCall('GET', '/stories?filter%5Bstatus%5D=active');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      const allActive = stories.every(s => s.status === 'active');
      expect(allActive).toBe(true);
    });
  });

  describe('Story Updates', () => {
    let voiceId, storyId;

    beforeAll(async () => {
      voiceId = await createVoice('Update Test Voice');
      storyId = await createStory('Update Test Story', 'Original content', voiceId);
    });

    test('updates title and text', async () => {
      const response = await global.api.apiCall('PUT', `/stories/${storyId}`, {
        title: 'Updated Story Title',
        text: 'Updated story content'
      });

      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(getResponse.data.title).toBe('Updated Story Title');
    });

    test('updates weekday schedule', async () => {
      // Mon/Wed/Fri = 42
      const response = await global.api.apiCall('PUT', `/stories/${storyId}`, { weekdays: 42 });

      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(getResponse.data.weekdays).toBe(42);
    });

    test('updates status to draft', async () => {
      const response = await global.api.apiCall('PUT', `/stories/${storyId}`, { status: 'draft' });

      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(getResponse.data.status).toBe('draft');
    });

    test('rejects update of non-existent story', async () => {
      const response = await global.api.apiCall('PUT', '/stories/99999', { title: 'Non-existent' });

      expect(response.status).toBe(404);
    });
  });

  describe('Story Deletion', () => {
    let voiceId;

    beforeAll(async () => {
      voiceId = await createVoice('Delete Test Voice');
    });

    test('soft deletes story', async () => {
      const storyId = await createStory('Delete Test Story', 'To be deleted', voiceId);

      const response = await global.api.apiCall('DELETE', `/stories/${storyId}`);
      expect(response.status).toBe(204);

      // Story should not be visible in default query
      const getResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(getResponse.status).toBe(404);
    });

    test('trashed=only returns soft-deleted stories', async () => {
      const storyId = await createStory('Trashed Story', 'To be trashed', voiceId);
      await global.api.apiCall('DELETE', `/stories/${storyId}`);

      const response = await global.api.apiCall('GET', '/stories?trashed=only');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      const found = stories.some(s => String(s.id) === String(storyId));
      expect(found).toBe(true);
    });

    test('trashed=with includes soft-deleted stories', async () => {
      const storyId = await createStory('With Trashed Story', 'To be trashed', voiceId);
      await global.api.apiCall('DELETE', `/stories/${storyId}`);

      const response = await global.api.apiCall('GET', '/stories?trashed=with');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      const found = stories.some(s => String(s.id) === String(storyId));
      expect(found).toBe(true);
    });

    test('returns 404 for non-existent story', async () => {
      const response = await global.api.apiCall('DELETE', '/stories/99999');

      expect(response.status).toBe(404);
    });
  });

  describe('Story Scheduling', () => {
    let voiceId, stationId;

    beforeAll(async () => {
      voiceId = await createVoice('Schedule Test Voice');
      stationId = await createStation('ScheduleTestStation');
    });

    test('creates future-dated story', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Future Story',
        text: 'This story is scheduled for the future.',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2030-01-01',
        end_date: '2030-12-31',
        weekdays: 127,
        target_stations: [parseInt(stationId, 10)]
      });

      expect(response.status).toBe(201);
      const storyId = global.api.parseJsonField(response.data, 'id');
      global.resources.track('stories', storyId);
    });

    test('creates weekend-only story', async () => {
      // Sun=1 + Sat=64 = 65
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Weekend Story',
        text: 'This story only plays on weekends.',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 65,
        target_stations: [parseInt(stationId, 10)]
      });

      expect(response.status).toBe(201);
      const storyId = global.api.parseJsonField(response.data, 'id');
      global.resources.track('stories', storyId);
    });
  });

  describe('Weekday Bitmask Filter', () => {
    let voiceId, stationId;
    const storyIds = {};

    beforeAll(async () => {
      voiceId = await createVoice('Bitmask Test Voice');
      stationId = await createStation('BitmaskTestStation');

      const formatDate = (date) => {
        const y = date.getFullYear();
        const m = String(date.getMonth() + 1).padStart(2, '0');
        const d = String(date.getDate()).padStart(2, '0');
        return `${y}-${m}-${d}`;
      };

      const today = new Date();
      const startDate = new Date(today);
      startDate.setMonth(startDate.getMonth() - 1);
      const endDate = new Date(today);
      endDate.setMonth(endDate.getMonth() + 1);

      const createBitmaskStory = async (title, weekdays) => {
        const response = await global.api.apiCall('POST', '/stories', {
          title: `${title}_${Date.now()}`,
          text: 'Bitmask test',
          voice_id: parseInt(voiceId, 10),
          status: 'active',
          start_date: formatDate(startDate),
          end_date: formatDate(endDate),
          weekdays,
          target_stations: [parseInt(stationId, 10)]
        });
        if (response.status === 201) {
          const id = global.api.parseJsonField(response.data, 'id');
          global.resources.track('stories', id);
          return id;
        }
        return null;
      };

      // Mon-Fri = 62, Weekend = 65, MWF = 42, All = 127
      storyIds.weekday = await createBitmaskStory('Weekday Only', 62);
      storyIds.weekend = await createBitmaskStory('Weekend Only', 65);
      storyIds.mwf = await createBitmaskStory('MWF', 42);
      storyIds.allDays = await createBitmaskStory('All Days', 127);
    });

    test('filters Monday stories (band=2)', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter%5Bweekdays%5D%5Bband%5D=2');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      // Weekend story (65) should not be in results
      const excludesWeekend = !stories.some(s => s.id === parseInt(storyIds.weekend));
      if (stories.length > 0) {
        expect(excludesWeekend).toBe(true);
      }
    });

    test('filters Saturday stories (band=64)', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter%5Bweekdays%5D%5Bband%5D=64');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      // Weekday story (62) should not be in results
      const excludesWeekday = !stories.some(s => s.id === parseInt(storyIds.weekday));
      if (stories.length > 0) {
        expect(excludesWeekday).toBe(true);
      }
    });
  });

  describe('Modern Query Parameters', () => {
    let voiceIds = [];

    beforeAll(async () => {
      voiceIds.push(await createVoice('Alice Anderson'));
      voiceIds.push(await createVoice('Bob Brown'));
      voiceIds.push(await createVoice('Charlie Chen'));

      await createStory('Breaking News Today', 'Important breaking news content', voiceIds[0]);
      await createStory('Weather Update Morning', "Today's weather forecast", voiceIds[1]);
      await createStory('Sports Highlights', 'Latest sports results', voiceIds[2]);
    });

    test('comparison operator gte', async () => {
      const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().split('T')[0];
      const response = await global.api.apiCall('GET', `/stories?filter%5Bcreated_at%5D%5Bgte%5D=${yesterday}`);

      expect(response.status).toBe(200);
    });

    test('multiple filters combined', async () => {
      const response = await global.api.apiCall('GET', `/stories?filter%5Bvoice_id%5D=${voiceIds[0]}&filter%5Bstatus%5D=active&filter%5Bweekdays%5D=127`);

      expect(response.status).toBe(200);
    });

    test('multi-field sorting', async () => {
      const response = await global.api.apiCall('GET', '/stories?sort=-created_at,+title');

      expect(response.status).toBe(200);
    });

    test('colon notation sorting', async () => {
      const response = await global.api.apiCall('GET', '/stories?sort=created_at:desc,title:asc');

      expect(response.status).toBe(200);
    });

    test('search functionality', async () => {
      const response = await global.api.apiCall('GET', '/stories?search=News');

      expect(response.status).toBe(200);
    });
  });

  describe('Story Audio', () => {
    let voiceId, stationId;
    const testAudio = '/tmp/test_audio_upload.wav';

    beforeAll(async () => {
      voiceId = await createVoice('Audio Test Voice');
      stationId = await createStation('AudioTestStation');

      try {
        execSync(`ffmpeg -f lavfi -i anullsrc=r=44100:cl=stereo -t 2 -f wav "${testAudio}" -y 2>/dev/null`, { stdio: 'ignore' });
      } catch {
        // ffmpeg not available
      }
    });

    afterAll(() => {
      if (fs.existsSync(testAudio)) {
        fs.unlinkSync(testAudio);
      }
    });

    test('uploads and downloads audio', async () => {
      if (!fs.existsSync(testAudio)) {
        console.log('Skipping audio test - ffmpeg not available');
        return;
      }

      // Create story
      const createResponse = await global.api.apiCall('POST', '/stories', {
        title: 'Story With Audio Upload Test',
        text: 'This story has uploaded audio for testing',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 127,
        target_stations: [parseInt(stationId, 10)]
      });

      expect(createResponse.status).toBe(201);
      const storyId = global.api.parseJsonField(createResponse.data, 'id');
      global.resources.track('stories', storyId);

      // Upload audio
      const uploadResponse = await global.api.uploadFile(`/stories/${storyId}/audio`, {}, testAudio, 'audio');
      expect(uploadResponse.status).toBe(201);

      // Verify audio_file field
      const getResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(getResponse.status).toBe(200);
      expect(getResponse.data.audio_file).not.toBe('');
    });
  });

  describe('Story Station Targeting', () => {
    let station1, station2, station3, voiceId;

    beforeAll(async () => {
      station1 = await createStation('TargetStation1');
      station2 = await createStation('TargetStation2');
      station3 = await createStation('TargetStation3');
      voiceId = await createVoice('TargetingTestVoice');
    });

    test('creates story with target_stations', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Targeted Story Test',
        text: 'This story targets specific stations.',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 127,
        target_stations: [parseInt(station1, 10), parseInt(station2, 10)]
      });

      expect(response.status).toBe(201);
      const storyId = global.api.parseJsonField(response.data, 'id');
      global.resources.track('stories', storyId);

      const getResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(getResponse.data.target_stations).toContain(parseInt(station1, 10));
      expect(getResponse.data.target_stations).toContain(parseInt(station2, 10));
    });

    test('rejects story without target_stations', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Story Without Targets',
        text: 'This story has no target stations.',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 127
      });

      expect([400, 422]).toContain(response.status);
    });

    test('rejects story with empty target_stations', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Story With Empty Targets',
        text: 'This story has empty target stations array.',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 127,
        target_stations: []
      });

      expect([400, 422]).toContain(response.status);
    });

    test('rejects story with invalid station ID', async () => {
      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Story With Invalid Station',
        text: 'This story targets a non-existent station.',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 127,
        target_stations: [99999]
      });

      expect(response.status).toBe(404);
    });
  });

  describe('Story Metadata', () => {
    let voiceId, stationId;

    beforeAll(async () => {
      voiceId = await createVoice('MetadataTestVoice');
      stationId = await createStation('MetadataTestStation');
    });

    test('creates story with metadata', async () => {
      const metadata = { source: 'test', priority: 'high', tags: ['breaking', 'local'] };

      const response = await global.api.apiCall('POST', '/stories', {
        title: 'Metadata Test Story',
        text: 'This is a story with metadata.',
        voice_id: parseInt(voiceId, 10),
        status: 'active',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 127,
        target_stations: [parseInt(stationId, 10)],
        metadata
      });

      expect(response.status).toBe(201);
      const storyId = global.api.parseJsonField(response.data, 'id');
      global.resources.track('stories', storyId);

      const getResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(getResponse.data.metadata).toBeDefined();
      expect(getResponse.data.metadata.source).toBe('test');
    });

    test('updates metadata', async () => {
      const storyId = await createStory('Update Metadata Story', 'Story for metadata update', voiceId);

      const response = await global.api.apiCall('PUT', `/stories/${storyId}`, {
        metadata: { source: 'updated', version: 2 }
      });

      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(getResponse.data.metadata.source).toBe('updated');
      expect(getResponse.data.metadata.version).toBe(2);
    });
  });
});
