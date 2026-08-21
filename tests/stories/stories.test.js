const fs = require('fs');
const { spawnSync } = require('child_process');
const storiesSchema = require('../lib/schemas/stories.schema');
const { generateQueryTests } = require('../lib/generators');
const { createMySQLExecutor, sqlInteger } = require('../lib/MySQLHelper');

const STORY_TRUE_PEAK_TARGET_DBTP = -1.0;
const TRUE_PEAK_TOLERANCE_DB = 0.3;

function runFFmpeg(args) {
  const result = spawnSync('ffmpeg', args, { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`ffmpeg failed: ${result.stderr || result.stdout}`);
  }
  return `${result.stdout || ''}${result.stderr || ''}`;
}

function createQuietStoryAudioFile(outputPath) {
  runFFmpeg([
    '-f', 'lavfi',
    '-i', 'sine=frequency=1000:duration=1',
    '-af', 'volume=-24dB',
    '-ar', '44100',
    '-ac', '1',
    '-f', 'wav',
    '-y', outputPath
  ]);
}

function measureTruePeakDBTP(inputPath) {
  const output = runFFmpeg([
    '-i', inputPath,
    '-af', 'loudnorm=I=-16:TP=-1:LRA=11:print_format=json',
    '-f', 'null',
    '-'
  ]);
  const start = output.indexOf('{');
  const end = output.lastIndexOf('}');
  if (start === -1 || end <= start) {
    throw new Error(`loudnorm JSON stats not found: ${output}`);
  }

  const stats = JSON.parse(output.slice(start, end + 1));
  return Number(stats.input_tp);
}

describe('Stories', () => {
  const storyData = (voiceId, targetStations, overrides = {}) => ({
    title: `Story ${Date.now()}`,
    text: 'Test content',
    voice_id: voiceId,
    status: 'active',
    weekdays: 127,
    ...(targetStations !== undefined ? { target_stations: targetStations } : {}),
    ...overrides
  });

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
    }, [station.id]);

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
      // Create dependencies
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
      }, [stationId]);
      storyId = story.id;
    });

    test('when fetching story by ID, then returns story', async () => {
      const response = await global.api.apiCall('GET', `/stories/${storyId}`);

      expect(response.status).toBe(200);
      expect(response.data.title).toContain('CRUD Test Story');
    });

    test('when updating title and text, then persists changes', async () => {
      const response = await global.api.apiCall('PUT', `/stories/${storyId}`, {
        title: 'Updated CRUD Story',
        text: 'Updated content'
      });

      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${storyId}`);
      expect(getResponse.data.title).toBe('Updated CRUD Story');
    });

    test('when fetching non-existent story, then returns 404', async () => {
      const response = await global.api.apiCall('GET', '/stories/999999');

      expect(response.status).toBe(404);
    });
  });

  describe('Story Soft Delete', () => {
    test('when deleting story, then soft deleted', async () => {
      const result = await createStoryWithDeps('DeleteTest', 'To be deleted', 'DeleteVoice', 'DeleteStation');
      expect(result).not.toBeNull();

      const response = await global.api.apiCall('DELETE', `/stories/${result.id}`);

      expect(response.status).toBe(204);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.status).toBe(404);
    });

    test('when trashed=only, then returns soft-deleted stories', async () => {
      const result = await createStoryWithDeps('TrashedOnly', 'To be trashed', 'TrashVoice1', 'TrashStation1');
      await global.api.apiCall('DELETE', `/stories/${result.id}`);

      const response = await global.api.apiCall('GET', '/stories?trashed=only');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      const found = stories.some(s => String(s.id) === String(result.id));
      expect(found).toBe(true);
    });

    test('when trashed=with, then includes soft-deleted stories', async () => {
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
      // Create dependencies
      const voice = await global.helpers.createVoice(global.resources, 'ScheduleVoice');
      const station = await global.helpers.createStation(global.resources, 'ScheduleStation');
      voiceId = voice.id;
      stationId = station.id;
    });

    test('when creating future-dated story, then accepted', async () => {
      const response = await global.api.apiCall('POST', '/stories', storyData(voiceId, [stationId], {
        title: `Future Story ${Date.now()}`,
        text: 'Scheduled for future',
        start_date: '2030-01-01',
        end_date: '2030-12-31'
      }));

      expect(response.status).toBe(201);

      // Cleanup
      global.resources.track('stories', response.data.id);
    });

    test('when creating weekend-only story, then accepted', async () => {
      const response = await global.api.apiCall('POST', '/stories', storyData(voiceId, [stationId], {
        title: `Weekend Story ${Date.now()}`,
        text: 'Weekend only',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        weekdays: 65
      }));

      expect(response.status).toBe(201);

      // Cleanup
      global.resources.track('stories', response.data.id);
    });

    test('when updating weekday schedule, then persisted', async () => {
      const result = await createStoryWithDeps('WeekdayUpdate', 'Test', 'WkdyVoice', 'WkdyStation');
      expect(result).not.toBeNull();

      // Update to MWF (weekdays=42)
      const response = await global.api.apiCall('PUT', `/stories/${result.id}`, { weekdays: 42 });

      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.data.weekdays).toBe(42);
    });
  });

  describe('Station Targeting', () => {
    let voiceId, station1Id, station2Id;

    beforeAll(async () => {
      // Create dependencies
      const voice = await global.helpers.createVoice(global.resources, 'TargetVoice');
      const station1 = await global.helpers.createStation(global.resources, 'Target1');
      const station2 = await global.helpers.createStation(global.resources, 'Target2');
      voiceId = voice.id;
      station1Id = station1.id;
      station2Id = station2.id;
    });

    test('when creating with multiple target_stations, then all assigned', async () => {
      const response = await global.api.apiCall('POST', '/stories', storyData(voiceId, [station1Id, station2Id], {
        title: `Multi-Target ${Date.now()}`,
        text: 'Targets multiple stations',
        start_date: '2024-01-01',
        end_date: '2024-12-31'
      }));

      expect(response.status).toBe(201);

      // Cleanup
      global.resources.track('stories', response.data.id);

      // Verify target_stations if returned in response
      const getResponse = await global.api.apiCall('GET', `/stories/${response.data.id}`);
      expect(getResponse.status).toBe(200);
      if (getResponse.data.target_stations) {
        expect(getResponse.data.target_stations).toContain(station1Id);
        expect(getResponse.data.target_stations).toContain(station2Id);
      }
    });

    test('when target_stations missing, then rejected', async () => {
      const response = await global.api.apiCall('POST', '/stories', storyData(voiceId, undefined, {
        title: 'No Targets',
        text: 'Missing target stations'
      }));

      expect([400, 422]).toContain(response.status);
    });

    test('when target_stations empty array, then rejected', async () => {
      const response = await global.api.apiCall('POST', '/stories', storyData(voiceId, [], {
        title: 'Empty Targets',
        text: 'Empty array'
      }));

      expect([400, 422]).toContain(response.status);
    });

    test('when target_stations has invalid ID, then rejected', async () => {
      const response = await global.api.apiCall('POST', '/stories', storyData(voiceId, [999999], {
        title: 'Invalid Station',
        text: 'Non-existent station'
      }));

      expect([404, 422]).toContain(response.status);
    });
  });

  describe('Story Audio', () => {
    const testAudio = '/tmp/test_story_audio.wav';

    beforeAll(() => {
      if (!global.helpers.createTestAudioFile(testAudio, 2)) {
        console.log('Could not create test audio file (ffmpeg unavailable or failed)');
      }
    });

    afterAll(() => {
      global.helpers.cleanupTempFile(testAudio);
    });

    test('when uploading audio, then attached to story', async () => {
      if (!fs.existsSync(testAudio)) return;

      const result = await createStoryWithDeps('AudioUpload', 'Has audio', 'AudioVoice', 'AudioStation');
      expect(result).not.toBeNull();

      const uploadResponse = await global.api.uploadFile(`/stories/${result.id}/audio`, {}, testAudio, 'audio');

      expect(uploadResponse.status).toBe(201);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.data.audio_file).not.toBe('');
    });

    test('when fetching story, then audio fields present', async () => {
      const result = await createStoryWithDeps('AudioFields', 'Check fields', 'FieldsVoice', 'FieldsStation');
      expect(result).not.toBeNull();

      const response = await global.api.apiCall('GET', `/stories/${result.id}`);

      expect(response.data).toHaveProperty('audio_url');
      expect(response.data).toHaveProperty('audio_file');
    });

    test('when uploading quiet story audio, then normalizes true peak to -1 dBTP', async () => {
      if (!global.helpers.isFFmpegAvailable()) return;

      const inputAudio = `/tmp/test_story_true_peak_input_${Date.now()}_${process.pid}.wav`;
      const outputAudio = `/tmp/test_story_true_peak_output_${Date.now()}_${process.pid}.wav`;

      try {
        createQuietStoryAudioFile(inputAudio);

        const result = await createStoryWithDeps(
          'TruePeakAudio',
          'Quiet story audio',
          'TruePeakVoice',
          'TruePeakStation'
        );
        expect(result).not.toBeNull();

        const uploadResponse = await global.api.uploadFile(`/stories/${result.id}/audio`, {}, inputAudio, 'audio');
        expect(uploadResponse.status).toBe(201);

        const audioReady = await global.helpers.waitForStoryAudio(result.id);
        expect(audioReady).toBe(true);

        const downloadStatus = await global.api.downloadFile(`/stories/${result.id}/audio`, outputAudio);
        expect(downloadStatus).toBe(200);

        const truePeakDBTP = measureTruePeakDBTP(outputAudio);
        expect(Math.abs(truePeakDBTP - STORY_TRUE_PEAK_TARGET_DBTP)).toBeLessThanOrEqual(TRUE_PEAK_TOLERANCE_DB);
      } finally {
        global.helpers.cleanupTempFile(inputAudio);
        global.helpers.cleanupTempFile(outputAudio);
      }
    });
  });

  describe('Audio Presence Filter', () => {
    const testAudio = '/tmp/test_has_audio_filter.wav';
    // Unique prefix scopes every list query to this block's fixtures.
    const titlePrefix = `HasAudioFilter_${Date.now()}`;
    let withAudioId, withoutAudioId, nullAudioId;

    beforeAll(async () => {
      if (!global.helpers.createTestAudioFile(testAudio, 1)) {
        console.warn('Audio presence filter tests will be skipped (ffmpeg not available)');
        return;
      }

      const withAudio = await createStoryWithDeps(`${titlePrefix} uploaded`, 'With audio', 'HasAudioVoice1', 'HasAudioStation1');
      const withoutAudio = await createStoryWithDeps(`${titlePrefix} empty`, 'Without audio', 'HasAudioVoice2', 'HasAudioStation2');
      const nullAudio = await createStoryWithDeps(`${titlePrefix} null`, 'NULL audio', 'HasAudioVoice3', 'HasAudioStation3');
      expect(withAudio).not.toBeNull();
      expect(withoutAudio).not.toBeNull();
      expect(nullAudio).not.toBeNull();

      const uploadResponse = await global.api.uploadFile(`/stories/${withAudio.id}/audio`, {}, testAudio, 'audio');
      expect(uploadResponse.status).toBe(201);

      // The API never writes NULL (the model field is a plain string), but the
      // column is nullable and legacy/imported rows can hold NULL. Force one
      // via SQL to pin that has_audio=false catches it.
      createMySQLExecutor().execSQL(
        `UPDATE stories SET audio_file = NULL WHERE id = ${sqlInteger(nullAudio.id, 'story ID')}`
      );

      withAudioId = withAudio.id;
      withoutAudioId = withoutAudio.id;
      nullAudioId = nullAudio.id;
    });

    afterAll(() => {
      global.helpers.cleanupTempFile(testAudio);
    });

    const listScopedIds = async (hasAudio) => {
      const response = await global.api.apiCall(
        'GET',
        `/stories?filter[title][like]=${titlePrefix}&filter[has_audio]=${hasAudio}`
      );
      expect(response.status).toBe(200);
      return response.data.data.map((story) => story.id);
    };

    test('when filtering has_audio=true, then returns only stories with audio', async () => {
      if (!withAudioId) return;

      expect(await listScopedIds('true')).toEqual([withAudioId]);
    });

    test('when filtering has_audio=false, then includes empty and NULL audio stories', async () => {
      if (!withAudioId) return;

      expect((await listScopedIds('false')).sort()).toEqual([withoutAudioId, nullAudioId].sort());
    });

    test('when filtering has_audio with non-boolean value, then returns 422', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter[has_audio]=maybe');
      expect(response.status).toBe(422);
    });

    test('when filtering has_audio ne with non-boolean value, then error reports the public ne operator', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter[has_audio][ne]=maybe');
      expect(response.status).toBe(422);
      expect(response.data.errors[0].field).toBe('filter[has_audio][ne]');
    });

    test('when sorting by has_audio, then returns 422', async () => {
      const response = await global.api.apiCall('GET', '/stories?sort=has_audio');
      expect(response.status).toBe(422);
    });

    test('when filtering has_audio null=false, then error reports the public null operator', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter[has_audio][null]=false');
      expect(response.status).toBe(422);
      expect(response.data.errors[0].field).toBe('filter[has_audio][null]');
    });
  });

  describe('Story Metadata', () => {
    test('when creating with metadata, then stored', async () => {
      const voice = await global.helpers.createVoice(global.resources, 'MetaVoice');
      const station = await global.helpers.createStation(global.resources, 'MetaStation');

      const response = await global.api.apiCall('POST', '/stories', storyData(voice.id, [station.id], {
        title: `Metadata Story ${Date.now()}`,
        text: 'Story with metadata',
        start_date: '2024-01-01',
        end_date: '2024-12-31',
        metadata: { source: 'test', priority: 'high' }
      }));

      expect(response.status).toBe(201);

      // Cleanup
      global.resources.track('stories', response.data.id);

      const getResponse = await global.api.apiCall('GET', `/stories/${response.data.id}`);
      expect(getResponse.data.metadata.source).toBe('test');
    });

    test('when updating metadata, then persisted', async () => {
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

  describe('Breaking News', () => {
    let voiceId, stationId;

    beforeAll(async () => {
      const voice = await global.helpers.createVoice(global.resources, 'BreakingVoice');
      const station = await global.helpers.createStation(global.resources, 'BreakingStation');
      voiceId = voice.id;
      stationId = station.id;
    });

    test('when creating story with is_breaking=true, then persists flag', async () => {
      const response = await global.api.apiCall('POST', '/stories', storyData(voiceId, [stationId], {
        title: `Breaking Story ${Date.now()}`,
        text: 'Breaking news content',
        start_date: '2024-01-01',
        end_date: '2030-12-31',
        is_breaking: true
      }));

      expect(response.status).toBe(201);
      global.resources.track('stories', response.data.id);

      const getResponse = await global.api.apiCall('GET', `/stories/${response.data.id}`);
      expect(getResponse.data.is_breaking).toBe(true);
    });

    test('when creating story without is_breaking, then defaults to false', async () => {
      const response = await global.api.apiCall('POST', '/stories', storyData(voiceId, [stationId], {
        title: `Normal Story ${Date.now()}`,
        text: 'Normal news content',
        start_date: '2024-01-01',
        end_date: '2030-12-31'
      }));

      expect(response.status).toBe(201);
      global.resources.track('stories', response.data.id);

      const getResponse = await global.api.apiCall('GET', `/stories/${response.data.id}`);
      expect(getResponse.data.is_breaking).toBe(false);
    });

    test('when updating is_breaking to true, then persists', async () => {
      const result = await createStoryWithDeps('BreakingUpdate', 'Test', 'BrkUpdVoice', 'BrkUpdStation');
      expect(result).not.toBeNull();

      const response = await global.api.apiCall('PUT', `/stories/${result.id}`, { is_breaking: true });

      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${result.id}`);
      expect(getResponse.data.is_breaking).toBe(true);
    });

    test('when updating is_breaking to false, then persists', async () => {
      const createResponse = await global.api.apiCall('POST', '/stories', storyData(voiceId, [stationId], {
        title: `Breaking to Normal ${Date.now()}`,
        text: 'Was breaking',
        start_date: '2024-01-01',
        end_date: '2030-12-31',
        is_breaking: true
      }));
      expect(createResponse.status).toBe(201);
      global.resources.track('stories', createResponse.data.id);

      const response = await global.api.apiCall('PUT', `/stories/${createResponse.data.id}`, { is_breaking: false });

      expect(response.status).toBe(200);

      const getResponse = await global.api.apiCall('GET', `/stories/${createResponse.data.id}`);
      expect(getResponse.data.is_breaking).toBe(false);
    });

    test('when filtering by is_breaking=1, then returns only breaking stories', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter[is_breaking]=1');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      expect(stories.length).toBeGreaterThan(0);
      const allBreaking = stories.every(s => s.is_breaking === true);
      expect(allBreaking).toBe(true);
    });

    test('when filtering by is_breaking=0, then returns only non-breaking stories', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter[is_breaking]=0');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      expect(stories.length).toBeGreaterThan(0);
      const allNonBreaking = stories.every(s => s.is_breaking === false);
      expect(allNonBreaking).toBe(true);
    });

    // Textual booleans are what generated OpenAPI clients send; MySQL would
    // coerce an unnormalized "true" to 0 and return the WRONG partition.
    test('when filtering by is_breaking=true, then returns only breaking stories', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter[is_breaking]=true');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      expect(stories.length).toBeGreaterThan(0);
      expect(stories.every(s => s.is_breaking === true)).toBe(true);
    });

    test('when filtering by is_breaking=false, then returns only non-breaking stories', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter[is_breaking]=false');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      expect(stories.length).toBeGreaterThan(0);
      expect(stories.every(s => s.is_breaking === false)).toBe(true);
    });

    test('when filtering by is_breaking ne=false, then returns only breaking stories', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter[is_breaking][ne]=false');

      expect(response.status).toBe(200);
      const stories = response.data.data || [];
      expect(stories.length).toBeGreaterThan(0);
      expect(stories.every(s => s.is_breaking === true)).toBe(true);
    });

    test('when filtering is_breaking with non-boolean value, then returns 422', async () => {
      const response = await global.api.apiCall('GET', '/stories?filter[is_breaking]=maybe');
      expect(response.status).toBe(422);
    });
  });

  describe('Status Filtering', () => {
    test('when filtering by status, then returns matching', async () => {
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
