const fs = require('fs');
const bulletinsSchema = require('../lib/schemas/bulletins.schema');
const { generateQueryTests } = require('../lib/generators');
const { createMySQLExecutor, sqlInteger, sqlString } = require('../lib/MySQLHelper');
const { declaresQueryParameter } = require('../lib/QueryFilterContract');

describe('Bulletins', () => {
  const mysql = createMySQLExecutor();
  const stationBulletinsEndpoint = stationId => `/stations/${stationId}/bulletins`;
  const enqueueBulletin = (stationId, body) => global.api.apiCall('POST', stationBulletinsEndpoint(stationId), body);
  const postBulletinHttp = (stationId, options = {}) => global.api.http({
    method: 'post',
    url: `${global.api.apiUrl}${stationBulletinsEndpoint(stationId)}`,
    validateStatus: () => true,
    ...options
  });
  const postJsonBulletinHttp = (stationId, headers = {}, options = {}) => postBulletinHttp(stationId, {
    data: '{}',
    headers: { 'Content-Type': 'application/json', ...headers },
    ...options
  });
  const getBulletinStoryIds = async bulletinId => {
    const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}/stories`);
    return {
      response,
      ids: response.data.data.map(story => story.story_id)
    };
  };
  const createStationVoiceFixture = async (stationName, voiceName, maxStories, pauseSeconds = 2.0, mixPoint = 3.0) => {
    const station = await global.helpers.createStation(global.resources, stationName, maxStories, pauseSeconds);
    const voice = await global.helpers.createVoice(global.resources, voiceName);
    expect(station).not.toBeNull();
    expect(voice).not.toBeNull();

    const stationVoice = await global.helpers.createStationVoiceWithJingle(global.resources, station.id, voice.id, mixPoint);
    expect(stationVoice).not.toBeNull();

    return { station, voice, stationVoice };
  };

  const setupQueryTestData = async () => {
    const { station } = await global.helpers.createBroadcastFixture(global.resources, {
      stationName: 'QueryBulletinStation',
      voiceName: 'QueryBulletinVoice',
      storyTitle: 'QueryBulletinStory',
      storyText: 'Query test story'
    });

    const response = await global.helpers.generateBulletin(station.id);
    // A failed fixture must fail the suite; pre-seeded rows would otherwise
    // keep the generated query tests green without exercising this data.
    expect(response.status).toBe(200);
    expect(response.data.id).toBeDefined();
    return [response.data.id];
  };

  // Generate query parameter tests
  generateQueryTests(bulletinsSchema, setupQueryTestData);

  // === BUSINESS LOGIC TESTS ===

  describe('Bulletin Generation', () => {
    let stationId;

    beforeAll(async () => {
      const { station } = await global.helpers.createBroadcastFixture(global.resources, {
        stationName: 'BulletinGenStation',
        voiceName: 'BulletinGenVoice',
        storyTitle: 'BulletinGenStory',
        storyText: 'Bulletin generation test story'
      });
      stationId = station.id;
    });

    test('when generating bulletin, then returns complete data', async () => {
      // Uses station setup from beforeAll

      const response = await global.helpers.generateBulletin(stationId);

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('id');
      expect(response.data).toHaveProperty('audio_url');
      expect(response.data).toHaveProperty('duration_seconds');
      expect(response.data).toHaveProperty('story_count');
      expect(response.data).toHaveProperty('filename');
    });

    test('when generating with date, then returns 422', async () => {
      const response = await enqueueBulletin(stationId, { date: '2026-10-07' });

      expect(response.status).toBe(422);
      expect(response.data.errors).toEqual([{ field: 'date', message: 'date is no longer supported' }]);
    });

    test.each([
      ['when generating with missing body, then queues', () => postBulletinHttp(stationId), 202, true],
      ['when generating with whitespace body, then queues', () => postJsonBulletinHttp(stationId, {}, {
        data: ' \n\t ',
        transformRequest: [data => data]
      }), 202, true],
      ['when generating with malformed JSON body, then returns 422', () => postJsonBulletinHttp(stationId, {}, {
        data: '{invalid json}',
        transformRequest: [data => data]
      }), 422, false],
      ['when generating with non-json content type and JSON body, then queues', () => postBulletinHttp(stationId, {
        data: '{}',
        headers: { 'Content-Type': 'text/plain' }
      }), 202, true],
      ['when generating with oversized body, then returns 413', () => postJsonBulletinHttp(stationId, {}, {
        data: 'a'.repeat(1024 * 1024 + 1),
        transformRequest: [data => data]
      }), 413, false]
    ])('%s', async (_name, request, status, hasJob) => {
      const response = await request();
      expect(response.status).toBe(status);
      if (hasJob) {
        expect(response.data).toHaveProperty('id');
        expect(response.headers.location).toBe(`/api/v1/bulletin-jobs/${response.data.id}`);
      }
    });

    test('when stories use different voices, then jingle context is stable across multiple bulletins', async () => {
      // Jingle context (voice + mix point) must come from the
      // highest-priority story before the playback order is shuffled.
      // A single run has a 50% chance of passing by luck with 2 stories,
      // so we generate multiple bulletins and assert all are consistent.
      // With 5 runs the false-pass probability drops to ~3%.

      // Two voices with very different mix points
      const station = await global.helpers.createStation(global.resources, 'JingleCtxStation', 2, 0);
      const highPriorityVoice = await global.helpers.createVoice(global.resources, 'JingleCtxVoiceHigh');
      const lowPriorityVoice = await global.helpers.createVoice(global.resources, 'JingleCtxVoiceLow');

      expect(station).not.toBeNull();
      expect(highPriorityVoice).not.toBeNull();
      expect(lowPriorityVoice).not.toBeNull();

      // High-priority voice gets a large mix point (5s), low-priority gets small (0.5s)
      const svHigh = await global.helpers.createStationVoiceWithJingle(global.resources, station.id, highPriorityVoice.id, 5.0);
      const svLow = await global.helpers.createStationVoiceWithJingle(global.resources, station.id, lowPriorityVoice.id, 0.5);
      expect(svHigh).not.toBeNull();
      expect(svLow).not.toBeNull();

      // Breaking story on high-priority voice -> will be first in SQL order
      await global.helpers.requireStoryWithReadyAudio(global.resources, {
        title: `JingleCtxBreaking_${Date.now()}`,
        text: 'Breaking story for jingle context test',
        voice_id: highPriorityVoice.id,
        weekdays: 127,
        status: 'active',
        is_breaking: true
      }, [station.id]);

      await global.helpers.requireStoryWithReadyAudio(global.resources, {
        title: `JingleCtxRegular_${Date.now()}`,
        text: 'Regular story for jingle context test',
        voice_id: lowPriorityVoice.id,
        weekdays: 127,
        status: 'active',
        is_breaking: false
      }, [station.id]);

      // Generate 5 bulletins - each shuffle is independent
      const runs = 5;
      const durations = [];
      for (let i = 0; i < runs; i++) {
        const response = await global.helpers.generateBulletin(station.id);
        expect(response.status).toBe(200);
        expect(response.data.story_count).toBe(2);
        durations.push(response.data.duration_seconds);
      }

      // Every bulletin must use the 5.0s mix point from the breaking
      // story's voice. Each test story is ~3s audio, pause_seconds is 0,
      // so total about 3 + 3 + 5.0 = 11.0s.
      // If the wrong mix point were used, total about 3 + 3 + 0.5 = 6.5s.
      // Threshold of 9s can only be met with the 5.0s mix point.
      for (let i = 0; i < runs; i++) {
        expect(durations[i]).toBeGreaterThan(9);
      }

      // All durations should be identical (same mix point every time)
      const uniqueDurations = new Set(durations.map(d => d.toFixed(2)));
      expect(uniqueDurations.size).toBe(1);
    });

    test('when breaking stories exceed available slots, then bulletin includes only breaking stories', async () => {
      const { station, voice } = await createStationVoiceFixture('BreakingPriorityStation', 'BreakingPriorityVoice', 2);

      const [breakingStoryA, breakingStoryB, regularStory] = await global.helpers.requireStationStoriesWithReadyAudio(
        global.resources,
        station.id,
        voice.id,
        [
          { title: `BreakingPriorityA_${Date.now()}`, text: 'Breaking story A', is_breaking: true },
          { title: `BreakingPriorityB_${Date.now()}`, text: 'Breaking story B', is_breaking: true },
          { title: `BreakingPriorityRegular_${Date.now()}`, text: 'Regular story', is_breaking: false }
        ]
      );

      const bulletinResponse = await global.helpers.generateBulletin(station.id);

      expect(bulletinResponse.status).toBe(200);

      const { response: bulletinStoriesResponse, ids: includedStoryIds } = await getBulletinStoryIds(bulletinResponse.data.id);
      expect(bulletinStoriesResponse.status).toBe(200);
      expect(bulletinStoriesResponse.data.total).toBe(2);

      expect(includedStoryIds).toHaveLength(2);
      expect(includedStoryIds).toEqual(expect.arrayContaining([breakingStoryA.id, breakingStoryB.id]));
      expect(includedStoryIds).not.toContain(regularStory.id);
    });

    test('when breaking and non-breaking stories compete for slots, then breaking always included', async () => {
      // Station with 3 slots, 1 breaking + 4 non-breaking stories
      const { station, voice } = await createStationVoiceFixture('BreakingAlwaysStation', 'BreakingAlwaysVoice', 3);

      const [breakingStory] = await global.helpers.requireStationStoriesWithReadyAudio(
        global.resources,
        station.id,
        voice.id,
        [{
          title: `BreakingAlways_${Date.now()}`,
          text: 'This breaking story must always appear',
          is_breaking: true
        }]
      );

      const regularStoryIds = [];
      for (let i = 0; i < 4; i++) {
        const [story] = await global.helpers.requireStationStoriesWithReadyAudio(global.resources, station.id, voice.id, [{
          title: `BreakingAlwaysRegular${i}_${Date.now()}`,
          text: `Regular story ${i}`,
          is_breaking: false
        }]);
        regularStoryIds.push(story.id);
      }

      // Generate 5 bulletins - fair rotation will vary the non-breaking stories
      const runs = 5;
      for (let i = 0; i < runs; i++) {
        const bulletinResponse = await global.helpers.generateBulletin(station.id);
        expect(bulletinResponse.status).toBe(200);
        expect(bulletinResponse.data.story_count).toBe(3);

        const { ids: includedStoryIds } = await getBulletinStoryIds(bulletinResponse.data.id);

        // Breaking story is in every single bulletin
        expect(includedStoryIds).toContain(breakingStory.id);

        // Remaining 2 slots are filled by non-breaking stories
        const nonBreakingIncluded = includedStoryIds.filter(id => id !== breakingStory.id);
        expect(nonBreakingIncluded).toHaveLength(2);
        nonBreakingIncluded.forEach(id => {
          expect(regularStoryIds).toContain(id);
        });
      }
    });

    test('when breaking story is ineligible, then excluded from bulletin despite flag', async () => {
      // Station with stories that are breaking but fail eligibility
      const { station, voice } = await createStationVoiceFixture('BreakingEligStation', 'BreakingEligVoice', 3);

      // Current weekday bitmask: Sunday=1, Monday=2, Tuesday=4, etc.
      // Use a bitmask that excludes today
      const todayBit = 1 << new Date().getDay();
      const wrongWeekdays = 127 ^ todayBit; // all days except today
      const [draftBreaking, expiredBreaking, wrongDayBreaking, eligibleStory] =
        await global.helpers.requireStationStoriesWithReadyAudio(global.resources, station.id, voice.id, [
          { title: `BreakingDraft_${Date.now()}`, text: 'Breaking but draft', status: 'draft', is_breaking: true },
          {
            title: `BreakingExpired_${Date.now()}`,
            text: 'Breaking but expired',
            start_date: '2020-01-01',
            end_date: '2020-12-31',
            is_breaking: true
          },
          {
            title: `BreakingWrongDay_${Date.now()}`,
            text: 'Breaking but wrong weekday',
            weekdays: wrongWeekdays,
            is_breaking: true
          },
          { title: `BreakingEligRegular_${Date.now()}`, text: 'Eligible regular story', is_breaking: false }
        ]);

      const bulletinResponse = await global.helpers.generateBulletin(station.id);

      expect(bulletinResponse.status).toBe(200);

      const { ids: includedStoryIds } = await getBulletinStoryIds(bulletinResponse.data.id);

      // None of the ineligible breaking stories should be included
      expect(includedStoryIds).not.toContain(draftBreaking.id);
      expect(includedStoryIds).not.toContain(expiredBreaking.id);
      expect(includedStoryIds).not.toContain(wrongDayBreaking.id);

      // The eligible regular story should be included
      expect(includedStoryIds).toContain(eligibleStory.id);
    });

    test('when multiple breaking stories compete for limited slots, then newest by start_date selected', async () => {
      // Station with 2 slots, 3 breaking stories with different start_dates
      const { station, voice } = await createStationVoiceFixture('BreakingNewestStation', 'BreakingNewestVoice', 2);

      const [oldBreaking, midBreaking, newBreaking] = await global.helpers.requireStationStoriesWithReadyAudio(
        global.resources,
        station.id,
        voice.id,
        [
          {
            title: `BreakingOld_${Date.now()}`,
            text: 'Old breaking story',
            start_date: '2024-01-01',
            end_date: '2030-12-31',
            is_breaking: true
          },
          {
            title: `BreakingMid_${Date.now()}`,
            text: 'Middle breaking story',
            start_date: '2025-06-01',
            end_date: '2030-12-31',
            is_breaking: true
          },
          {
            title: `BreakingNew_${Date.now()}`,
            text: 'Newest breaking story',
            start_date: '2026-03-01',
            end_date: '2030-12-31',
            is_breaking: true
          }
        ]
      );

      const bulletinResponse = await global.helpers.generateBulletin(station.id);

      expect(bulletinResponse.status).toBe(200);
      expect(bulletinResponse.data.story_count).toBe(2);

      const { ids: includedStoryIds } = await getBulletinStoryIds(bulletinResponse.data.id);

      // Newest two breaking stories should be selected
      expect(includedStoryIds).toContain(newBreaking.id);
      expect(includedStoryIds).toContain(midBreaking.id);
      expect(includedStoryIds).not.toContain(oldBreaking.id);
    });
  });

  describe('Bulletin Retrieval', () => {
    test('when fetching single bulletin, then returns data', async () => {
      const listResponse = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (listResponse.data.data.length > 0) {
        const bulletinId = listResponse.data.data[0].id;

        const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}`);

        expect(response.status).toBe(200);
        expect(response.data.id).toBe(bulletinId);
      }
    });

    test('when fetching non-existent bulletin, then returns 404', async () => {
      const response = await global.api.apiCall('GET', '/bulletins/999999999');

      expect(response.status).toBe(404);
    });

    test('when fetching bulletin, then has correct field types', async () => {
      const listResponse = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (listResponse.data.data.length > 0) {
        const bulletinId = listResponse.data.data[0].id;

        const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}`);
        const bulletin = response.data;

        expect(typeof bulletin.id).toBe('number');
        expect(typeof bulletin.station_id).toBe('number');
        expect(typeof bulletin.station_name).toBe('string');
        expect(typeof bulletin.audio_url).toBe('string');
        expect(typeof bulletin.filename).toBe('string');
        expect(typeof bulletin.duration_seconds).toBe('number');
      }
    });
  });

  describe('Asynchronous Bulletin Jobs', () => {
    let stationId;

    beforeAll(async () => {
      const { station } = await global.helpers.createBroadcastFixture(global.resources, {
        stationName: 'AsyncJobStation',
        voiceName: 'AsyncJobVoice',
        storyTitle: 'AsyncJobStory',
        storyText: 'Asynchronous job test story'
      });
      stationId = station.id;
    });

    test('when generation is enqueued, then polling resolves to the created bulletin', async () => {
      const accepted = await enqueueBulletin(stationId);
      expect(accepted.status).toBe(202);
      expect(accepted.headers.location).toBe(`/api/v1/bulletin-jobs/${accepted.data.id}`);
      expect(['queued', 'running']).toContain(accepted.data.status);

      const completed = await global.helpers.waitForBulletinJob(accepted.data.id);
      expect(completed.status).toBe(200);
      expect(completed.data.status).toBe('succeeded');
      expect(completed.data.bulletin_id).toEqual(expect.any(Number));

      const bulletin = await global.api.apiCall('GET', `/bulletins/${completed.data.bulletin_id}`);
      expect(bulletin.status).toBe(200);
    });

    test('when the same generation is requested concurrently, then each request creates a job', async () => {
      const responses = await Promise.all([
        enqueueBulletin(stationId),
        enqueueBulletin(stationId),
        enqueueBulletin(stationId)
      ]);

      for (const response of responses) {
        expect(response.status).toBe(202);
      }
      const jobIds = new Set(responses.map((response) => response.data.id));
      expect(jobIds.size).toBe(responses.length);

      const completed = await Promise.all(
        responses.map((response) => global.helpers.waitForBulletinJob(response.data.id))
      );
      for (const response of completed) {
        expect(response.data.status).toBe('succeeded');
      }
    });

    test('when generation has no eligible stories, then the asynchronous job fails safely', async () => {
      const emptyStation = await global.helpers.createStation(global.resources, 'AsyncEmptyStation');
      expect(emptyStation).not.toBeNull();
      const accepted = await enqueueBulletin(emptyStation.id);
      expect(accepted.status).toBe(202);

      const completed = await global.helpers.waitForBulletinJob(accepted.data.id);
      expect(completed.data.status).toBe('failed');
      expect(completed.data.error_code).toBe('bulletin.no_stories');
      expect(completed.data.bulletin_id).toBeNull();
    });

    test('when Accept audio/wav is requested, then directs clients to the audio endpoint', async () => {
      const response = await postJsonBulletinHttp(stationId, { 'Accept': 'audio/wav' });

      expect(response.status).toBe(406);
      expect(response.headers['content-type']).toMatch(/application\/problem\+json/);
    });

    test.each([
      'application/json;q=0',
      '*/*;q=0'
    ])('when Accept %s excludes JSON, then returns 406', async accept => {
      const response = await postJsonBulletinHttp(stationId, { 'Accept': accept });

      expect(response.status).toBe(406);
      expect(response.headers['content-type']).toMatch(/application\/problem\+json/);
    });
  });

  describe('Bulletin Stories Endpoint', () => {
    let bulletinId;

    beforeAll(async () => {
      const { station } = await global.helpers.createBroadcastFixture(global.resources, {
        stationName: 'BulletinStoriesEndpoint',
        voiceName: 'BulletinStoriesVoice',
        storyTitle: 'BulletinStoriesStory',
        storyText: 'Bulletin stories endpoint test'
      });

      const response = await global.helpers.generateBulletin(station.id);
      expect(response.status).toBe(200);
      bulletinId = response.data.id;
    });

    test('when called with only pagination, then returns 200', async () => {
      const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}/stories?limit=10&offset=0`);

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
    });

    test.each([
      ['when called with filter, then returns 422', 'filter[story_id]=1'],
      ['when called with sort, then returns 422', 'sort=story_order'],
      ['when called with fields, then returns 422', 'fields=id,story_id'],
      ['when called with search, then returns 422', 'search=anything'],
      ['when called with trashed, then returns 422', 'trashed=only']
    ])('%s', async (_name, query) => {
      const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}/stories?${query}`);
      expect(response.status).toBe(422);
    });
  });

  describe('Bulletin Audio Download', () => {
    test('when downloading audio, then file is valid', async () => {
      const response = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (response.data.data.length > 0) {
        const bulletinId = response.data.data[0].id;
        const downloadPath = '/tmp/test_bulletin_download.wav';

        const downloadResponse = await global.api.downloadFile(`/bulletins/${bulletinId}/audio`, downloadPath);

        if (downloadResponse === 200) {
          expect(fs.existsSync(downloadPath)).toBe(true);
          const stats = fs.statSync(downloadPath);
          expect(stats.size).toBeGreaterThan(1000);

          // Cleanup
          fs.unlinkSync(downloadPath);
        }
      }
    });
  });

  describe('Station Bulletin Endpoints', () => {
    let stationId;
    let storyId;

    beforeAll(async () => {
      const { station, story } = await global.helpers.createBroadcastFixture(global.resources, {
        stationName: 'StationBulletinEndpoint',
        voiceName: 'StationBulletinVoice',
        storyTitle: 'StationBulletinStory',
        storyText: 'Station endpoint test story'
      });
      stationId = station.id;
      storyId = story.id;
    });

    // Bulletins have no soft deletion, so nested bulletin lists neither declare
    // nor accept trashed.
    test.each([
      ['/stations/{id}/bulletins', 'only', () => stationId],
      ['/stations/{id}/bulletins', 'with', () => stationId],
      ['/stories/{id}/bulletins', 'only', () => storyId],
      ['/stories/{id}/bulletins', 'with', () => storyId]
    ])('when listing %s with trashed=%s, then returns a trashed 422', async (template, value, id) => {
      expect(declaresQueryParameter(template, 'trashed')).toBe(false);
      const response = await global.api.apiCall('GET', `${template.replace('{id}', id())}?trashed=${value}`);
      expect(response.status).toBe(422);
      expect(response.data.errors[0].field).toBe('trashed');
    });

    test('when generating station bulletin, then succeeds', async () => {
      // Uses station setup from beforeAll

      const response = await global.helpers.generateBulletin(stationId);

      expect(response.status).toBe(200);
    });

    test('when listing station bulletins, then returns data', async () => {
      // Uses station setup from beforeAll

      const response = await global.api.apiCall('GET', `/stations/${stationId}/bulletins`);

      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
    });

    test('when requesting the latest bulletin, then returns a single resource', async () => {
      const response = await global.api.apiCall('GET', `/stations/${stationId}/bulletins/latest`);
      expect(response.status).toBe(200);
      expect(response.data).not.toHaveProperty('data');
      expect(response.data).toHaveProperty('id');
    });

    test('when limiting the list to one, then keeps the list envelope', async () => {
      const response = await global.api.apiCall('GET', `/stations/${stationId}/bulletins?limit=1`);
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
      expect(response.data.data).toHaveLength(1);
    });

    test('when using the removed latest parameter, then returns 422 with migration guidance', async () => {
      const response = await global.api.apiCall('GET', `/stations/${stationId}/bulletins?latest=true`);
      expect(response.status).toBe(422);
      expect(response.data.detail).toContain('/stations/{id}/bulletins/latest');
    });
  });

  describe('Bulletin Error Cases', () => {
    test.each([
      ['when station non-existent, then returns 404', 'POST', '/stations/99999/bulletins', {}],
      ['when bulletin audio non-existent, then returns 404', 'GET', '/bulletins/99999/audio', undefined],
      ['when bulletin job non-existent, then returns 404', 'GET', '/bulletin-jobs/99999', undefined]
    ])('%s', async (_name, method, endpoint, body) => {
      const response = await global.api.apiCall(method, endpoint, body);
      expect(response.status).toBe(404);
    });
  });

  describe('Bulletin History', () => {
    test('when listing with sort, then ordered by date', async () => {
      const response = await global.api.apiCall('GET', '/bulletins?sort=-created_at');

      expect(response.status).toBe(200);
      const bulletins = response.data.data || [];
      if (bulletins.length > 1) {
        const first = new Date(bulletins[0].created_at);
        const second = new Date(bulletins[1].created_at);
        expect(first >= second).toBe(true);
      }
    });

    test('when filtering by date-time, then bounds and every spelling of an instant select the right rows', async () => {
      const station = await global.helpers.createStation(global.resources, 'BulletinRangeStation');
      expect(station).not.toBeNull();

      const stationId = sqlInteger(station.id, 'station ID');
      const suffix = `${Date.now()}_${process.pid}`;
      const rows = [
        {
          filename: `range_semantics_before_${suffix}.wav`,
          createdAt: '2024-01-09 12:00:00'
        },
        {
          filename: `range_semantics_inside_${suffix}.wav`,
          createdAt: '2024-01-15 12:00:00'
        },
        {
          filename: `range_semantics_after_${suffix}.wav`,
          createdAt: '2024-01-21 12:00:00'
        }
      ];
      const [, insideFilename, afterFilename] = rows.map(row => row.filename);
      const filenameList = rows.map(row => sqlString(row.filename)).join(', ');

      const lowerBound = '2024-01-10 00:00:00';
      const upperBound = '2024-01-20 23:59:59';

      const values = rows.map(row => (
        `(${stationId}, ${sqlString(row.filename)}, ${sqlString(row.filename)}, ${sqlString(row.createdAt)})`
      )).join(',');
      const list = async filters => {
        const response = await global.api.apiCall(
          'GET',
          `/bulletins?filter[station_id]=${stationId}&${filters}&sort=created_at&limit=10`
        );
        expect(response.status).toBe(200);
        return response.data.data || [];
      };

      try {
        mysql.execSQL(`INSERT INTO bulletins (station_id, filename, audio_file, created_at) VALUES ${values}`);

        // Track inserted IDs in ResourceManager as a safety net: if this test
        // aborts (timeout, signal) before the finally DELETE runs, global
        // teardown still removes these rows. The finally DELETE is the primary
        // cleanup path; tracking is defense-in-depth.
        const insertedIds = mysql.execSQL(
          `SELECT id FROM bulletins WHERE station_id = ${stationId} AND filename IN (${filenameList})`,
          { silent: true }
        ).trim().split('\n').map(value => Number(value.trim()));
        expect(insertedIds).toHaveLength(rows.length);
        insertedIds.forEach(id => {
          expect(Number.isSafeInteger(id)).toBe(true);
          global.resources.track('bulletins', id);
        });

        const inside = await list(`filter[created_at][gte]=${encodeURIComponent(lowerBound)}&filter[created_at][lte]=${encodeURIComponent(upperBound)}`);
        expect(inside.map(b => b.filename)).toEqual([insideFilename]);

        // The inside row's instant as the API reports it, spelled in UTC, with
        // zero and positive offsets, and as the server-local string it was
        // inserted as. The stack runs in a non-UTC zone, so a misread offset
        // misses the row.
        const utc = new Date(inside[0].created_at).toISOString().replace('.000Z', 'Z');
        const plusOne = new Date(Date.parse(utc) + 3600 * 1000).toISOString().replace('.000Z', '+01:00');
        for (const value of [utc, utc.replace('Z', '+00:00'), plusOne, rows[1].createdAt]) {
          expect((await list(`filter[created_at][eq]=${encodeURIComponent(value)}`)).map(b => b.filename)).toEqual([insideFilename]);
        }

        // A comma fraction must not be truncated to the whole second.
        expect((await list(`filter[created_at][gte]=${encodeURIComponent(`${rows[1].createdAt},5`)}`)).map(b => b.filename)).toEqual([afterFilename]);
      } finally {
        mysql.execSQL(`DELETE FROM bulletins WHERE station_id = ${stationId} AND filename IN (${filenameList})`);
      }
    });

    // The driver binds times in the server zone (Europe/Amsterdam here), so the
    // bindable year range 1 to 9999 is checked after conversion.
    test.each([
      ['0001-01-01T00:00:00+14:00'],
      ['9999-12-31T23:30:00Z']
    ])('when filter[created_at][gte]=%s leaves the bindable year range in server time, then returns 422', async value => {
      const response = await global.api.apiCall('GET', `/bulletins?filter[created_at][gte]=${encodeURIComponent(value)}`);
      expect(response.status).toBe(422);
      expect(response.data.errors[0].field).toBe('filter[created_at][gte]');
    });
  });
});
