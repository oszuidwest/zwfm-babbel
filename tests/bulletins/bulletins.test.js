const fs = require('fs');
const bulletinsSchema = require('../lib/schemas/bulletins.schema');
const { generateQueryTests } = require('../lib/generators');
const { createMySQLExecutor, sqlInteger, sqlString } = require('../lib/MySQLHelper');

describe('Bulletins', () => {
  const mysql = createMySQLExecutor();

  const setupQueryTestData = async () => {
    const { station } = await global.helpers.createBroadcastFixture(global.resources, {
      stationName: 'QueryBulletinStation',
      voiceName: 'QueryBulletinVoice',
      storyTitle: 'QueryBulletinStory',
      storyText: 'Query test story'
    });

    const response = await global.api.apiCall('POST', `/stations/${station.id}/bulletins`, {});
    return response.status === 200 && response.data.id ? [response.data.id] : [];
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
      // Arrange: Uses station setup from beforeAll

      // Act
      const response = await global.api.apiCall('POST', `/stations/${stationId}/bulletins`, {});

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('id');
      expect(response.data).toHaveProperty('audio_url');
      expect(response.data).toHaveProperty('duration_seconds');
      expect(response.data).toHaveProperty('story_count');
      expect(response.data).toHaveProperty('filename');
    });

    test('when generating with specific date, then succeeds', async () => {
      // Arrange
      const today = new Date().toISOString().split('T')[0];

      // Act
      const response = await global.api.apiCall('POST', `/stations/${stationId}/bulletins`, { date: today });

      // Assert
      expect(response.status).toBe(200);
    });

    test('when generating with missing body, then succeeds', async () => {
      // Act
      const response = await global.api.http({
        method: 'post',
        url: `${global.api.apiUrl}/stations/${stationId}/bulletins`,
        validateStatus: () => true
      });

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('id');
    });

    test('when generating with whitespace body, then succeeds', async () => {
      // Act
      const response = await global.api.http({
        method: 'post',
        url: `${global.api.apiUrl}/stations/${stationId}/bulletins`,
        data: ' \n\t ',
        headers: { 'Content-Type': 'application/json' },
        transformRequest: [data => data],
        validateStatus: () => true
      });

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('id');
    });

    test('when generating with malformed JSON body, then returns 422', async () => {
      // Act
      const response = await global.api.http({
        method: 'post',
        url: `${global.api.apiUrl}/stations/${stationId}/bulletins`,
        data: '{invalid json}',
        headers: { 'Content-Type': 'application/json' },
        transformRequest: [data => data],
        validateStatus: () => true
      });

      // Assert
      expect(response.status).toBe(422);
    });

    test('when generating with non-json content type and JSON body, then succeeds', async () => {
      // Act
      const response = await global.api.http({
        method: 'post',
        url: `${global.api.apiUrl}/stations/${stationId}/bulletins`,
        data: '{}',
        headers: { 'Content-Type': 'text/plain' },
        validateStatus: () => true
      });

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('id');
    });

    test('when generating with oversized body, then returns 413', async () => {
      // Act
      const response = await global.api.http({
        method: 'post',
        url: `${global.api.apiUrl}/stations/${stationId}/bulletins`,
        data: 'a'.repeat(1024 * 1024 + 1),
        headers: { 'Content-Type': 'application/json' },
        transformRequest: [data => data],
        validateStatus: () => true
      });

      // Assert
      expect(response.status).toBe(413);
    });

    test('when stories use different voices, then jingle context is stable across multiple bulletins', async () => {
      // Regression: jingle context (voice + mix point) must come from the
      // highest-priority story BEFORE the playback order is shuffled.
      // A single run has a 50% chance of passing by luck with 2 stories,
      // so we generate multiple bulletins and assert ALL are consistent.
      // With 5 runs the false-pass probability drops to ~3%.

      // Arrange: two voices with very different mix points
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
      await global.helpers.createStoryWithReadyAudio(global.resources, {
        title: `JingleCtxBreaking_${Date.now()}`,
        text: 'Breaking story for jingle context test',
        voice_id: highPriorityVoice.id,
        weekdays: 127,
        status: 'active',
        is_breaking: true
      }, [station.id]);

      await global.helpers.createStoryWithReadyAudio(global.resources, {
        title: `JingleCtxRegular_${Date.now()}`,
        text: 'Regular story for jingle context test',
        voice_id: lowPriorityVoice.id,
        weekdays: 127,
        status: 'active',
        is_breaking: false
      }, [station.id]);

      // Act: generate 5 bulletins - each shuffle is independent
      const runs = 5;
      const durations = [];
      for (let i = 0; i < runs; i++) {
        const response = await global.api.apiCall('POST', `/stations/${station.id}/bulletins`, {});
        expect(response.status).toBe(200);
        expect(response.data.story_count).toBe(2);
        durations.push(response.data.duration_seconds);
      }

      // Assert: every bulletin must use the 5.0s mix point from the breaking
      // story's voice. Each test story is ~3s audio, pause_seconds is 0,
      // so total ≈ 3 + 3 + 5.0 = 11.0s.
      // If the wrong mix point were used, total ≈ 3 + 3 + 0.5 = 6.5s.
      // Threshold of 9s can only be met with the 5.0s mix point.
      for (let i = 0; i < runs; i++) {
        expect(durations[i]).toBeGreaterThan(9);
      }

      // All durations should be identical (same mix point every time)
      const uniqueDurations = new Set(durations.map(d => d.toFixed(2)));
      expect(uniqueDurations.size).toBe(1);
    });

    test('when breaking stories exceed available slots, then bulletin includes only breaking stories', async () => {
      // Arrange
      const station = await global.helpers.createStation(global.resources, 'BreakingPriorityStation', 2);
      const voice = await global.helpers.createVoice(global.resources, 'BreakingPriorityVoice');

      expect(station).not.toBeNull();
      expect(voice).not.toBeNull();

      const stationVoice = await global.helpers.createStationVoiceWithJingle(global.resources, station.id, voice.id, 3.0);
      expect(stationVoice).not.toBeNull();

      const [breakingStoryA, breakingStoryB, regularStory] = await global.helpers.createStationStoriesWithReadyAudio(
        global.resources,
        station.id,
        voice.id,
        [
          { title: `BreakingPriorityA_${Date.now()}`, text: 'Breaking story A', is_breaking: true },
          { title: `BreakingPriorityB_${Date.now()}`, text: 'Breaking story B', is_breaking: true },
          { title: `BreakingPriorityRegular_${Date.now()}`, text: 'Regular story', is_breaking: false }
        ]
      );

      // Act
      const bulletinResponse = await global.api.apiCall('POST', `/stations/${station.id}/bulletins`, {});

      // Assert
      expect(bulletinResponse.status).toBe(200);

      const bulletinStoriesResponse = await global.api.apiCall('GET', `/bulletins/${bulletinResponse.data.id}/stories`);
      expect(bulletinStoriesResponse.status).toBe(200);
      expect(bulletinStoriesResponse.data.total).toBe(2);

      const includedStoryIds = bulletinStoriesResponse.data.data.map(story => story.story_id);
      expect(includedStoryIds).toHaveLength(2);
      expect(includedStoryIds).toEqual(expect.arrayContaining([breakingStoryA.id, breakingStoryB.id]));
      expect(includedStoryIds).not.toContain(regularStory.id);
    });

    test('when breaking and non-breaking stories compete for slots, then breaking always included', async () => {
      // Arrange: station with 3 slots, 1 breaking + 4 non-breaking stories
      const station = await global.helpers.createStation(global.resources, 'BreakingAlwaysStation', 3);
      const voice = await global.helpers.createVoice(global.resources, 'BreakingAlwaysVoice');

      expect(station).not.toBeNull();
      expect(voice).not.toBeNull();

      const stationVoice = await global.helpers.createStationVoiceWithJingle(global.resources, station.id, voice.id, 3.0);
      expect(stationVoice).not.toBeNull();

      const [breakingStory] = await global.helpers.createStationStoriesWithReadyAudio(
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
        const [story] = await global.helpers.createStationStoriesWithReadyAudio(global.resources, station.id, voice.id, [{
          title: `BreakingAlwaysRegular${i}_${Date.now()}`,
          text: `Regular story ${i}`,
          is_breaking: false
        }]);
        regularStoryIds.push(story.id);
      }

      // Act: generate 5 bulletins - fair rotation will vary the non-breaking stories
      const runs = 5;
      for (let i = 0; i < runs; i++) {
        const bulletinResponse = await global.api.apiCall('POST', `/stations/${station.id}/bulletins`, {});
        expect(bulletinResponse.status).toBe(200);
        expect(bulletinResponse.data.story_count).toBe(3);

        const storiesResponse = await global.api.apiCall('GET', `/bulletins/${bulletinResponse.data.id}/stories`);
        const includedStoryIds = storiesResponse.data.data.map(s => s.story_id);

        // Assert: breaking story is in every single bulletin
        expect(includedStoryIds).toContain(breakingStory.id);

        // Assert: remaining 2 slots are filled by non-breaking stories
        const nonBreakingIncluded = includedStoryIds.filter(id => id !== breakingStory.id);
        expect(nonBreakingIncluded).toHaveLength(2);
        nonBreakingIncluded.forEach(id => {
          expect(regularStoryIds).toContain(id);
        });
      }
    });

    test('when breaking story is ineligible, then excluded from bulletin despite flag', async () => {
      // Arrange: station with stories that are breaking but fail eligibility
      const station = await global.helpers.createStation(global.resources, 'BreakingEligStation', 3);
      const voice = await global.helpers.createVoice(global.resources, 'BreakingEligVoice');

      expect(station).not.toBeNull();
      expect(voice).not.toBeNull();

      const stationVoice = await global.helpers.createStationVoiceWithJingle(global.resources, station.id, voice.id, 3.0);
      expect(stationVoice).not.toBeNull();

      // Current weekday bitmask: Sunday=1, Monday=2, Tuesday=4, etc.
      // Use a bitmask that excludes today
      const todayBit = 1 << new Date().getDay();
      const wrongWeekdays = 127 ^ todayBit; // all days except today
      const [draftBreaking, expiredBreaking, wrongDayBreaking, eligibleStory] =
        await global.helpers.createStationStoriesWithReadyAudio(global.resources, station.id, voice.id, [
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

      // Act
      const bulletinResponse = await global.api.apiCall('POST', `/stations/${station.id}/bulletins`, {});

      // Assert
      expect(bulletinResponse.status).toBe(200);

      const storiesResponse = await global.api.apiCall('GET', `/bulletins/${bulletinResponse.data.id}/stories`);
      const includedStoryIds = storiesResponse.data.data.map(s => s.story_id);

      // None of the ineligible breaking stories should be included
      expect(includedStoryIds).not.toContain(draftBreaking.id);
      expect(includedStoryIds).not.toContain(expiredBreaking.id);
      expect(includedStoryIds).not.toContain(wrongDayBreaking.id);

      // The eligible regular story should be included
      expect(includedStoryIds).toContain(eligibleStory.id);
    });

    test('when multiple breaking stories compete for limited slots, then newest by start_date selected', async () => {
      // Arrange: station with 2 slots, 3 breaking stories with different start_dates
      const station = await global.helpers.createStation(global.resources, 'BreakingNewestStation', 2);
      const voice = await global.helpers.createVoice(global.resources, 'BreakingNewestVoice');

      expect(station).not.toBeNull();
      expect(voice).not.toBeNull();

      const stationVoice = await global.helpers.createStationVoiceWithJingle(global.resources, station.id, voice.id, 3.0);
      expect(stationVoice).not.toBeNull();

      const [oldBreaking, midBreaking, newBreaking] = await global.helpers.createStationStoriesWithReadyAudio(
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

      // Act
      const bulletinResponse = await global.api.apiCall('POST', `/stations/${station.id}/bulletins`, {});

      // Assert
      expect(bulletinResponse.status).toBe(200);
      expect(bulletinResponse.data.story_count).toBe(2);

      const storiesResponse = await global.api.apiCall('GET', `/bulletins/${bulletinResponse.data.id}/stories`);
      const includedStoryIds = storiesResponse.data.data.map(s => s.story_id);

      // Newest two breaking stories should be selected
      expect(includedStoryIds).toContain(newBreaking.id);
      expect(includedStoryIds).toContain(midBreaking.id);
      expect(includedStoryIds).not.toContain(oldBreaking.id);
    });
  });

  describe('Bulletin Retrieval', () => {
    test('when fetching single bulletin, then returns data', async () => {
      // Arrange
      const listResponse = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (listResponse.data.data.length > 0) {
        const bulletinId = listResponse.data.data[0].id;

        // Act
        const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}`);

        // Assert
        expect(response.status).toBe(200);
        expect(response.data.id).toBe(bulletinId);
      }
    });

    test('when fetching non-existent bulletin, then returns 404', async () => {
      // Act
      const response = await global.api.apiCall('GET', '/bulletins/999999999');

      // Assert
      expect(response.status).toBe(404);
    });

    test('when fetching bulletin, then has correct field types', async () => {
      // Arrange
      const listResponse = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (listResponse.data.data.length > 0) {
        const bulletinId = listResponse.data.data[0].id;

        // Act
        const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}`);
        const bulletin = response.data;

        // Assert
        expect(typeof bulletin.id).toBe('number');
        expect(typeof bulletin.station_id).toBe('number');
        expect(typeof bulletin.station_name).toBe('string');
        expect(typeof bulletin.audio_url).toBe('string');
        expect(typeof bulletin.filename).toBe('string');
        expect(typeof bulletin.duration_seconds).toBe('number');
      }
    });
  });

  describe('Bulletin Cache-Control', () => {
    let stationId;

    beforeAll(async () => {
      const { station } = await global.helpers.createBroadcastFixture(global.resources, {
        stationName: 'CacheCtrlStation',
        voiceName: 'CacheCtrlVoice',
        storyTitle: 'CacheCtrlStory',
        storyText: 'Cache control test story'
      });
      stationId = station.id;

      // Warm the cache once so the HIT scenarios have something to serve.
      const warmup = await global.api.apiCall('POST', `/stations/${stationId}/bulletins`, {});
      expect(warmup.status).toBe(200);
    });

    test('when generating without cache header, then returns MISS', async () => {
      // Act
      const response = await global.api.apiCall('POST', `/stations/${stationId}/bulletins`, {});

      // Assert
      expect(response.status).toBe(200);
      expect(response.headers['x-cache']).toBe('MISS');
    });

    test('when Cache-Control max-age allows reuse, then returns HIT', async () => {
      // Act
      const response = await global.api.http({
        method: 'post',
        url: `${global.api.apiUrl}/stations/${stationId}/bulletins`,
        data: '{}',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'max-age=3600'
        },
        validateStatus: () => true
      });

      // Assert
      expect(response.status).toBe(200);
      expect(response.headers['x-cache']).toBe('HIT');
      expect(response.headers['age']).toBeDefined();
    });

    test('when Cache-Control no-cache, then forces regeneration and returns MISS', async () => {
      // Act
      const response = await global.api.http({
        method: 'post',
        url: `${global.api.apiUrl}/stations/${stationId}/bulletins`,
        data: '{}',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache'
        },
        validateStatus: () => true
      });

      // Assert
      expect(response.status).toBe(200);
      expect(response.headers['x-cache']).toBe('MISS');
    });

    test('when Accept audio/wav with warm cache, then serves cached binary', async () => {
      // Act
      const response = await global.api.http({
        method: 'post',
        url: `${global.api.apiUrl}/stations/${stationId}/bulletins`,
        data: '{}',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'audio/wav',
          'Cache-Control': 'max-age=3600'
        },
        responseType: 'arraybuffer',
        validateStatus: () => true
      });

      // Assert
      expect(response.status).toBe(200);
      expect(response.headers['content-type']).toMatch(/audio\/wav/);
      expect(response.headers['x-bulletin-cached']).toBe('true');
      expect(response.headers['x-cache']).toBe('HIT');
    });

    test('when Cache-Control max-age is invalid, then falls back to fresh generation', async () => {
      // Act
      const response = await global.api.http({
        method: 'post',
        url: `${global.api.apiUrl}/stations/${stationId}/bulletins`,
        data: '{}',
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'max-age=garbage'
        },
        validateStatus: () => true
      });

      // Assert
      expect(response.status).toBe(200);
      expect(response.headers['x-cache']).toBe('MISS');
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

      const response = await global.api.apiCall('POST', `/stations/${station.id}/bulletins`, {});
      expect(response.status).toBe(200);
      bulletinId = response.data.id;
    });

    test('when called with only pagination, then returns 200', async () => {
      // Act
      const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}/stories?limit=10&offset=0`);

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
    });

    test.each([
      ['when called with filter, then returns 422', 'filter[story_id]=1'],
      ['when called with sort, then returns 422', 'sort=story_order'],
      ['when called with fields, then returns 422', 'fields=id,story_id'],
      ['when called with search, then returns 422', 'search=anything']
    ])('%s', async (_name, query) => {
      const response = await global.api.apiCall('GET', `/bulletins/${bulletinId}/stories?${query}`);
      expect(response.status).toBe(422);
    });
  });

  describe('Bulletin Audio Download', () => {
    test('when downloading audio, then file is valid', async () => {
      // Arrange
      const response = await global.api.apiCall('GET', '/bulletins?limit=1');

      if (response.data.data.length > 0) {
        const bulletinId = response.data.data[0].id;
        const downloadPath = '/tmp/test_bulletin_download.wav';

        // Act
        const downloadResponse = await global.api.downloadFile(`/bulletins/${bulletinId}/audio`, downloadPath);

        // Assert
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

    beforeAll(async () => {
      const { station } = await global.helpers.createBroadcastFixture(global.resources, {
        stationName: 'StationBulletinEndpoint',
        voiceName: 'StationBulletinVoice',
        storyTitle: 'StationBulletinStory',
        storyText: 'Station endpoint test story'
      });
      stationId = station.id;
    });

    test('when generating station bulletin, then succeeds', async () => {
      // Arrange: Uses station setup from beforeAll

      // Act
      const response = await global.api.apiCall('POST', `/stations/${stationId}/bulletins`, {});

      // Assert
      expect(response.status).toBe(200);
    });

    test('when listing station bulletins, then returns data', async () => {
      // Arrange: Uses station setup from beforeAll

      // Act
      const response = await global.api.apiCall('GET', `/stations/${stationId}/bulletins`);

      // Assert
      expect(response.status).toBe(200);
      expect(response.data).toHaveProperty('data');
    });

    test.each([
      ['when latest=true combined with unknown filter, then returns 422', 'latest=true&filter[__bogus__]=1', 422],
      ['when latest=true combined with unknown sort, then returns 422', 'latest=true&sort=__bogus__', 422],
      ['when latest=true combined with unknown fields, then returns 422', 'latest=true&fields=id,__bogus__', 422],
      ['when latest=true combined with extra known query params, then returns 422', 'latest=true&sort=-created_at', 422],
      ['when latest=true combined with limit other than 1, then returns 422', 'latest=true&limit=2', 422],
      ['when latest=true combined with limit=1, then returns 200', 'latest=true&limit=1', 200],
      ['when limit appears twice, then returns 422 regardless of which wins', 'latest=true&limit=1&limit=2', 422]
    ])('%s', async (_name, query, status) => {
      const response = await global.api.apiCall('GET', `/stations/${stationId}/bulletins?${query}`);
      expect(response.status).toBe(status);
    });
  });

  describe('Bulletin Error Cases', () => {
    test.each([
      ['when station non-existent, then returns 404', 'POST', '/stations/99999/bulletins', {}],
      ['when bulletin audio non-existent, then returns 404', 'GET', '/bulletins/99999/audio', undefined]
    ])('%s', async (_name, method, endpoint, body) => {
      const response = await global.api.apiCall(method, endpoint, body);
      expect(response.status).toBe(404);
    });
  });

  describe('Bulletin History', () => {
    test('when listing with sort, then ordered by date', async () => {
      // Act
      const response = await global.api.apiCall('GET', '/bulletins?sort=-created_at');

      // Assert
      expect(response.status).toBe(200);
      const bulletins = response.data.data || [];
      if (bulletins.length > 1) {
        const first = new Date(bulletins[0].created_at);
        const second = new Date(bulletins[1].created_at);
        expect(first >= second).toBe(true);
      }
    });

    test('when filtering by date range, then applies both bounds', async () => {
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
      const [beforeFilename, insideFilename, afterFilename] = rows.map(row => row.filename);
      const filenameList = rows.map(row => sqlString(row.filename)).join(', ');

      const lowerBound = '2024-01-10 00:00:00';
      const upperBound = '2024-01-20 23:59:59';

      const values = rows.map(row => (
        `(${stationId}, ${sqlString(row.filename)}, ${sqlString(row.filename)}, ${sqlString(row.createdAt)})`
      )).join(',');

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

        const response = await global.api.apiCall(
          'GET',
          `/bulletins?filter[station_id]=${stationId}&filter[created_at][gte]=${encodeURIComponent(lowerBound)}&filter[created_at][lte]=${encodeURIComponent(upperBound)}&sort=created_at&limit=10`
        );

        expect(response.status).toBe(200);
        const filenames = new Set((response.data.data || []).map(b => b.filename));

        expect(filenames).toContain(insideFilename);
        expect(filenames).not.toContain(beforeFilename);
        expect(filenames).not.toContain(afterFilename);
      } finally {
        mysql.execSQL(`DELETE FROM bulletins WHERE station_id = ${stationId} AND filename IN (${filenameList})`);
      }
    });
  });
});
