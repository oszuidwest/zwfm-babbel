/**
 * Babbel bulletin cleanup tests.
 * Tests that purged bulletins behave correctly: no audio_url, metadata preserved,
 * latest endpoint skips purged, automation regenerates after purge.
 *
 * Follows Jest best practices:
 * - AAA pattern (Arrange, Act, Assert)
 * - "when...then" naming convention
 */

const { execSync } = require('child_process');
const fsSync = require('fs');
const path = require('path');

describe('Bulletin Cleanup', () => {
  const automationKey = 'test-automation-key-for-integration-tests';

  // MySQL connection defaults (matching docker-compose)
  const mysqlUser = process.env.MYSQL_USER || 'babbel';
  const mysqlPassword = process.env.MYSQL_PASSWORD || 'babbel';
  const mysqlDatabase = process.env.MYSQL_DATABASE || 'babbel';
  const audioDir = path.join(__dirname, '../../audio');

  // Test state set during beforeAll
  let testStationId = null;
  let purgedBulletinId = null;
  let unpurgedBulletinId = null;

  // Execute SQL against the Docker MySQL container
  const execSQL = (sql) => {
    const cmd = `docker exec -i babbel-mysql mysql -u ${mysqlUser} -p${mysqlPassword} ${mysqlDatabase} -e "${sql}"`;
    return execSync(cmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
  };

  // Mark a bulletin as purged via direct SQL and remove its audio file
  const markBulletinPurged = (bulletinId) => {
    const id = parseInt(bulletinId, 10);

    // Set file_purged_at in database
    execSQL(`UPDATE bulletins SET file_purged_at = NOW() WHERE id = ${id}`);

    // Get filename from database to delete the actual file
    const result = execSQL(`SELECT audio_file FROM bulletins WHERE id = ${id}`);
    const lines = result.trim().split('\n');
    if (lines.length >= 2) {
      const filename = lines[1].trim();
      if (filename) {
        const filePath = path.join(audioDir, 'output', filename);
        try {
          fsSync.unlinkSync(filePath);
        } catch {
          // File may not exist
        }
      }
    }
  };

  beforeAll(async () => {
    // Create test resources: station -> voice -> station-voice with jingle -> story with audio
    const station = await global.helpers.createStation(global.resources, 'Cleanup Test Station', 3, 2.0);
    expect(station).not.toBeNull();
    testStationId = station.id;

    const voice = await global.helpers.createVoice(global.resources, 'Cleanup Test Voice');
    expect(voice).not.toBeNull();

    const sv = await global.helpers.createStationVoiceWithJingle(global.resources, testStationId, voice.id);
    expect(sv).not.toBeNull();

    const story = await global.helpers.createStoryWithAudio(global.resources, {
      title: `CleanupTestStory_${Date.now()}`,
      text: 'Story for testing bulletin cleanup behavior.',
      voice_id: voice.id,
      weekdays: 127,
      status: 'active'
    }, [parseInt(testStationId, 10)]);
    expect(story).not.toBeNull();

    // Wait for audio processing
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Generate first bulletin
    const bulletin1 = await global.api.apiCall('POST', `/stations/${testStationId}/bulletins`, {});
    expect(bulletin1.status).toBe(200);
    purgedBulletinId = global.api.parseJsonField(bulletin1.data, 'id');
    global.resources.track('bulletins', purgedBulletinId);

    // Small delay for different timestamps
    await new Promise(resolve => setTimeout(resolve, 1000));

    // Generate second bulletin
    const bulletin2 = await global.api.apiCall('POST', `/stations/${testStationId}/bulletins`, {});
    expect(bulletin2.status).toBe(200);
    unpurgedBulletinId = global.api.parseJsonField(bulletin2.data, 'id');
    global.resources.track('bulletins', unpurgedBulletinId);

    // Mark the first (older) bulletin as purged
    markBulletinPurged(purgedBulletinId);
  });

  describe('Purged Bulletin Properties', () => {
    test('when bulletin is purged, then has no audio_url but has file_purged_at', async () => {
      // Act
      const purgedResponse = await global.api.apiCall('GET', `/bulletins/${purgedBulletinId}`);
      const unpurgedResponse = await global.api.apiCall('GET', `/bulletins/${unpurgedBulletinId}`);

      // Assert: purged bulletin
      expect(purgedResponse.status).toBe(200);
      expect(purgedResponse.data.audio_url).toBeFalsy();
      expect(purgedResponse.data.file_purged_at).toBeTruthy();

      // Assert: unpurged bulletin still has audio_url
      expect(unpurgedResponse.status).toBe(200);
      expect(unpurgedResponse.data.audio_url).toBeTruthy();
      expect(unpurgedResponse.data.file_purged_at).toBeFalsy();
    });

    test('when requesting purged bulletin audio, then returns 404', async () => {
      // Act
      const response = await global.api.apiCall('GET', `/bulletins/${purgedBulletinId}/audio`);

      // Assert
      expect(response.status).toBe(404);
    });

    test('when bulletin is purged, then metadata is preserved', async () => {
      // Act
      const response = await global.api.apiCall('GET', `/bulletins/${purgedBulletinId}`);

      // Assert
      expect(response.status).toBe(200);
      const bulletin = response.data;
      expect(bulletin.id).toBe(parseInt(purgedBulletinId, 10));
      expect(bulletin.station_id).toBeDefined();
      expect(bulletin.filename).toBeTruthy();
      expect(bulletin.duration_seconds).toBeDefined();
      expect(bulletin.story_count).toBeDefined();
      expect(bulletin.created_at).toBeTruthy();
    });
  });

  describe('Purged Bulletin Listing', () => {
    test('when listing bulletins, then includes both purged and unpurged', async () => {
      // Act
      const response = await global.api.apiCall('GET', `/stations/${testStationId}/bulletins`);

      // Assert
      expect(response.status).toBe(200);
      const bulletins = response.data.data || [];
      expect(bulletins.length).toBeGreaterThanOrEqual(2);

      const purged = bulletins.find(b => String(b.id) === String(purgedBulletinId));
      const unpurged = bulletins.find(b => String(b.id) === String(unpurgedBulletinId));

      expect(purged).toBeDefined();
      expect(purged.audio_url).toBeFalsy();
      expect(purged.file_purged_at).toBeTruthy();

      expect(unpurged).toBeDefined();
      expect(unpurged.audio_url).toBeTruthy();
      expect(unpurged.file_purged_at).toBeFalsy();
    });

    test('when requesting latest bulletin, then skips purged', async () => {
      // Arrange: generate a third bulletin and purge it (making it the newest)
      const thirdResponse = await global.api.apiCall('POST', `/stations/${testStationId}/bulletins`, {});
      expect(thirdResponse.status).toBe(200);
      const thirdBulletinId = global.api.parseJsonField(thirdResponse.data, 'id');
      global.resources.track('bulletins', thirdBulletinId);

      markBulletinPurged(thirdBulletinId);

      // Act
      const latestResponse = await global.api.apiCall('GET', `/stations/${testStationId}/bulletins?latest=true`);

      // Assert
      expect(latestResponse.status).toBe(200);
      const latestId = String(latestResponse.data.id);

      // Should not return either purged bulletin
      expect(latestId).not.toBe(String(thirdBulletinId));
      expect(latestId).not.toBe(String(purgedBulletinId));
      expect(latestResponse.data.audio_url).toBeTruthy();
    });
  });

  describe('Automation After Purge', () => {
    test('when all bulletins purged, then automation regenerates', async () => {
      // Arrange: create a separate station to avoid interference
      const station = await global.helpers.createStation(global.resources, 'Automation Purge Test', 3, 2.0);
      expect(station).not.toBeNull();

      const voice = await global.helpers.createVoice(global.resources, 'Automation Purge Voice');
      expect(voice).not.toBeNull();

      const sv = await global.helpers.createStationVoiceWithJingle(global.resources, station.id, voice.id);
      expect(sv).not.toBeNull();

      const story = await global.helpers.createStoryWithAudio(global.resources, {
        title: `AutomationPurgeStory_${Date.now()}`,
        text: 'Story for testing automation after purge.',
        voice_id: voice.id,
        weekdays: 127,
        status: 'active'
      }, [parseInt(station.id, 10)]);
      expect(story).not.toBeNull();

      await new Promise(resolve => setTimeout(resolve, 2000));

      // Generate initial bulletin via automation
      const initialResponse = await global.helpers.publicBulletinRequest(station.id, {
        key: automationKey,
        max_age: '0'
      });
      expect(initialResponse.status).toBe(200);
      const initialBulletinId = initialResponse.headers['x-bulletin-id'];

      // Purge it
      markBulletinPurged(initialBulletinId);

      // Act: request again - should generate fresh since no unpurged bulletins exist
      const afterPurgeResponse = await global.helpers.publicBulletinRequest(station.id, {
        key: automationKey,
        max_age: '3600'
      });

      // Assert
      expect(afterPurgeResponse.status).toBe(200);
      expect(afterPurgeResponse.headers['x-bulletin-cached']).toBe('false');
      expect(afterPurgeResponse.headers['x-bulletin-id']).not.toBe(initialBulletinId);
      expect(afterPurgeResponse.contentType).toContain('audio/wav');
    });
  });

  describe('Purge Filtering', () => {
    test('when filtering by purged status, then returns correct results', async () => {
      // Act
      const response = await global.api.apiCall('GET',
        `/stations/${testStationId}/bulletins?filter[file_purged_at][ne]=null`
      );

      // Assert
      expect(response.status).toBe(200);
      const purgedBulletins = response.data.data || [];

      // All returned bulletins should have file_purged_at set
      for (const b of purgedBulletins) {
        expect(b.file_purged_at).toBeTruthy();
      }
    });
  });
});
